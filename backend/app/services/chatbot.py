# =============================================================
#  backend/app/services/chatbot.py
#  Security awareness chatbot — keyword matching engine
#
#  CONCEPT: Rule-based vs AI chatbots
#  There are two main approaches to chatbots:
#
#  1. Rule-based (this file): You define keywords → responses.
#     Pros:  Fast, predictable, no API costs, works offline.
#     Cons:  Can't handle phrasing it hasn't seen before.
#
#  2. LLM-powered (e.g. OpenAI API): The model generates
#     responses freely from any question.
#     Pros:  Flexible, handles anything.
#     Cons:  Costs money per request, can hallucinate.
#
#  For a security tool, rule-based is actually BETTER — we
#  control exactly what security advice gets given.
#
#  HOW IT WORKS:
#  Each "topic" has a list of trigger keywords and a response.
#  When a message arrives:
#    1. Lowercase the message
#    2. Check each topic's keywords against the message
#    3. Return the response for the first match
#    4. If nothing matches, return a helpful fallback
# =============================================================

import logging
import re

logger = logging.getLogger(__name__)

# =============================================================
#  KNOWLEDGE BASE
#  Each entry is a dict:
#    keywords  : list of strings — any triggers a match
#    response  : the text to return
#    priority  : higher = checked first (default 0)
# =============================================================
TOPICS = [
    {
        "priority": 10,
        "keywords": ["what is phishing", "define phishing", "explain phishing", "phishing mean"],
        "response": (
            "🎣 Phishing is a cyberattack where criminals impersonate trusted organisations "
            "(banks, PayPal, your employer) via email, SMS, or fake websites to steal your "
            "login credentials, credit card details, or personal information.\n\n"
            "The name comes from 'fishing' — criminals cast a wide net hoping someone takes the bait.\n\n"
            "📊 By the numbers:\n"
            "• 91% of cyberattacks start with a phishing email\n"
            "• $4.91 million — average cost of a phishing breach\n"
            "• 3.4 billion phishing emails are sent every day\n\n"
            "The best defence is learning to recognise them before clicking."
        ),
    },
    {
        "priority": 9,
        "keywords": ["spot", "identify", "recognise", "recognize", "detect", "tell if", "how to know", "red flag", "sign"],
        "response": (
            "🔍 Key red flags that an email is phishing:\n\n"
            "🚨 HIGH RISK:\n"
            "• Sender domain doesn't match the company (paypa1.com instead of paypal.com)\n"
            "• URL contains an IP address (http://192.168.1.1/login)\n"
            "• Attachment you weren't expecting (.exe, .zip, .docm files)\n"
            "• Asks for your password, PIN, or full credit card number\n\n"
            "⚠️  MEDIUM RISK:\n"
            "• Urgency words: 'URGENT', 'Act now', 'Account suspended'\n"
            "• Generic greeting: 'Dear Customer' (your bank knows your name)\n"
            "• Slightly off grammar or spelling\n"
            "• Threats: 'Your account will be closed in 24 hours'\n\n"
            "🔵 LOWER RISK (but still suspicious if combined with above):\n"
            "• Unexpected prizes or rewards\n"
            "• Requests to 'verify' or 'confirm' your details\n\n"
            "Rule of thumb: if it creates urgency or asks for credentials — stop and verify independently."
        ),
    },
    {
        "priority": 9,
        "keywords": ["check link", "check url", "safe link", "hover", "suspicious link", "click link", "url safe"],
        "response": (
            "🔗 How to check a link before clicking:\n\n"
            "1. HOVER first — on desktop, hover your mouse over the link.\n"
            "   The real URL appears in the bottom-left of your browser.\n"
            "   Does it match what the email claims?\n\n"
            "2. CHECK THE DOMAIN carefully:\n"
            "   ✅ paypal.com/login   ← real PayPal\n"
            "   ❌ paypa1.com/login   ← fake (1 instead of l)\n"
            "   ❌ paypal.com.login-secure.ru   ← fake (.com is not the end)\n"
            "   ❌ http://185.234.12.1/paypal   ← IP address, never legitimate\n\n"
            "3. USE A LINK SCANNER:\n"
            "   • https://www.virustotal.com  — paste the URL, checks 70+ engines\n"
            "   • https://urlvoid.com         — reputation database\n\n"
            "4. WHEN IN DOUBT — go directly to the website by typing it yourself.\n"
            "   Never click a link in an email to 'verify your account'."
        ),
    },
    {
        "priority": 8,
        "keywords": ["report", "reporting", "what to do", "received phishing", "got phishing", "forward", "suspicious email"],
        "response": (
            "📢 What to do if you receive a phishing email:\n\n"
            "✅ DO:\n"
            "1. Report it to your IT/security team immediately\n"
            "2. Use PhishGuard's Detect Email page to analyse it\n"
            "3. Report to your email provider:\n"
            "   • Gmail: three dots menu → 'Report phishing'\n"
            "   • Outlook: right-click → 'Report' → 'Report phishing'\n"
            "4. Report to national agencies:\n"
            "   • UK: report@phishing.gov.uk\n"
            "   • US: reportphishing@apwg.org\n"
            "   • Also: forward to the impersonated company (abuse@paypal.com)\n\n"
            "❌ DON'T:\n"
            "• Don't click any links or open attachments\n"
            "• Don't reply to the email (confirms your address is active)\n"
            "• Don't call phone numbers listed in the email\n"
            "• Don't 'unsubscribe' — that also confirms your address\n\n"
            "⚠️  If you already clicked: change passwords immediately and notify IT."
        ),
    },
    {
        "priority": 8,
        "keywords": ["password", "strong password", "password manager", "passphrase"],
        "response": (
            "🔑 Password best practices:\n\n"
            "WHAT MAKES A STRONG PASSWORD:\n"
            "• Length beats complexity — 'correct-horse-battery-staple' is stronger than 'P@ssw0rd'\n"
            "• Aim for 16+ characters\n"
            "• Unique per site — never reuse passwords\n"
            "• Never include: your name, birthday, pet name, or common words\n\n"
            "USE A PASSWORD MANAGER:\n"
            "They generate and store unique random passwords for every site.\n"
            "Good options: Bitwarden (free, open source), 1Password, Dashlane\n\n"
            "YOU ONLY NEED TO REMEMBER:\n"
            "• Your master password (make it a long passphrase)\n"
            "• Your device password\n"
            "• Your email password (recovery fallback)\n\n"
            "COMMON MISTAKE: Using the same password everywhere.\n"
            "If one site gets breached, attackers try your credentials on every other site.\n"
            "This is called 'credential stuffing'."
        ),
    },
    {
        "priority": 8,
        "keywords": ["2fa", "two factor", "two-factor", "mfa", "authenticator", "otp", "one time"],
        "response": (
            "🔐 Two-Factor Authentication (2FA / MFA):\n\n"
            "WHAT IS IT?\n"
            "A second proof of identity beyond your password.\n"
            "Even if attackers steal your password, they can't log in without this second factor.\n\n"
            "TYPES (best to worst):\n"
            "1. 🏆 Hardware key (YubiKey) — physically plug in\n"
            "2. ✅ Authenticator app (Google Authenticator, Authy) — 6-digit rotating code\n"
            "3. ⚠️  SMS text code — convenient but can be SIM-swapped\n"
            "4. ❌ Email code — only as secure as your email account\n\n"
            "ENABLE IT ON:\n"
            "• Your email account (most important)\n"
            "• Banking and finance apps\n"
            "• Work systems and VPN\n"
            "• Social media accounts\n\n"
            "If a phishing site captures your password, 2FA still protects you\n"
            "(unless the attacker also does real-time session hijacking — rare)."
        ),
    },
    {
        "priority": 7,
        "keywords": ["spear phishing", "spear", "targeted", "whaling", "ceo fraud"],
        "response": (
            "🎯 Spear Phishing — targeted attacks:\n\n"
            "Regular phishing = mass emails sent to millions hoping someone clicks.\n\n"
            "Spear phishing = a carefully crafted email targeting ONE specific person,\n"
            "using personal details gathered from LinkedIn, social media, or data breaches.\n\n"
            "EXAMPLE:\n"
            "'Hi Sarah, it's Mike from accounts. I saw your LinkedIn post about the Q3 project.\n"
            "Can you urgently process this invoice? [malicious attachment]'\n\n"
            "WHALING = spear phishing targeting executives (CEOs, CFOs)\n"
            "CEO FRAUD = impersonating a CEO to trick finance staff into wire transfers\n\n"
            "DEFENCE:\n"
            "• Any urgent financial request via email → verify by phone (use a known number, not one in the email)\n"
            "• Limit what you share publicly on LinkedIn/social media\n"
            "• Your company should have a policy: no wire transfers from email-only approval"
        ),
    },
    {
        "priority": 7,
        "keywords": ["attachment", "download", "file", "pdf", "word doc", "excel", "zip", "macro"],
        "response": (
            "📎 Dangerous email attachments:\n\n"
            "HIGH RISK file types:\n"
            "• .exe .msi .bat .cmd — programs that run immediately\n"
            "• .docm .xlsm .pptm   — Office files with macros (mini-programs)\n"
            "• .zip .rar .7z       — compressed archives hiding malware\n"
            "• .iso .img           — disk images (bypass some email filters)\n\n"
            "SAFER (but not risk-free):\n"
            "• .pdf  — can still contain malicious JavaScript\n"
            "• .docx .xlsx — safer without macros, but not zero-risk\n\n"
            "RULES:\n"
            "1. Never open an attachment you weren't specifically expecting\n"
            "2. Never enable macros if Word/Excel warns you\n"
            "3. When in doubt — upload to virustotal.com before opening\n"
            "4. Better still — open in Google Drive (sandboxed, macros disabled)"
        ),
    },
    {
        "priority": 5,
        "keywords": ["vishing", "smishing", "voice", "phone call", "text message", "sms"],
        "response": (
            "📞 Beyond email — other phishing channels:\n\n"
            "VISHING (Voice phishing):\n"
            "Fake phone calls pretending to be banks, HMRC/IRS, or tech support.\n"
            "Tell-tale signs: unsolicited call, asks for card details or remote access.\n"
            "Rule: hang up, call back on the official number from their website.\n\n"
            "SMISHING (SMS phishing):\n"
            "Fake texts about parcels, bank alerts, or prize winnings.\n"
            "Contains a link to a fake website. Treat all unexpected SMS links with suspicion.\n\n"
            "QUISHING (QR code phishing):\n"
            "Fake QR codes in emails or printed posters that redirect to phishing sites.\n"
            "QR codes bypass URL inspection — check the URL before logging in.\n\n"
            "PRINCIPLE: Any channel can be used for phishing.\n"
            "Verify requests independently through official channels, not ones given to you."
        ),
    },
    {
        "priority": 3,
        "keywords": ["hello", "hi", "hey", "help", "start", "what can you do"],
        "response": (
            "👋 Hello! I'm PhishGuard's security awareness assistant.\n\n"
            "I can help you with:\n"
            "• What phishing is and how it works\n"
            "• How to spot a phishing email\n"
            "• How to safely check suspicious links\n"
            "• What to do if you receive a phishing email\n"
            "• Password best practices\n"
            "• Two-factor authentication (2FA)\n"
            "• Spear phishing and targeted attacks\n"
            "• Dangerous email attachments\n"
            "• SMS and voice phishing\n\n"
            "Try asking: 'How do I spot a phishing email?'"
        ),
    },
]

# Sort by priority descending once at startup
TOPICS.sort(key=lambda t: t.get("priority", 0), reverse=True)

FALLBACK = (
    "🤔 I'm not sure about that specific question. "
    "I can help with topics like:\n"
    "• Spotting phishing emails\n"
    "• Checking suspicious links\n"
    "• Reporting phishing\n"
    "• Password security\n"
    "• Two-factor authentication\n\n"
    "Try asking one of those!"
)


def get_response(message: str) -> str:
    """
    Returns a security awareness response for the given message.

    ALGORITHM:
    1. Lowercase the message for case-insensitive matching
    2. Loop through topics (highest priority first)
    3. If ANY keyword from a topic appears in the message → return that response
    4. If nothing matches → return FALLBACK

    Args:
        message: Raw text from the user

    Returns:
        Response string to display in the chat
    """
    if not message or not message.strip():
        return FALLBACK

    msg_lower = message.lower().strip()
    logger.debug("Chatbot received: %s", msg_lower[:80])

    for topic in TOPICS:
        for keyword in topic["keywords"]:
            # re.search finds the keyword anywhere in the message
            # re.escape makes special characters (like ?) safe
            if re.search(re.escape(keyword), msg_lower):
                logger.debug("Matched keyword '%s'", keyword)
                return topic["response"]

    logger.debug("No keyword match — returning fallback")
    return FALLBACK