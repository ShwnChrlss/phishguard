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
#  2. LLM-powered (e.g. Claude/OpenAI API): The model generates
#     responses freely from any question.
#     Pros:  Flexible, handles anything.
#     Cons:  Costs money per request, can hallucinate.
#
#  For a security tool, rule-based is actually BETTER for core
#  advice — we control exactly what security guidance is given.
#
#  HOW MATCHING WORKS (3 layers):
#  Layer 1 — EXACT keyword match (re.search)
#             Fastest. Checks if any keyword phrase appears
#             verbatim in the message.
#
#  Layer 2 — TOKEN match (fuzzy)
#             Splits both message and keywords into individual
#             words. Checks if enough words overlap.
#             Handles: "phishing email what is it" → matches
#             "what is phishing" even with word order changed.
#
#  Layer 3 — SMART FALLBACK
#             Instead of "I don't know", scores every topic
#             by how many words it shares with the message,
#             then suggests the closest matching topics.
#             Users always get a useful response.
#
#  CONCEPT: Why sorting by priority matters
#  Topics with higher priority are checked first. This means
#  a specific topic ("what is phishing") beats a general one
#  ("spot", which would also match "spot phishing").
# =============================================================

import logging
import re

logger = logging.getLogger(__name__)

# =============================================================
#  KNOWLEDGE BASE
#  Each entry is a dict:
#    keywords  : list of strings — any ONE triggers a match
#    tags      : short topic labels used in smart fallback
#    response  : the text to return
#    priority  : higher = checked first (default 0)
# =============================================================
TOPICS = [

    # GREETINGS
    {
        "priority": 10,
        "tags": ["greeting", "help"],
        "keywords": [
            "hello", "hi there", "hey", "good morning", "good afternoon",
            "help", "what can you do", "what do you know", "start",
            "what can i ask", "topics", "menu",
        ],
        "response": (
            "👋 Hello! I'm PhishGuard's security awareness assistant.\n\n"
            "I can help you with:\n\n"
            "🎣 PHISHING BASICS\n"
            "  • What phishing is and how it works\n"
            "  • How to spot a phishing email\n"
            "  • Spear phishing and targeted attacks\n\n"
            "🔗 LINKS & ATTACHMENTS\n"
            "  • How to check if a link is safe\n"
            "  • Which file attachments are dangerous\n\n"
            "🚨 INCIDENTS\n"
            "  • What to do if you clicked a phishing link\n"
            "  • How to report phishing emails\n\n"
            "🔒 STAYING SECURE\n"
            "  • Password best practices\n"
            "  • Two-factor authentication (2FA)\n"
            "  • SMS, voice, and QR code scams\n"
            "  • Social engineering tactics\n"
            "  • Data breaches — what to do\n\n"
            "Just type your question naturally — I'll do my best to help!"
        ),
    },

    # WHAT IS PHISHING
    {
        "priority": 9,
        "tags": ["phishing", "basics"],
        "keywords": [
            "what is phishing", "define phishing", "explain phishing",
            "phishing mean", "what does phishing mean", "phishing definition",
            "tell me about phishing", "phishing attack", "how does phishing work",
        ],
        "response": (
            "🎣 Phishing is a cyberattack where criminals impersonate trusted "
            "organisations — banks, PayPal, your employer — via email, SMS, or "
            "fake websites to steal your login credentials, credit card details, "
            "or personal information.\n\n"
            "The name comes from 'fishing' — criminals cast a wide net hoping "
            "someone takes the bait.\n\n"
            "📊 By the numbers:\n"
            "• 91% of cyberattacks begin with a phishing email\n"
            "• $4.91 million — average cost of a phishing breach\n"
            "• 3.4 billion phishing emails are sent every day\n\n"
            "HOW A TYPICAL ATTACK WORKS:\n"
            "1. You receive an email claiming to be from your bank\n"
            "2. It says your account is suspended — click here to fix it\n"
            "3. The link goes to a fake site that looks identical to your bank\n"
            "4. You enter your credentials — now the attacker has them\n"
            "5. They log into your real account and drain it\n\n"
            "The best defence is learning to recognise the signs before clicking.\n"
            "Ask me: 'How do I spot a phishing email?'"
        ),
    },

    # SPOT A PHISHING EMAIL
    {
        "priority": 9,
        "tags": ["phishing", "detection", "red flags"],
        "keywords": [
            "spot", "identify", "recognise", "recognize", "how to tell",
            "tell if", "how to know", "red flag", "signs of phishing",
            "suspicious email", "fake email", "phishing signs",
            "how do i know if", "how can i tell", "warning signs",
        ],
        "response": (
            "🔍 Key red flags that an email is phishing:\n\n"
            "🚨 HIGH RISK — stop immediately:\n"
            "• Sender domain doesn't match the company\n"
            "  (paypa1.com instead of paypal.com — notice the '1')\n"
            "• URL contains an IP address (http://192.168.1.1/login)\n"
            "• Unexpected attachment (.exe, .zip, .docm files)\n"
            "• Asks for your password, PIN, or full card number\n\n"
            "⚠️  MEDIUM RISK — be cautious:\n"
            "• Urgency: 'URGENT', 'Act now', 'Account suspended'\n"
            "• Generic greeting: 'Dear Customer'\n"
            "• Poor grammar or unusual spelling\n"
            "• Threats: 'Your account closes in 24 hours'\n\n"
            "RULE OF THUMB:\n"
            "If it creates urgency OR asks for credentials — stop.\n"
            "Go directly to the website by typing it yourself."
        ),
    },

    # CHECK A LINK
    {
        "priority": 9,
        "tags": ["links", "url", "safety"],
        "keywords": [
            "check link", "check url", "safe link", "safe url", "hover",
            "suspicious link", "link safe", "url safe", "verify link",
            "is this link safe", "how to check a link", "link checker",
            "unsafe link", "click link safely",
        ],
        "response": (
            "🔗 How to check a link before clicking:\n\n"
            "STEP 1 — HOVER first (desktop only):\n"
            "Hover your mouse over the link without clicking.\n"
            "The real destination URL appears in the bottom-left of your browser.\n\n"
            "STEP 2 — INSPECT THE DOMAIN:\n"
            "✅ paypal.com/login               ← real\n"
            "❌ paypa1.com/login               ← fake ('1' not 'l')\n"
            "❌ paypal.com.verify-now.ru       ← fake (.com is not the end)\n"
            "❌ http://185.234.12.1/paypal     ← IP address, never legitimate\n\n"
            "STEP 3 — USE A FREE SCANNER:\n"
            "• https://www.virustotal.com  — checks 70+ security engines\n"
            "• https://urlvoid.com         — reputation check\n"
            "• https://www.urlscan.io      — screenshots the site safely\n\n"
            "STEP 4 — WHEN IN DOUBT:\n"
            "Type the website address yourself in a new tab.\n"
            "Never click 'verify your account' links in emails."
        ),
    },

    # I CLICKED A PHISHING LINK
    {
        "priority": 9,
        "tags": ["incident", "clicked", "emergency"],
        "keywords": [
            "clicked", "i clicked", "already clicked", "accidentally clicked",
            "clicked a link", "opened a link", "clicked phishing",
            "what if i clicked", "what should i do if i clicked",
            "i think i clicked", "clicked bad link", "opened attachment",
            "i opened", "think i got phished", "got phished",
            "fell for phishing", "entered my details", "gave my password",
        ],
        "response": (
            "🚨 You clicked a phishing link — act fast:\n\n"
            "IMMEDIATE STEPS:\n\n"
            "1. DISCONNECT from the internet\n"
            "   Turn off WiFi — stops malware sending your data out.\n\n"
            "2. DON'T enter any information\n"
            "   If a fake login page appeared — close it immediately.\n\n"
            "3. CHANGE YOUR PASSWORDS\n"
            "   Start with email (most critical — it's the master key).\n"
            "   Then banking, work systems, any reused passwords.\n"
            "   Use a different trusted device if possible.\n\n"
            "4. ENABLE 2FA immediately\n"
            "   Even with a stolen password, 2FA blocks the attacker.\n\n"
            "5. RUN A MALWARE SCAN\n"
            "   Use Windows Defender or Malwarebytes (free).\n\n"
            "6. NOTIFY your IT/security team\n\n"
            "7. MONITOR your accounts for 30 days\n"
            "   Watch for unusual logins or unexpected transactions.\n\n"
            "IF YOU ENTERED PAYMENT DETAILS:\n"
            "Contact your bank immediately to freeze the card."
        ),
    },

    # REPORT PHISHING
    {
        "priority": 8,
        "tags": ["reporting", "incident"],
        "keywords": [
            "report", "reporting", "how to report", "report phishing",
            "where to report", "report email", "forward phishing",
            "received phishing", "got phishing email", "report spam",
            "what to do with phishing email",
        ],
        "response": (
            "📢 How to report a phishing email:\n\n"
            "STEP 1 — Report in your email client:\n"
            "• Gmail: three-dot menu → 'Report phishing'\n"
            "• Outlook: right-click → 'Report' → 'Report phishing'\n\n"
            "STEP 2 — Report to national agencies:\n"
            "• UK: report@phishing.gov.uk\n"
            "• US: reportphishing@apwg.org\n"
            "• Kenya: report to Communications Authority (CA)\n\n"
            "STEP 3 — Report to the impersonated company:\n"
            "• PayPal: spoof@paypal.com\n"
            "• Google: reportphishing@google.com\n\n"
            "STEP 4 — Use PhishGuard:\n"
            "Paste into Detect Email page — gets logged for your org.\n\n"
            "❌ DON'T:\n"
            "• Click links before reporting\n"
            "• Reply to the email\n"
            "• Click 'unsubscribe' — confirms your address is active"
        ),
    },

    # PASSWORDS
    {
        "priority": 8,
        "tags": ["passwords", "security"],
        "keywords": [
            "password", "strong password", "password manager",
            "passphrase", "reuse password", "same password",
            "create password", "good password", "secure password",
            "bitwarden", "1password", "credential stuffing",
        ],
        "response": (
            "🔑 Password best practices:\n\n"
            "WHAT MAKES A STRONG PASSWORD:\n"
            "• Length beats complexity — aim for 16+ characters\n"
            "• 'correct-horse-battery-staple' beats 'P@ssw0rd!'\n"
            "• Unique per site — never reuse across accounts\n"
            "• Never use: name, birthday, pet name\n\n"
            "USE A PASSWORD MANAGER:\n"
            "Generates and stores a unique random password for every site.\n"
            "• Bitwarden  — free, open source ✅\n"
            "• 1Password  — paid, excellent UX\n"
            "• KeePassXC  — offline only, maximum privacy\n\n"
            "YOU ONLY NEED TO REMEMBER:\n"
            "1. Your manager master password\n"
            "2. Your device login\n"
            "3. Your main email password\n\n"
            "⚠️  Check if you've been breached:\n"
            "https://haveibeenpwned.com"
        ),
    },

    # TWO-FACTOR AUTH
    {
        "priority": 8,
        "tags": ["2fa", "mfa", "authentication"],
        "keywords": [
            "2fa", "two factor", "two-factor", "mfa", "multi factor",
            "authenticator", "otp", "one time password", "one time code",
            "google authenticator", "authy", "yubikey", "hardware key",
            "second factor", "verification code", "what is 2fa",
            "how does 2fa work", "enable 2fa",
        ],
        "response": (
            "🔐 Two-Factor Authentication (2FA / MFA):\n\n"
            "WHAT IS IT?\n"
            "A second proof of identity beyond your password.\n"
            "Even if attackers steal your password, they can't log in\n"
            "without this second factor.\n\n"
            "TYPES ranked best to worst:\n"
            "1. 🏆 Hardware key (YubiKey) — immune to phishing\n"
            "2. ✅ Authenticator app — 6-digit code every 30 seconds\n"
            "   Google Authenticator, Authy, Microsoft Authenticator\n"
            "3. ⚠️  SMS code — convenient but can be SIM-swapped\n"
            "4. ❌ Email code — only as secure as your email\n\n"
            "ENABLE IT ON (in order of importance):\n"
            "• Email account — unlocks everything else\n"
            "• Banking and finance\n"
            "• Work systems and VPN\n"
            "• Social media accounts"
        ),
    },

    # SPEAR PHISHING
    {
        "priority": 8,
        "tags": ["spear phishing", "targeted attacks"],
        "keywords": [
            "spear phishing", "spear", "targeted attack", "targeted phishing",
            "whaling", "ceo fraud", "business email compromise", "bec",
            "personalised attack", "targeted email",
        ],
        "response": (
            "🎯 Spear Phishing — targeted attacks:\n\n"
            "REGULAR PHISHING = mass emails, generic, easy to spot.\n\n"
            "SPEAR PHISHING = a crafted email targeting ONE person,\n"
            "using details from LinkedIn, social media, or data breaches.\n\n"
            "EXAMPLE:\n"
            "'Hi Sarah, it's Mike from accounts. Saw your Q3 post —\n"
            "can you urgently approve this invoice? [attachment]'\n\n"
            "WHALING = targeting executives (CEO, CFO)\n"
            "CEO FRAUD = impersonating CEO to trick finance into wire transfers\n"
            "BEC = Business Email Compromise — $2.7B lost per year\n\n"
            "DEFENCE:\n"
            "• Urgent financial request by email → verify by phone\n"
            "  Use a number you already know — not one in the email\n"
            "• Limit what you share publicly on LinkedIn\n"
            "• Require dual approval for wire transfers"
        ),
    },

    # ATTACHMENTS
    {
        "priority": 7,
        "tags": ["attachments", "files", "malware"],
        "keywords": [
            "attachment", "download", "dangerous file", "file type",
            "open attachment", "email attachment", "file extension",
            "is it safe to open", "safe to download", "exe file",
            "pdf safe", "word doc", "excel", "zip file", "macro",
        ],
        "response": (
            "📎 Email attachments — what's safe and what isn't:\n\n"
            "🔴 HIGH RISK — never open from unknown senders:\n"
            "• .exe .msi .bat .cmd .ps1  — run immediately\n"
            "• .docm .xlsm .pptm         — Office files with macros\n"
            "• .zip .rar .7z             — archives hiding malware\n"
            "• .iso .img                 — bypass email filters\n\n"
            "🟡 LOWER RISK (but not zero):\n"
            "• .pdf  — can contain malicious JavaScript\n"
            "• .docx .xlsx — check the sender carefully\n\n"
            "🟢 GENERALLY SAFE:\n"
            "• .txt .csv — plain text, no code execution\n\n"
            "RULES:\n"
            "1. Never open an attachment you weren't expecting\n"
            "2. Never click 'Enable Macros' if Office warns you\n"
            "3. Scan unknowns at virustotal.com first\n"
            "4. Open in Google Drive when possible (macros disabled)"
        ),
    },

    # SMS / VISHING / SMISHING
    {
        "priority": 7,
        "tags": ["smishing", "vishing", "phone scams"],
        "keywords": [
            "vishing", "smishing", "voice phishing", "phone call scam",
            "text message scam", "sms phishing", "sms scam", "fake text",
            "phone scam", "fake call", "qr code", "quishing",
            "phishing via sms", "phishing via phone",
            "are phishing attacks done via",
        ],
        "response": (
            "📱 Phishing beyond email:\n\n"
            "SMISHING (SMS phishing):\n"
            "Fake texts about parcels, bank alerts, prize winnings.\n"
            "Rule: don't click links in unexpected texts — go to\n"
            "the official website directly instead.\n\n"
            "VISHING (Voice phishing):\n"
            "Fake calls from 'your bank', HMRC/IRS, or tech support.\n"
            "They may know your name/address from data breaches.\n"
            "Rule: hang up, call back on the official number.\n\n"
            "QUISHING (QR code phishing):\n"
            "Fake QR codes in emails or posters hiding phishing URLs.\n"
            "Rule: after scanning, check the URL before entering details.\n\n"
            "PRINCIPLE:\n"
            "Any channel can be used for phishing.\n"
            "Always verify through an independent, trusted channel."
        ),
    },

    # SOCIAL ENGINEERING
    {
        "priority": 7,
        "tags": ["social engineering", "manipulation"],
        "keywords": [
            "social engineering", "manipulation", "pretexting", "baiting",
            "tailgating", "impersonation", "psychological attack",
            "scam tactics", "how do attackers manipulate", "human hacking",
            "trick people",
        ],
        "response": (
            "🧠 Social Engineering — hacking humans, not systems:\n\n"
            "WHAT IS IT?\n"
            "Manipulating people psychologically rather than breaking\n"
            "technical systems. Exploits: urgency, fear, trust, greed.\n\n"
            "COMMON TACTICS:\n\n"
            "PRETEXTING: Fake scenario — 'I'm from IT, I need your\n"
            "password to fix a critical issue.'\n\n"
            "BAITING: USB drive in a car park labelled 'Salary Review 2024'.\n"
            "Curiosity gets people to plug it in — malware installs.\n\n"
            "URGENCY & FEAR: 'Your account closes in 2 hours.'\n"
            "Panic bypasses rational thinking.\n\n"
            "AUTHORITY: 'This is the CEO — wire £50,000 now.'\n\n"
            "DEFENCE:\n"
            "• Slow down — urgency is a manipulation tactic\n"
            "• Verify identity through a separate known channel\n"
            "• No legitimate organisation will ask for your password\n"
            "• When in doubt, say 'Let me call you back'"
        ),
    },

    # DATA BREACHES
    {
        "priority": 7,
        "tags": ["data breach", "compromised accounts"],
        "keywords": [
            "data breach", "my data leaked", "account compromised",
            "have i been pwned", "haveibeenpwned", "email leaked",
            "password leaked", "breach", "hacked account", "account hacked",
            "credentials stolen", "dark web",
        ],
        "response": (
            "💥 Data Breaches — what to do:\n\n"
            "FIRST — CHECK IF YOU'RE AFFECTED:\n"
            "Go to https://haveibeenpwned.com\n"
            "Enter your email — shows every known breach with your data.\n"
            "(Trusted site run by security researcher Troy Hunt)\n\n"
            "IF YOUR PASSWORD WAS LEAKED:\n"
            "1. Change it immediately on the affected site\n"
            "2. Change it anywhere you reused that same password\n"
            "3. Enable 2FA on the affected account\n"
            "4. Watch for targeted phishing — attackers use breach data\n\n"
            "IF PAYMENT CARD DETAILS LEAKED:\n"
            "Contact your bank to cancel and reissue the card.\n\n"
            "REALITY CHECK:\n"
            "Most emails appear in at least one breach.\n"
            "Unique passwords per site mean one breach doesn't\n"
            "compromise all your other accounts."
        ),
    },

    # MALWARE
    {
        "priority": 7,
        "tags": ["malware", "ransomware", "viruses"],
        "keywords": [
            "malware", "ransomware", "virus", "trojan", "spyware",
            "keylogger", "infected", "computer infected",
            "remove malware", "malware scan", "computer virus",
            "device infected", "how do i know if i have malware",
        ],
        "response": (
            "🦠 Malware — what it is and what to do:\n\n"
            "TYPES:\n"
            "• Virus      — spreads by attaching to files\n"
            "• Trojan     — disguised as legitimate software\n"
            "• Spyware    — silently records keystrokes\n"
            "• Keylogger  — records passwords and card numbers\n"
            "• Ransomware — encrypts files, demands payment\n\n"
            "SIGNS YOU MAY BE INFECTED:\n"
            "• Computer unusually slow\n"
            "• Unexpected pop-ups or browser redirects\n"
            "• Programs you didn't install\n"
            "• Files encrypted or missing\n\n"
            "WHAT TO DO:\n"
            "1. Disconnect from internet\n"
            "2. Run Malwarebytes (free) full scan\n"
            "3. Run Windows Defender offline scan\n"
            "4. If ransomware — do NOT pay\n"
            "   Check https://www.nomoreransom.org for free decryptors\n"
            "5. Restore from a clean backup\n\n"
            "PREVENTION:\n"
            "• Keep OS updated — patches fix exploits\n"
            "• Don't open unexpected attachments\n"
            "• Use an ad-blocker"
        ),
    },

    # WIFI AND VPN
    {
        "priority": 6,
        "tags": ["wifi", "network", "vpn"],
        "keywords": [
            "wifi", "public wifi", "unsecured network", "vpn",
            "man in the middle", "mitm", "network security",
            "coffee shop wifi", "hotel wifi", "open network",
            "is public wifi safe",
        ],
        "response": (
            "📶 WiFi and Network Security:\n\n"
            "PUBLIC WIFI RISKS:\n"
            "On an open network anyone on the same network can\n"
            "potentially intercept your traffic.\n"
            "This is called a Man-in-the-Middle (MitM) attack.\n\n"
            "HOW TO STAY SAFE:\n"
            "1. USE A VPN — encrypts all traffic before it leaves your device\n"
            "   Recommended: Mullvad, ProtonVPN, or your company VPN\n"
            "2. Only visit HTTPS sites\n"
            "3. Avoid banking on public WiFi\n"
            "4. Use your phone's hotspot instead\n\n"
            "HOME WIFI:\n"
            "• Use WPA3 or WPA2 encryption\n"
            "• Change the default router password\n"
            "• Keep router firmware updated"
        ),
    },

    # PRIVACY
    {
        "priority": 6,
        "tags": ["privacy", "personal information"],
        "keywords": [
            "privacy", "personal information", "oversharing", "linkedin",
            "social media security", "protect personal info",
            "digital footprint", "online privacy",
        ],
        "response": (
            "🔏 Protecting your personal information online:\n\n"
            "WHY IT MATTERS:\n"
            "Attackers use your public info to craft convincing\n"
            "spear phishing emails. More info = more convincing attack.\n\n"
            "LIMIT PUBLICLY:\n"
            "• Date of birth (used for identity verification)\n"
            "• Phone number (used for SIM swapping)\n"
            "• Employer + manager name (used in BEC attacks)\n"
            "• Holiday announcements (signals empty house)\n\n"
            "SOCIAL MEDIA HYGIENE:\n"
            "• Audit your LinkedIn — is work history public?\n"
            "• Set Instagram/Facebook to private\n"
            "• Use a separate email for social media vs banking\n\n"
            "CHECK YOUR FOOTPRINT:\n"
            "Google yourself to see what's publicly visible.\n"
            "Set up https://www.google.com/alerts for your name."
        ),
    },

]

# Sort by priority descending once at startup
TOPICS.sort(key=lambda t: t.get("priority", 0), reverse=True)


# =============================================================
#  MATCHING ENGINE
# =============================================================

def _tokenize(text: str) -> set:
    """
    CONCEPT: Tokenization
    Breaks a sentence into individual meaningful words,
    removing stopwords (common words that add no signal).

    'how do I check if a link is safe'
    → {'check', 'link', 'safe'}

    This allows token-overlap matching to handle rephrased
    questions that don't match any exact keyword phrase.
    """
    stopwords = {
        'i', 'me', 'my', 'a', 'an', 'the', 'is', 'it', 'its',
        'do', 'did', 'does', 'how', 'what', 'when', 'where', 'why',
        'who', 'can', 'could', 'should', 'would', 'will', 'if',
        'to', 'of', 'in', 'on', 'at', 'for', 'and', 'or', 'but',
        'be', 'been', 'being', 'have', 'has', 'had', 'are', 'was',
        'were', 'get', 'got', 'about', 'that', 'this', 'with', 'by',
        'from', 'as', 'into', 'there', 'their', 'they', 'any', 'some',
        'just', 'also', 'more', 'so', 'up', 'out', 'not', 'no', 'than',
        'then', 'now', 'tell', 'know', 'think', 'want', 'need', 'use',
    }
    words = re.findall(r'[a-z0-9]+', text.lower())
    return {w for w in words if w not in stopwords and len(w) > 1}


def _score_topic(msg_tokens: set, topic: dict) -> float:
    """
    CONCEPT: Scoring / ranking
    Scores a topic by token overlap with the user message.

    overlap / total_keyword_tokens = similarity 0.0 to 1.0

    Example:
      message: {'check', 'url', 'virustotal'}
      keyword: {'check', 'link', 'safe', 'url'}
      overlap: {'check', 'url'} = 2
      score:   2/4 = 0.50

    Returns the best score across all keywords in the topic.
    """
    best = 0.0
    for keyword in topic["keywords"]:
        kw_tokens = _tokenize(keyword)
        if not kw_tokens:
            continue
        overlap = len(msg_tokens & kw_tokens)
        score   = overlap / len(kw_tokens)
        if score > best:
            best = score
    return best


def get_response(message: str) -> str:
    """
    Three-layer matching engine.

    Layer 1 — Exact phrase: fastest, handles most questions.
    Layer 2 — Token overlap: handles rephrasing and word order.
    Layer 3 — Smart fallback: always gives a useful response.
    """
    if not message or not message.strip():
        return _greeting_response()

    msg_lower  = message.lower().strip()
    msg_tokens = _tokenize(msg_lower)
    logger.debug("Chatbot: '%s' | tokens: %s", msg_lower[:60], msg_tokens)

    # Layer 1 — Exact keyword phrase match
    for topic in TOPICS:
        for keyword in topic["keywords"]:
            if re.search(re.escape(keyword), msg_lower):
                logger.debug("L1 match: '%s'", keyword)
                return topic["response"]

    # Layer 2 — Token overlap match (handles rephrasing)
    THRESHOLD = 0.40
    best_score, best_topic = 0.0, None
    for topic in TOPICS:
        score = _score_topic(msg_tokens, topic)
        if score >= THRESHOLD and score > best_score:
            best_score, best_topic = score, topic

    if best_topic:
        logger.debug("L2 match: score=%.2f", best_score)
        return best_topic["response"]

    # Layer 3 — Smart fallback
    logger.debug("L3 fallback")
    return _smart_fallback(msg_tokens)


def _greeting_response() -> str:
    for topic in TOPICS:
        if "greeting" in topic.get("tags", []):
            return topic["response"]
    return "👋 Hello! Ask me about phishing, passwords, or email security."


def _smart_fallback(msg_tokens: set) -> str:
    """
    CONCEPT: Graceful degradation
    Score all topics, suggest the top 2 closest ones
    so users always get a useful path forward.
    """
    scored = sorted(
        [(  _score_topic(msg_tokens, t), t) for t in TOPICS],
        reverse=True
    )
    scored = [(s, t) for s, t in scored if s > 0]

    response = "🤔 I'm not sure I understood that exactly.\n\n"

    if scored:
        response += "These topics might help:\n\n"
        for score, topic in scored[:2]:
            label   = topic.get("tags", ["Topic"])[0].title()
            example = max(topic["keywords"], key=len)
            response += f"▸ {label}\n  Try: '{example}'\n\n"
    else:
        response += (
            "Try asking:\n"
            "• 'What is phishing?'\n"
            "• 'I accidentally clicked a phishing link'\n"
            "• 'How do I check if a link is safe?'\n"
            "• 'What is two-factor authentication?'\n"
        )

    response += "\nOr type 'help' to see all topics."
    return response


def get_topics() -> list:
    """
    Returns suggested questions guaranteed to match the engine.
    Used by the frontend to generate chip buttons dynamically.
    Keeps chips and knowledge base always in sync.
    """
    return [
        {"label": "What is phishing?",        "question": "What is phishing?"},
        {"label": "Spot phishing emails",      "question": "How do I spot a phishing email?"},
        {"label": "Check suspicious links",    "question": "How do I check if a link is safe?"},
        {"label": "I clicked a bad link",      "question": "I accidentally clicked a phishing link"},
        {"label": "Report phishing",           "question": "How do I report a phishing email?"},
        {"label": "Strong passwords",          "question": "How do I create a strong password?"},
        {"label": "Two-factor auth (2FA)",     "question": "What is two-factor authentication?"},
        {"label": "Spear phishing",            "question": "What is spear phishing?"},
        {"label": "Dangerous attachments",     "question": "Are email attachments dangerous?"},
        {"label": "SMS and phone scams",       "question": "Are phishing attacks done via SMS or phone calls?"},
        {"label": "Social engineering",        "question": "What is social engineering?"},
        {"label": "Data breaches",             "question": "What should I do if my data was breached?"},
        {"label": "Malware and ransomware",    "question": "What is malware?"},
        {"label": "Public WiFi safety",        "question": "Is public WiFi safe?"},
        {"label": "Protect personal info",     "question": "How do I protect my personal information online?"},
    ]
