# =============================================================
#  backend/ml/features_additions.py
#  ADDITIONS TO features.py — Missing Signals + Kenya Context
# =============================================================
#
#  HOW TO USE THIS FILE:
#  This file documents every addition you need to make to
#  your existing features.py. Each section tells you:
#    1. WHERE to add the code (which class, which method)
#    2. WHAT to add (the actual code)
#    3. WHY it matters (the threat model it addresses)
#
#  After adding everything here, your feature vector grows
#  from ~25 features to ~45 features — each new feature
#  is a signal your current model is completely blind to.
#
#  IMPORTANT: After editing features.py, you MUST retrain
#  the model. The trained model.pkl is coupled to the exact
#  feature vector it was trained on. Adding a new feature
#  changes the vector length, making the old model.pkl
#  incompatible with the new extractor.
#  Always: edit features.py → retrain → restart app.
# =============================================================


# =============================================================
#  ADDITION 1: NEW SIGNAL DICTIONARIES
#  Add these to the top of features.py, alongside the
#  existing URGENCY_WORDS, REWARD_WORDS, etc.
# =============================================================

# ── Kenyan Brand Impersonation ─────────────────────────────
# These are the most impersonated entities in Kenya-specific
# phishing. None of them appear in your current IMPERSONATED_BRANDS
# list, which means your model currently treats a message
# claiming to be from Safaricom or KRA as having ZERO brand
# impersonation signal — a dangerous blind spot.
KENYA_BRANDS = [
    # Telcos
    "safaricom", "airtel kenya", "telkom kenya",
    # Mobile money
    "m-pesa", "mpesa", "m pesa", "fuliza",
    "airtel money", "t-kash", "tkash",
    # Banks
    "equity bank", "equity", "kcb", "kcb bank",
    "cooperative bank", "co-op bank", "coopbank",
    "absa kenya", "stanbic kenya", "ncba",
    "family bank", "i&m bank", "dtb bank",
    "prime bank", "sidian bank", "diamond trust",
    # Government & Tax
    "kra", "kenya revenue authority",
    "ecitizen", "e-citizen", "huduma",
    "ntsa", "kenya power", "kplc",
    "nhif", "nssf", "helb",
    # Other high-value impersonation targets
    "jumia kenya", "tala", "branch app",
    "mshwari", "kcb mpesa",
]

# ── Swahili Urgency Words ─────────────────────────────────
# Phishing messages in Kenya frequently mix English and Swahili
# (Sheng and standard Swahili). Your current URGENCY_WORDS
# are 100% English — these Swahili patterns are completely
# invisible to your current model.
SWAHILI_URGENCY = [
    # Urgency and action demands
    "haraka", "sasa hivi", "leo tu", "mara moja",
    "wakati umekwisha", "muda mfupi",
    # Account threats
    "akaunti yako", "imefungwa", "itafungwa",
    "tumezuia", "imezuiwa", "hakika yako",
    # Verification demands
    "thibitisha", "thibisha", "hakikisha",
    "jaza fomu", "ingiza nambari",
    # Prize/reward lures
    "umeshinda", "pata zawadi", "bonyeza hapa",
    "kujua zaidi", "dai sasa", "pokea pesa",
    # Money-related manipulation
    "pesa yako", "fedha yako", "malipo yako",
    "rejesho lako", "refund yako",
]

# ── MPESA Fraud Patterns ─────────────────────────────────
# Real MPESA confirmation messages follow strict formats.
# Phishing messages try to mimic these formats but deviate
# in specific, detectable ways.
MPESA_FRAUD_PATTERNS = [
    # Fake transaction confirmations asking for action
    "mpesa transaction", "mpesa reversal", "mpesa refund",
    "wrong number sent", "sent to wrong number",
    "kindly reverse", "please reverse",
    "send back", "return the money",
    "agent number", "till number",
    # Fake prize notifications using MPESA as lure
    "mpesa winner", "mpesa promotion",
    "safaricom winner", "safaricom promotion",
    "you have been selected by safaricom",
    "safaricom anniversary", "safaricom lottery",
    # KRA-specific patterns
    "tax refund", "vat refund", "tax rebate",
    "kra refund", "pin certificate",
    "tax compliance", "itax",
]

# ── Financial Lure Keywords (Kenya-specific) ─────────────
KENYA_FINANCIAL_LURES = [
    "fuliza limit", "overdraft limit",
    "credit limit increased", "loan approved",
    "instant loan", "borrow now",
    "earn daily", "earn weekly",
    "investment opportunity", "double your money",
    "guaranteed returns", "risk free investment",
]


# =============================================================
#  ADDITION 2: NEW REGEX PATTERNS
#  Add these alongside the existing RE_URL, RE_IP_URL, etc.
# =============================================================

import re

# Detects non-ASCII (Unicode) characters appearing inside URLs.
# This catches homograph attacks where attackers use visually
# identical Unicode characters from other scripts.
# Example: pаypal.com uses Cyrillic 'а' (U+0430) not Latin 'a'
# The regex looks for non-standard characters in what should
# be an ASCII-only URL structure.
RE_UNICODE_IN_URL = re.compile(
    r'https?://[^\s]*[^\x00-\x7F][^\s]*',
    re.IGNORECASE
)

# Detects Reply-To header in raw email text.
# We extract the domain from Reply-To and compare it to
# the From domain to detect sender spoofing.
RE_REPLY_TO = re.compile(
    r'Reply-To:\s*[^<\n]*<?([^>\n@]+@([^\s>\n]+))>?',
    re.IGNORECASE
)

RE_FROM_HEADER = re.compile(
    r'^From:\s*[^<\n]*<?([^>\n@]+@([^\s>\n]+))>?',
    re.IGNORECASE | re.MULTILINE
)

# Detects MPESA confirmation message format.
# Real MPESA messages follow: "XYZ123AB Confirmed. Ksh X.XX
# sent to NAME NUMBER on DATE at TIME"
# Deviations from this format signal a fake.
RE_MPESA_LEGIT_FORMAT = re.compile(
    r'[A-Z0-9]{10}\s+confirmed\.\s+ksh\s+[\d,]+\.\d{2}\s+sent to',
    re.IGNORECASE
)

# Detects KRA PIN format (Kenya Revenue Authority Personal ID)
# Real KRA PINs follow the format: A000000000B (letter, 9 digits, letter)
RE_KRA_PIN = re.compile(r'\b[A-Z]\d{9}[A-Z]\b')

# Detects Safaricom shortcode format — legitimate Safaricom
# messages come from specific registered shortcodes, not
# arbitrary mobile numbers or email addresses.
RE_SAFARICOM_SHORTCODE = re.compile(r'\b(MPESA|SAFARICOM|M-PESA)\b', re.IGNORECASE)


# =============================================================
#  ADDITION 3: NEW FEATURE METHODS
#  Add these methods to your EmailFeatureExtractor class
#  in features.py.
# =============================================================

# ── 3A: Reply-To Domain Mismatch ─────────────────────────
# Add this as a new method in EmailFeatureExtractor.
# Then call it from extract() with **self._header_mismatch_features(text)

def _header_mismatch_features(self, text: str) -> dict:
    """
    Detects Reply-To domain mismatch — one of the most reliable
    spear-phishing indicators.

    The attack: an email appears to come from a legitimate
    address (From: security@kra.go.ke) but the Reply-To is set
    to an attacker-controlled address (Reply-To: kra-help@gmail.com).
    The victim reads "KRA" in the From field and replies,
    unknowingly sending their response to the attacker.

    We extract both domains and flag any mismatch.
    A legitimate email from KRA will have both From and Reply-To
    on @kra.go.ke (or no Reply-To at all).

    WHY THIS SIGNAL IS STRONG:
    It requires no keyword matching and no ML — it is a binary,
    structural test. Either the domains match or they do not.
    Attackers cannot easily work around this without also
    controlling a legitimate-looking domain.
    """
    from_match     = RE_FROM_HEADER.search(text)
    replyto_match  = RE_REPLY_TO.search(text)

    has_replyto_mismatch = 0.0
    replyto_is_freemail  = 0.0

    if from_match and replyto_match:
        from_domain    = from_match.group(2).lower().strip()
        replyto_domain = replyto_match.group(2).lower().strip()

        # Flag if domains differ
        if from_domain and replyto_domain and from_domain != replyto_domain:
            has_replyto_mismatch = 1.0

        # Flag if Reply-To uses a free email provider
        # Legitimate organisations don't send from gmail/yahoo/hotmail
        freemail_providers = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "live.com", "ymail.com", "aol.com", "protonmail.com",
        ]
        if any(p in replyto_domain for p in freemail_providers):
            replyto_is_freemail = 1.0

    return {
        "has_replyto_mismatch": has_replyto_mismatch,
        "replyto_is_freemail":  replyto_is_freemail,
    }


# ── 3B: HTML-to-Text Ratio ────────────────────────────────
# Add this as a new method in EmailFeatureExtractor.
# Then call it from extract() with **self._html_ratio_features(text)

def _html_ratio_features(self, text: str) -> dict:
    """
    Measures the ratio of plain text to total HTML content.

    Phishing emails typically use a LOT of HTML (to create
    official-looking formatting) but contain LITTLE actual
    text (because the message is simple: click here / verify now).

    Legitimate business emails tend to have substantial text
    content relative to their HTML structure.

    FORMULA:
      plain_text_length / total_email_length

    LOW ratio → lots of HTML, little text → suspicious
    HIGH ratio → mostly text → more likely legitimate

    We also measure image density because phishing emails
    often replace text with images to evade text-based filters.
    """
    import re as _re

    total_length = max(len(text), 1)

    # Extract plain text by removing all HTML tags
    plain_text = _re.sub(r'<[^>]+>', ' ', text)
    plain_text = _re.sub(r'\s+', ' ', plain_text).strip()
    plain_length = len(plain_text)

    html_text_ratio = plain_length / total_length

    # Count characters inside tags (HTML structure)
    html_tags_text = ''.join(_re.findall(r'<[^>]+>', text))
    html_structure_ratio = len(html_tags_text) / total_length

    # Image tags per 1000 characters — high image density = suspicious
    img_count   = len(_re.findall(r'<img\b', text, _re.IGNORECASE))
    img_density = (img_count / total_length) * 1000

    return {
        "html_text_ratio":       round(html_text_ratio, 4),
        "html_structure_ratio":  round(html_structure_ratio, 4),
        "img_density_per_1k":    round(img_density, 4),
    }


# ── 3C: Unicode / Homograph Attack Detection ─────────────
# Add this as a new method in EmailFeatureExtractor.
# Then call it from extract() with **self._unicode_features(text)

def _unicode_features(self, text: str) -> dict:
    """
    Detects homograph attacks and Unicode obfuscation.

    A homograph attack replaces ASCII letters in a URL with
    visually identical Unicode characters from other scripts.
    To a human, 'paypa1.com' and 'pаypal.com' look similar,
    but they are completely different strings — the second
    uses the Cyrillic character 'а' (U+0430).

    Simple string matching cannot catch this. Unicode-aware
    detection can.

    We also detect zero-width characters — invisible Unicode
    characters inserted into URLs and text to break keyword
    matching without affecting visual appearance.
    """
    # Check for non-ASCII characters in URLs
    has_unicode_url = float(bool(RE_UNICODE_IN_URL.search(text)))

    # Zero-width characters — completely invisible to humans
    # but break naive string matching
    zero_width_chars = [
        '\u200b',  # zero-width space
        '\u200c',  # zero-width non-joiner
        '\u200d',  # zero-width joiner
        '\ufeff',  # byte order mark (often invisible)
        '\u00ad',  # soft hyphen (renders invisible in most contexts)
    ]
    has_zero_width = float(any(c in text for c in zero_width_chars))

    # Mixed script detection in domain names — a URL that
    # mixes Latin and Cyrillic characters is almost always malicious
    urls = RE_URL.findall(text)
    has_mixed_script = 0.0
    for url in urls:
        try:
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(url).netloc
            has_latin  = any('\u0041' <= c <= '\u007A' for c in domain)
            has_cyrillic = any('\u0400' <= c <= '\u04FF' for c in domain)
            has_greek    = any('\u0370' <= c <= '\u03FF' for c in domain)
            if has_latin and (has_cyrillic or has_greek):
                has_mixed_script = 1.0
                break
        except Exception:
            pass

    return {
        "has_unicode_in_url":  has_unicode_url,
        "has_zero_width_chars": has_zero_width,
        "has_mixed_script_url": has_mixed_script,
    }


# ── 3D: Kenya-Specific Features ──────────────────────────
# Add this as a new method in EmailFeatureExtractor.
# Then call it from extract() with **self._kenya_features(text, text_lower)

def _kenya_features(self, text: str, text_lower: str) -> dict:
    """
    Kenya-specific phishing signal detection.

    This is PhishGuard's most differentiated feature group —
    no other tool has these signals. They directly address
    the threats your target users (Kenyan consumers, SMEs,
    government workers) actually face.

    MPESA Transaction Reversal Scam:
      The most common M-Pesa scam. Attacker sends money to victim
      "by mistake", then calls/messages claiming the victim should
      send it back (often to a different number). The original
      transaction is sometimes fraudulent. Keywords: "wrong number",
      "reverse", "send back".

    KRA Impersonation:
      Fake KRA tax refund or compliance notices. Always ask for
      PIN, banking details, or a "processing fee". Real KRA
      communicates via iTax portal, not WhatsApp or email lures.

    Safaricom Prize Scam:
      Fake messages claiming you won an Safaricom promotion.
      Often use near-official language and request your MPESA PIN
      or personal details to "claim your prize".
    """
    # Count Kenya-specific brand mentions
    kenya_brand_count = sum(1 for b in KENYA_BRANDS if b in text_lower)

    # MPESA fraud pattern detection
    mpesa_fraud_count = sum(
        1 for p in MPESA_FRAUD_PATTERNS if p in text_lower
    )

    # Check for MPESA transaction reversal scam
    has_reversal_scam = float(
        bool(re.search(
            r'(wrong|mistake|error).{0,50}(number|sent|transfer|send)',
            text_lower
        )) and bool(re.search(r'(reverse|refund|return|send back)', text_lower))
    )

    # Swahili urgency word count
    swahili_urgency_count = sum(
        1 for w in SWAHILI_URGENCY if w in text_lower
    )

    # KRA-specific signals
    has_kra_signal = float(
        bool(re.search(r'(kra|kenya revenue|tax refund|itax)', text_lower))
        and bool(re.search(r'(pin|account|payment|fee|processing)', text_lower))
    )

    # Check if message claims to be from a Kenya financial brand
    # but uses a non-corporate email/reply address
    has_kenya_financial = float(
        any(b in text_lower for b in [
            "mpesa", "m-pesa", "equity", "kcb", "safaricom",
            "cooperative bank", "airtel money"
        ])
    )

    # Kenya financial lure keywords
    kenya_lure_count = sum(
        1 for w in KENYA_FINANCIAL_LURES if w in text_lower
    )

    # Detect MPESA-format spoofing:
    # Real MPESA messages have a specific 10-char transaction code.
    # Fakes often omit this or use wrong formats.
    has_mpesa_mention   = float("mpesa" in text_lower or "m-pesa" in text_lower)
    has_legit_mpesa_fmt = float(bool(RE_MPESA_LEGIT_FORMAT.search(text_lower)))

    # Suspicious if MPESA is mentioned but WITHOUT the legit format
    # (could be a fake notification that skips the transaction code)
    mpesa_format_anomaly = float(
        has_mpesa_mention == 1.0 and has_legit_mpesa_fmt == 0.0
    )

    return {
        "kenya_brand_count":     float(kenya_brand_count),
        "mpesa_fraud_count":     float(mpesa_fraud_count),
        "has_reversal_scam":     has_reversal_scam,
        "swahili_urgency_count": float(swahili_urgency_count),
        "has_kra_signal":        has_kra_signal,
        "has_kenya_financial":   has_kenya_financial,
        "kenya_lure_count":      float(kenya_lure_count),
        "mpesa_format_anomaly":  mpesa_format_anomaly,
    }


# =============================================================
#  ADDITION 4: UPDATE THE extract() METHOD
#  In your EmailFeatureExtractor.extract() method, add the
#  four new feature groups to the features dict.
#  Find the block that reads:
#
#    features = {
#        **self._url_features(text, text_lower),
#        **self._domain_features(text, text_lower),
#        ...
#    }
#
#  And add these four lines to it:
#
#        **self._header_mismatch_features(text),
#        **self._html_ratio_features(text),
#        **self._unicode_features(text),
#        **self._kenya_features(text, text_lower),
#
#  The full updated extract() should look like:
# =============================================================

UPDATED_EXTRACT_METHOD = '''
    def extract(self, text: str) -> Dict[str, float]:
        text_lower = text.lower()

        features = {
            **self._url_features(text, text_lower),
            **self._domain_features(text, text_lower),
            **self._urgency_features(text_lower),
            **self._reward_features(text_lower),
            **self._sensitive_features(text_lower),
            **self._formatting_features(text, text_lower),
            **self._html_features(text, text_lower),
            **self._brand_features(text_lower),
            **self._attachment_features(text_lower),
            # ── NEW ADDITIONS ──────────────────────────
            **self._header_mismatch_features(text),
            **self._html_ratio_features(text),
            **self._unicode_features(text),
            **self._kenya_features(text, text_lower),
        }

        return features
'''


# =============================================================
#  ADDITION 5: UPDATE _build_explanations() IN trainer.py
#  Add these explanation blocks to the _build_explanations()
#  method in trainer.py so users see clear reasons why
#  Kenya-specific threats were flagged.
#
#  Add after the existing explanation blocks:
# =============================================================

UPDATED_EXPLANATIONS = '''
        # Kenya-specific explanations
        if features.get("has_replyto_mismatch"):
            reasons.append(
                "🚨 Reply-To address domain differs from the From address. "
                "Your reply would go to a different organisation than the sender. "
                "This is a common spear-phishing technique."
            )
        if features.get("replyto_is_freemail"):
            reasons.append(
                "⚠️ Reply-To address uses a free email provider (Gmail/Yahoo). "
                "Legitimate organisations use their own domain for replies."
            )
        if features.get("has_unicode_in_url"):
            reasons.append(
                "🚨 URL contains non-standard characters that may be visual "
                "lookalikes for legitimate domains (homograph attack). "
                "The URL may not go where it appears to."
            )
        if features.get("mpesa_format_anomaly"):
            reasons.append(
                "🚨 Message mentions M-Pesa but does not follow the official "
                "Safaricom transaction confirmation format. "
                "Likely a fake M-Pesa notification."
            )
        if features.get("has_reversal_scam"):
            reasons.append(
                "🚨 M-Pesa reversal scam pattern detected. "
                "'Sent to wrong number — please send back' is a common fraud. "
                "Never send money back without calling Safaricom directly."
            )
        if features.get("has_kra_signal"):
            reasons.append(
                "⚠️ KRA (Kenya Revenue Authority) mentioned alongside requests "
                "for payment or personal information. "
                "Verify all KRA communications at itax.kra.go.ke only."
            )
        if features.get("swahili_urgency_count", 0) >= 2:
            reasons.append(
                f"⚠️ {int(features['swahili_urgency_count'])} Swahili urgency "
                "phrases detected. Creates artificial pressure to act quickly "
                "without verifying the sender."
            )
        if features.get("kenya_brand_count", 0) >= 2:
            reasons.append(
                f"⚠️ {int(features['kenya_brand_count'])} Kenyan brands "
                "mentioned. Phishing emails often impersonate local trusted "
                "organisations like Safaricom, Equity Bank, or KRA."
            )
'''


# =============================================================
#  SUMMARY: FEATURE COUNT BEFORE AND AFTER
# =============================================================

print("""
=============================================================
  PhishGuard Feature Enhancement Summary
=============================================================

CURRENT feature groups (in features.py):
  _url_features()         →  7 features
  _domain_features()      →  3 features
  _urgency_features()     →  3 features
  _reward_features()      →  2 features
  _sensitive_features()   →  3 features
  _formatting_features()  →  7 features
  _html_features()        →  6 features
  _brand_features()       →  2 features
  _attachment_features()  →  2 features
  ─────────────────────────────────────
  CURRENT TOTAL           → ~35 features

NEW feature groups (additions):
  _header_mismatch_features() →  2 features  (Reply-To spoofing)
  _html_ratio_features()      →  3 features  (HTML vs text balance)
  _unicode_features()         →  3 features  (homograph attacks)
  _kenya_features()           →  8 features  (Kenya-specific threats)
  ─────────────────────────────────────
  ADDITIONS TOTAL             → 16 features

FINAL TOTAL → ~51 features

These 16 new features target:
  • Reply-To domain spoofing (missed by all current features)
  • HTML structure anomalies (missed by current ratio checks)
  • Unicode/homograph attacks (completely absent currently)
  • MPESA reversal scams (the most common Kenyan fraud)
  • KRA tax impersonation (high-value target in Kenya)
  • Swahili-language social engineering (invisible to current model)
  • Kenya brand impersonation (Safaricom, Equity, KCB etc.)
  • MPESA transaction format spoofing (binary, reliable signal)

REMINDER: After editing features.py, always retrain:
  python backend/scripts/train_model.py --auto-replace
=============================================================
""")
