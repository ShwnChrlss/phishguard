# =============================================================
#  backend/ml/features.py
#  Hand-Crafted Feature Extraction
# =============================================================
#
#  CONCEPT: What is a "feature"?
#
#  Machine learning models cannot read text. They only work
#  with NUMBERS. A "feature" is one measurable property of an
#  email converted into a number.
#
#  Example:
#    Email text: "URGENT!! Verify your PayPal account NOW!!!"
#    Features:
#      urgency_keyword_count  = 2   ("urgent", "now")
#      exclamation_count      = 3
#      caps_ratio             = 0.4  (40% of letters are caps)
#      has_brand_impersonation = 1   ("paypal" found)
#
#  The model learns: "when these numbers look like THIS,
#  it's usually phishing."
#
#  WHY hand-craft features instead of letting the model figure
#  it all out from raw text?
#    - Domain knowledge makes the model faster and more accurate
#    - TF-IDF handles the raw word signals
#    - We handle the structural signals TF-IDF can't see:
#      URL patterns, header anomalies, formatting tricks
#    - Combining both gives us the best of both worlds
#
#  FEATURE GROUPS IN THIS FILE:
#    1.  URL features          (links, IP addresses, shorteners)
#    2.  Domain features       (lookalikes, mismatches, TLDs)
#    3.  Urgency features      (pressure words, time threats)
#    4.  Reward features       (prize lures, financial baits)
#    5.  Sensitive info        (requests for passwords, SSN etc.)
#    6.  Formatting features   (CAPS, punctuation, length)
#    7.  HTML features         (hidden text, suspicious tags)
#    8.  Header features       (spoofed From, Reply-To tricks)
#    9.  Brand impersonation   (fake PayPal, Amazon, etc.)
#    10. Attachment features   (suspicious file types)
# =============================================================

import re
import math
from typing import Dict, List
from urllib.parse import urlparse


# =============================================================
#  SIGNAL DICTIONARIES
#  These are the word lists we search for in every email.
#  Defined at module level so they're compiled once, not
#  re-created every time extract() is called.
# =============================================================

# Words that create artificial urgency or fear.
# Phishers want you to act without thinking.
URGENCY_WORDS = [
    "urgent", "immediately", "action required", "act now",
    "verify now", "confirm now", "respond immediately",
    "account suspended", "account will be closed",
    "account has been locked", "limited time", "expires soon",
    "within 24 hours", "within 48 hours", "last chance",
    "final notice", "warning", "alert", "critical",
    "your account will be", "suspended", "terminated",
    "unauthorized access", "suspicious activity",
    "unusual sign-in", "security breach",
]

# Words that promise rewards to lure victims into clicking.
REWARD_WORDS = [
    "winner", "you have won", "congratulations", "selected",
    "prize", "reward", "bonus", "free", "claim now",
    "gift card", "lottery", "jackpot", "you are entitled",
    "special offer", "exclusive deal", "limited offer",
    "cash prize", "voucher", "redeem",
]

# Words that ask for sensitive personal or financial information.
SENSITIVE_WORDS = [
    "password", "pin number", "social security",
    "credit card", "debit card", "bank account",
    "account number", "routing number", "billing information",
    "date of birth", "mother's maiden name", "ssn",
    "national insurance", "tax id", "driver's license",
    "passport number", "security question",
]

# URL shortening services — they hide the real destination.
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.io", "rebrand.ly", "is.gd",
    "tiny.cc", "lnkd.in", "ift.tt", "cutt.ly",
]

# Top-level domains (.tk, .ml etc.) that are free or cheap
# and disproportionately used for phishing infrastructure.
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom free domains
    ".xyz", ".click", ".download", ".link",
    ".online", ".site", ".top", ".loan",
    ".win", ".bid", ".stream", ".faith",
]

# Well-known brands phishers most commonly impersonate.
# Source: APWG Phishing Trends Reports.
IMPERSONATED_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft",
    "netflix", "facebook", "instagram", "linkedin", "twitter",
    "dropbox", "docusign", "fedex", "ups", "dhl", "usps",
    "irs", "hmrc", "bank of america", "chase", "wells fargo",
    "citibank", "american express", "visa", "mastercard",
]

# Attachment extensions that can execute code or hide malware.
DANGEROUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z",   # often contain the above
    ".doc", ".docm", ".xls", ".xlsm",  # macro-enabled Office
    ".iso", ".img",
]


# =============================================================
#  REGEX PATTERNS
#  Compiled once at module load time — faster than compiling
#  inside a loop. re.compile() is the expensive step;
#  calling .search() on a compiled pattern is cheap.
# =============================================================

# Matches any HTTP/HTTPS URL in text
RE_URL = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

# Matches IPv4 addresses (e.g. 192.168.1.1) inside a URL
RE_IP_URL = re.compile(
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE
)

# HTML <a href="...">display text</a> pattern
RE_ANCHOR = re.compile(
    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)

# CSS tricks that hide text from the human reader
RE_HIDDEN = re.compile(
    r'(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)',
    re.IGNORECASE
)

# Lookalike domain patterns — digits replacing letters
# (paypa1, amaz0n, g00gle) or hyphens before brand names
RE_LOOKALIKE = re.compile(
    r'(paypa[l1]|amaz[o0]n|g[o0]{2}gle|micros[o0]ft|app[l1]e'
    r'|faceb[o0]{2}k|netfl[i1]x|inst[a@]gram'
    r'|-paypal|-amazon|-apple|-google|-microsoft)',
    re.IGNORECASE
)

# Detects when the @ sign is used inside a URL to trick you.
# https://legitimate.com@evil.com/phish → browser goes to evil.com
RE_AT_IN_URL = re.compile(r'https?://[^@]+@', re.IGNORECASE)

# HTML tags count — emails with many tags can hide content
RE_HTML_TAGS = re.compile(r'<[^>]+>')

# Detects base64-encoded content (sometimes used to hide payloads)
RE_BASE64 = re.compile(r'base64', re.IGNORECASE)


# =============================================================
#  MAIN EXTRACTOR CLASS
# =============================================================

class EmailFeatureExtractor:
    """
    Extracts a fixed-length numerical feature vector from email text.

    Usage:
        extractor = EmailFeatureExtractor()
        features = extractor.extract(email_text)
        # features is a dict: {"url_count": 3, "caps_ratio": 0.4, ...}

        # For ML training, convert to a list of values:
        feature_values = list(features.values())

    The feature vector is ALWAYS the same length and in the SAME
    order, regardless of the email content. This consistency is
    required by scikit-learn — every row in the training matrix
    must have the same number of columns.
    """

    def extract(self, text: str) -> Dict[str, float]:
        """
        Main entry point. Takes raw email text, returns a dict
        mapping feature name → numeric value.

        All values are floats (even counts), because scikit-learn
        works best with consistent numeric types.

        Args:
            text: The full email text (headers + body combined).

        Returns:
            OrderedDict of feature_name → float value.
            Always the same keys in the same order.
        """
        text_lower = text.lower()

        # Build the feature dict by calling each group of extractors.
        # dict unpacking (**) merges them into one flat dict.
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
        }

        return features

    def get_feature_names(self) -> List[str]:
        """
        Returns the list of feature names in extraction order.
        Useful for interpreting which features a model found important.
        """
        return list(self.extract("dummy text for schema").keys())

    def extract_batch(self, texts: List[str]):
        """
        Extracts features from a list of emails.
        Returns a 2D list: rows = emails, cols = features.
        This is the shape scikit-learn expects.

        Args:
            texts: List of email strings.

        Returns:
            List of lists — shape (n_emails, n_features).
        """
        return [list(self.extract(t).values()) for t in texts]

    # ── FEATURE GROUP 1: URL FEATURES ─────────────────────────

    def _url_features(self, text: str, text_lower: str) -> Dict[str, float]:
        """
        URLs are one of the strongest phishing signals.
        Legitimate emails link to known domains.
        Phishing emails link to IP addresses, shorteners,
        lookalike domains, and recently-registered sites.
        """
        urls = RE_URL.findall(text)
        n_urls = len(urls)

        # Check each URL for specific bad patterns
        has_ip_url       = 0
        has_at_url       = 0
        has_shortener    = 0
        has_susp_tld     = 0
        max_url_length   = 0

        for url in urls:
            url_lower = url.lower()

            # IP address in URL instead of domain name
            # Legitimate services use domain names, not raw IPs.
            if RE_IP_URL.search(url):
                has_ip_url = 1

            # @ symbol inside URL — classic spoofing trick
            # https://paypal.com@evil.com → goes to evil.com
            if RE_AT_IN_URL.search(url):
                has_at_url = 1

            # URL shortener — hides true destination
            if any(s in url_lower for s in URL_SHORTENERS):
                has_shortener = 1

            # Suspicious free TLD
            if any(url_lower.endswith(tld) or f"{tld}/" in url_lower
                   for tld in SUSPICIOUS_TLDS):
                has_susp_tld = 1

            # Very long URLs often hide real destinations with
            # extra parameters or obfuscation
            max_url_length = max(max_url_length, len(url))

        return {
            "url_count":          float(n_urls),
            "has_ip_url":         float(has_ip_url),
            "has_at_in_url":      float(has_at_url),
            "has_url_shortener":  float(has_shortener),
            "has_suspicious_tld": float(has_susp_tld),
            "max_url_length":     float(min(max_url_length, 500)),  # cap outliers
            "urls_per_100_chars": float(n_urls) / max(len(text) / 100, 1),
        }

    # ── FEATURE GROUP 2: DOMAIN FEATURES ──────────────────────

    def _domain_features(self, text: str, text_lower: str) -> Dict[str, float]:
        """
        Domain-level tricks: lookalike domains, hyperlink
        mismatches (link text ≠ href destination), subdomain abuse.
        """
        has_lookalike = float(bool(RE_LOOKALIKE.search(text_lower)))

        # Hyperlink mismatch: <a href="evil.com">paypal.com</a>
        # The user sees "paypal.com" but clicking goes to "evil.com".
        has_mismatch = 0.0
        anchors = RE_ANCHOR.findall(text)
        for href, display in anchors:
            href_lower    = href.strip().lower()
            display_lower = display.strip().lower()

            # If display text looks like a URL but differs from href
            if display_lower.startswith("http") and href_lower:
                try:
                    href_domain    = urlparse(href_lower).netloc
                    display_domain = urlparse(display_lower).netloc
                    if href_domain and display_domain:
                        if href_domain != display_domain:
                            has_mismatch = 1.0
                            break
                except Exception:
                    pass

        # Count subdomains — phishers use:
        # paypal.secure-login.evil.com (many dots in domain)
        subdomain_depths = []
        for url in RE_URL.findall(text):
            try:
                netloc = urlparse(url).netloc
                dots = netloc.count(".")
                subdomain_depths.append(dots)
            except Exception:
                pass
        max_subdomain_depth = float(max(subdomain_depths, default=0))

        return {
            "has_lookalike_domain": has_lookalike,
            "has_hyperlink_mismatch": has_mismatch,
            "max_subdomain_depth": max_subdomain_depth,
        }

    # ── FEATURE GROUP 3: URGENCY FEATURES ─────────────────────

    def _urgency_features(self, text_lower: str) -> Dict[str, float]:
        """
        Phishers create artificial urgency to prevent you from
        thinking clearly. "Your account closes in 24 hours!" 
        pressures you to act before verifying legitimacy.

        We count matching words — more matches = higher risk.
        """
        count = sum(1 for w in URGENCY_WORDS if w in text_lower)

        # Check for time-pressure patterns ("24 hours", "48 hours")
        has_time_pressure = float(
            bool(re.search(r'\d+\s*(hour|minute|day)s?\b', text_lower))
        )

        # Threats of account termination
        has_account_threat = float(
            bool(re.search(
                r'(account|access).{0,30}(close|suspend|terminat|delet|block)',
                text_lower
            ))
        )

        return {
            "urgency_word_count":  float(count),
            "has_time_pressure":   has_time_pressure,
            "has_account_threat":  has_account_threat,
        }

    # ── FEATURE GROUP 4: REWARD / LURE FEATURES ───────────────

    def _reward_features(self, text_lower: str) -> Dict[str, float]:
        """
        The "too good to be true" lure. Prizes, free gifts, and
        lottery wins that require you to click a link to claim.
        """
        count = sum(1 for w in REWARD_WORDS if w in text_lower)

        # "You have been selected" / "You are a winner" patterns
        has_winner_pattern = float(
            bool(re.search(
                r'(you (have|are|were)|congratulations).{0,40}(won|winner|selected|chosen)',
                text_lower
            ))
        )

        return {
            "reward_word_count":  float(count),
            "has_winner_pattern": has_winner_pattern,
        }

    # ── FEATURE GROUP 5: SENSITIVE INFO REQUESTS ──────────────

    def _sensitive_features(self, text_lower: str) -> Dict[str, float]:
        """
        Legitimate organisations NEVER ask for passwords or full
        credit card numbers via email. Any such request is a
        near-certain phishing indicator.
        """
        count = sum(1 for w in SENSITIVE_WORDS if w in text_lower)

        # Direct password request
        has_password_req = float("password" in text_lower or "passcode" in text_lower)

        # Form submission language
        has_form_request = float(
            bool(re.search(
                r'(fill (in|out)|submit|enter|provide|confirm|update)\s.{0,30}'
                r'(your|the)\s.{0,20}(detail|info|account|password|credential)',
                text_lower
            ))
        )

        return {
            "sensitive_word_count": float(count),
            "has_password_request": has_password_req,
            "has_form_request":     has_form_request,
        }

    # ── FEATURE GROUP 6: FORMATTING FEATURES ──────────────────

    def _formatting_features(self, text: str, text_lower: str) -> Dict[str, float]:
        """
        Phishing emails often have distinctive formatting:
        - LOTS OF CAPITALS to create panic
        - Excessive punctuation (!!!, ???)
        - Generic greetings ("Dear Customer" not "Dear Alice")
        - Unusual text length
        """
        total_chars  = max(len(text), 1)
        letter_chars = max(sum(1 for c in text if c.isalpha()), 1)
        upper_chars  = sum(1 for c in text if c.isupper())

        # Ratio of uppercase to all letters.
        # Legitimate emails: ~5-10%. Phishing: often 30%+
        caps_ratio = upper_chars / letter_chars

        # Punctuation abuse
        exclamation_count = text.count("!")
        question_count    = text.count("?")

        # Generic salutation — phishers send bulk emails and
        # don't know your real name
        has_generic_greeting = float(
            bool(re.search(
                r'\b(dear (customer|user|account holder|member|sir|madam|valued)|'
                r'hello (user|customer|member)|to whom it may concern)\b',
                text_lower
            ))
        )

        # Very short or very long emails are sometimes suspicious
        word_count  = len(text.split())
        char_count  = len(text)

        # Entropy: measures randomness of text. Very high entropy
        # can indicate obfuscated/encoded content in the email.
        entropy = self._text_entropy(text[:500])  # first 500 chars

        return {
            "caps_ratio":            round(caps_ratio, 4),
            "exclamation_count":     float(exclamation_count),
            "question_count":        float(question_count),
            "has_generic_greeting":  has_generic_greeting,
            "word_count":            float(word_count),
            "char_count":            float(char_count),
            "text_entropy":          round(entropy, 4),
        }

    # ── FEATURE GROUP 7: HTML FEATURES ────────────────────────

    def _html_features(self, text: str, text_lower: str) -> Dict[str, float]:
        """
        HTML emails can hide content that's invisible to readers
        but visible to link-crawlers and spam filters:
        - display:none text that contains legitimate-looking words
        - Zero-width characters that break keyword filters
        - Excessive image usage to avoid text analysis
        - base64-encoded payloads
        """
        html_tag_count = len(RE_HTML_TAGS.findall(text))
        has_hidden     = float(bool(RE_HIDDEN.search(text)))
        has_base64     = float(bool(RE_BASE64.search(text)))

        # Count <img> tags — phishing emails often use images
        # instead of text to evade text-based filters
        img_count = len(re.findall(r'<img\b', text, re.IGNORECASE))

        # Count <form> tags — forms that POST data to attackers
        form_count = len(re.findall(r'<form\b', text, re.IGNORECASE))

        # Inline styles that make text invisible
        has_zero_fontsize = float(
            bool(re.search(r'font-size\s*:\s*0', text_lower))
        )

        return {
            "html_tag_count":     float(html_tag_count),
            "has_hidden_text":    has_hidden,
            "has_base64_content": has_base64,
            "img_tag_count":      float(img_count),
            "form_tag_count":     float(form_count),
            "has_zero_fontsize":  has_zero_fontsize,
        }

    # ── FEATURE GROUP 8: BRAND IMPERSONATION ──────────────────

    def _brand_features(self, text_lower: str) -> Dict[str, float]:
        """
        Counts how many well-known brand names appear in the email.
        An email mentioning 3+ brands is suspicious — legitimate
        emails are usually from ONE company.

        Also flags the presence of specific high-value brands
        that are most frequently impersonated.
        """
        brands_present = [b for b in IMPERSONATED_BRANDS if b in text_lower]
        brand_count    = len(brands_present)

        # Specifically flag PayPal and bank impersonation —
        # highest-value targets for credential theft
        has_financial_brand = float(
            any(b in text_lower for b in [
                "paypal", "bank", "chase", "wells fargo",
                "citibank", "american express", "visa", "mastercard"
            ])
        )

        return {
            "impersonated_brand_count": float(brand_count),
            "has_financial_brand":      has_financial_brand,
        }

    # ── FEATURE GROUP 9: ATTACHMENT FEATURES ──────────────────

    def _attachment_features(self, text_lower: str) -> Dict[str, float]:
        """
        Detects references to dangerous attachment types.
        Phishing emails often ask you to open an attachment
        that installs malware.
        """
        has_dangerous_attachment = float(
            any(ext in text_lower for ext in DANGEROUS_EXTENSIONS)
        )

        # Mentions of downloading or opening files
        has_download_request = float(
            bool(re.search(
                r'(download|open|run|execute|install|click to (open|view|download))',
                text_lower
            ))
        )

        return {
            "has_dangerous_attachment": has_dangerous_attachment,
            "has_download_request":     has_download_request,
        }

    # ── UTILITY ───────────────────────────────────────────────

    @staticmethod
    def _text_entropy(text: str) -> float:
        """
        Calculates Shannon entropy of text — a measure of randomness.

        CONCEPT: Shannon Entropy
          Entropy = -Σ p(c) * log2(p(c))  for each character c

          Low entropy  → repetitive text ("aaaaaaa") → entropy ≈ 0
          High entropy → random/encoded text         → entropy ≈ 8

        Normal English text: entropy ≈ 4.0 - 4.5
        Base64/obfuscated:   entropy ≈ 5.5 - 6.5

        We use this to detect encoded or obfuscated content
        that might be hiding a malicious payload or trying to
        evade keyword-based filters.
        """
        if not text:
            return 0.0

        # Count frequency of each character
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        n = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy