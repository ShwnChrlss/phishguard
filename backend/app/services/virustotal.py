# =============================================================
#  backend/app/services/virustotal.py
#  URL reputation checking via VirusTotal API v3
#
#  CONCEPT: Threat Intelligence Enrichment
#  Our ML model analyses email TEXT patterns.
#  VirusTotal analyses actual URLs against 70+ security vendors.
#  Combining both gives a much stronger signal:
#    ML alone:       "this email looks phishy"
#    VT enriched:    "this email links to a URL flagged by
#                     5 security vendors as malicious"
#
#  CONCEPT: Graceful Degradation
#  If VirusTotal is down or rate-limited, the scan still
#  works — it just returns without VT enrichment.
#  Never let an external API break your core feature.
#
#  CONCEPT: BASE64URL encoding
#  VirusTotal API v3 requires URLs to be base64url encoded
#  (url-safe base64, no padding) before embedding in the path.
#  Raw URLs contain / ? & = which would break the URL path.
# =============================================================

import base64
import hashlib
import logging
import time
import requests
from flask import current_app

logger = logging.getLogger(__name__)

# ── IN-MEMORY CACHE ───────────────────────────────────────────
# Key:   SHA256(url)          → consistent fixed-length key
# Value: { result, timestamp } → cached VT response
#
# CONCEPT: Why SHA256 as cache key not the raw URL?
# URLs can be very long (2000+ chars).
# SHA256 gives a fixed 64-char key regardless of URL length.
# Also prevents any weird characters in dict keys.
#
# Production upgrade: replace with Redis + TTL
_cache: dict = {}
CACHE_TTL_SECONDS = 86400  # 24 hours


def _get_api_key() -> str:
    return current_app.config.get('VIRUSTOTAL_API_KEY', '') or \
           __import__('os').environ.get('VIRUSTOTAL_API_KEY', '')


def _encode_url(url: str) -> str:
    """
    BASE64URL encode a URL for the VirusTotal API path.

    Standard base64 uses + / = which break URLs.
    base64url substitutes:  + → -   / → _   strips =

    Example:
      "https://evil.tk/phish" →  "aHR0cHM6Ly9ldmlsLnRrL3BoaXNo"
    """
    return base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()


def _cache_key(url: str) -> str:
    """SHA256 hash of URL — used as cache key."""
    return hashlib.sha256(url.encode()).hexdigest()


def _is_cached(key: str) -> bool:
    """Check if a cache entry exists and hasn't expired."""
    if key not in _cache:
        return False
    age = time.time() - _cache[key]['timestamp']
    return age < CACHE_TTL_SECONDS


def check_url(url: str) -> dict:
    """
    Check a single URL against VirusTotal.

    Returns a dict with:
      url          : the checked URL
      malicious    : int  — number of engines flagging as malicious
      suspicious   : int  — number flagging as suspicious
      harmless     : int  — number flagging as harmless
      undetected   : int  — number with no opinion
      total        : int  — total engines that scanned
      reputation   : str  — "clean" | "suspicious" | "malicious"
      from_cache   : bool — True if result came from cache
      error        : str  — set if something went wrong

    CONCEPT: Return dict not exception
    Callers check result['error'] — they don't need try/catch.
    This is called the "result object pattern".
    """
    api_key = _get_api_key()
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY not set — skipping URL check")
        return {'url': url, 'error': 'API key not configured', 'reputation': 'unknown'}

    key = _cache_key(url)

    # Cache hit — return stored result without API call
    if _is_cached(key):
        logger.debug("VT cache hit for URL: %s", url[:50])
        result = dict(_cache[key]['result'])
        result['from_cache'] = True
        return result

    # Cache miss — call VirusTotal
    encoded = _encode_url(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"

    try:
        resp = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=10,  # never wait more than 10 seconds
        )

        if resp.status_code == 404:
            # URL not in VT database — not necessarily safe, just unknown
            result = {
                'url':        url,
                'malicious':  0,
                'suspicious': 0,
                'harmless':   0,
                'undetected': 0,
                'total':      0,
                'reputation': 'unknown',
                'from_cache': False,
                'error':      None,
            }
            _cache[key] = {'result': result, 'timestamp': time.time()}
            return result

        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit")
            return {'url': url, 'error': 'Rate limited', 'reputation': 'unknown'}

        resp.raise_for_status()
        data  = resp.json()
        stats = data['data']['attributes']['last_analysis_stats']

        malicious  = stats.get('malicious',  0)
        suspicious = stats.get('suspicious', 0)
        harmless   = stats.get('harmless',   0)
        undetected = stats.get('undetected', 0)
        total      = malicious + suspicious + harmless + undetected

        # Determine reputation bucket
        if malicious >= 3:
            reputation = 'malicious'
        elif malicious >= 1 or suspicious >= 3:
            reputation = 'suspicious'
        else:
            reputation = 'clean'

        result = {
            'url':        url,
            'malicious':  malicious,
            'suspicious': suspicious,
            'harmless':   harmless,
            'undetected': undetected,
            'total':      total,
            'reputation': reputation,
            'from_cache': False,
            'error':      None,
        }

        # Store in cache
        _cache[key] = {'result': result, 'timestamp': time.time()}
        logger.info("VT check: %s → %s (%d malicious)", url[:50], reputation, malicious)
        return result

    except requests.Timeout:
        logger.error("VirusTotal timeout for URL: %s", url[:50])
        return {'url': url, 'error': 'Timeout', 'reputation': 'unknown'}

    except Exception as e:
        logger.error("VirusTotal error for %s: %s", url[:50], e)
        return {'url': url, 'error': str(e), 'reputation': 'unknown'}


def check_urls(urls: list) -> list:
    """
    Check multiple URLs, respecting the free tier rate limit.

    Free tier: 4 requests per minute = 1 request per 15 seconds.
    We add a small delay between requests to avoid 429 errors.

    CONCEPT: Rate limit compliance
    Hitting the rate limit wastes time on retries.
    Proactively spacing requests is more efficient.

    Args:
        urls: list of URL strings (max 5 checked per scan)

    Returns:
        list of result dicts from check_url()
    """
    results = []
    # Cap at 5 URLs per scan — free tier protection
    for i, url in enumerate(urls[:5]):
        result = check_url(url)
        results.append(result)

        # Delay between requests only if not from cache
        # and not the last URL
        if not result.get('from_cache') and i < len(urls[:5]) - 1:
            time.sleep(15)  # 4 requests/minute = 1 per 15s

    return results


def enrich_risk_score(base_score: float, vt_results: list) -> float:
    """
    Boost the ML risk score based on VirusTotal findings.

    CONCEPT: Score enrichment
    ML gives us a base probability (0.0 → 1.0).
    VT gives us hard evidence from security vendors.
    We combine them:
      - Malicious URL found  → significant boost
      - Suspicious URL found → moderate boost
      - All clean            → no change

    We cap at 0.97 — never 100% certain from automation alone.

    Args:
        base_score:  ML risk score (0.0 → 1.0)
        vt_results:  list of check_url() results

    Returns:
        enriched score (0.0 → 0.97)
    """
    boost = 0.0

    for r in vt_results:
        if r.get('error'):
            continue
        rep = r.get('reputation', 'unknown')
        mal = r.get('malicious', 0)

        if rep == 'malicious':
            boost = max(boost, 0.30 + min(mal * 0.02, 0.15))
        elif rep == 'suspicious':
            boost = max(boost, 0.15)

    enriched = min(base_score + boost, 0.97)
    if boost > 0:
        logger.info("VT enrichment: %.2f → %.2f (boost +%.2f)", base_score, enriched, boost)
    return enriched
