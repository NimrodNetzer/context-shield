"""
Heuristic engine — the primary security layer.

Produces typed Signal objects and a score_floor from deterministic rules.
No LLM involved. Every decision here is auditable and explainable.

score_floor: the minimum score the final verdict can carry regardless of what
the LLM returns. This prevents a prompt-injected LLM from downgrading a
verdict when hard signals are present.
"""

import ipaddress
import re
import unicodedata
from email.utils import parseaddr
from urllib.parse import urlparse

from models import HeuristicResult, Severity, Signal

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".msi", ".dll", ".scr", ".hta", ".pif",
    # Macro-capable Office formats
    ".xlsm", ".xlsb", ".docm", ".dotm", ".pptm", ".xltm",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".date", ".racing",
    ".stream", ".download", ".accountant", ".loan", ".gq",
    ".ml", ".cf", ".tk", ".ga",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
}

URGENCY_PATTERNS = re.compile(
    r"\b("
    r"verify your account|verify now|confirm your (account|identity|email)|"
    r"account (suspended|locked|disabled|will be (closed|terminated))|"
    r"act (now|immediately|urgently)|immediate(ly)? action|"
    r"click here (now|immediately|to avoid)|"
    r"your (password|account|access) (has been|will be)|"
    r"limited time|expires? (in|soon|today)|"
    r"update (your )?(payment|billing|credit card)|"
    r"unusual (activity|sign.?in|login)|"
    r"we noticed|suspicious (activity|login|access)"
    r")\b",
    re.IGNORECASE,
)

# Known brand names — display-name spoofing check
KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft", "netflix",
    "facebook", "instagram", "linkedin", "twitter", "dropbox",
    "bank of america", "chase", "wells fargo", "citibank",
    "dhl", "fedex", "ups", "irs", "hmrc",
]

# Confusable character map for homoglyph detection (extend as needed)
_CONFUSABLES: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "6": "b", "8": "b", "ν": "v", "а": "a", "е": "e",
    "о": "o", "р": "p", "с": "c", "х": "x", "ʼ": "'",
}

_CONFUSABLE_RE = re.compile("|".join(re.escape(k) for k in _CONFUSABLES))


def _normalize_homoglyphs(text: str) -> str:
    text = unicodedata.normalize("NFKC", text.lower())
    return _CONFUSABLE_RE.sub(lambda m: _CONFUSABLES[m.group()], text)


def _extract_domain(address: str) -> str | None:
    _, addr = parseaddr(address)
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip()
    return None


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s\"'<>]{4,200}", text)


def _is_private_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_auth_headers(headers, signals: list[Signal]) -> int:
    floor = 0
    if headers.dkim == "fail":
        signals.append(Signal(type="dkim_fail", severity=Severity.HIGH))
        floor = max(floor, 40)
    if headers.spf in ("fail", "softfail"):
        signals.append(Signal(type="spf_fail", severity=Severity.HIGH, value=headers.spf))
        floor = max(floor, 35)
    if headers.dmarc == "fail":
        signals.append(Signal(type="dmarc_fail", severity=Severity.HIGH))
        floor = max(floor, 35)
    # All three failing together is a strong spoofing indicator
    if headers.dkim == "fail" and headers.spf in ("fail", "softfail") and headers.dmarc == "fail":
        floor = max(floor, 75)
    return floor


def _check_reply_to_mismatch(sender: str, reply_to: str | None, signals: list[Signal]) -> int:
    if not reply_to:
        return 0
    sender_domain = _extract_domain(sender)
    reply_domain = _extract_domain(reply_to)
    if sender_domain and reply_domain and sender_domain != reply_domain:
        signals.append(Signal(
            type="reply_to_mismatch",
            severity=Severity.HIGH,
            value=f"{sender_domain} → {reply_domain}",
        ))
        return 40
    return 0


def _check_display_name_spoofing(sender: str, signals: list[Signal]) -> int:
    display_name, addr = parseaddr(sender)
    if not display_name or not addr:
        return 0
    domain = _extract_domain(sender) or ""
    name_normalized = _normalize_homoglyphs(display_name)
    domain_normalized = _normalize_homoglyphs(domain)
    domain_parts = domain_normalized.split(".")
    registered_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain_normalized
    for brand in KNOWN_BRANDS:
        brand_norm = _normalize_homoglyphs(brand.replace(" ", ""))
        if brand_norm in name_normalized and brand_norm not in registered_domain:
            signals.append(Signal(
                type="display_name_spoofing",
                severity=Severity.CRITICAL,
                value=f'"{display_name}" from {domain}',
            ))
            return 70
    return 0


def _check_homoglyph_domain(sender: str, signals: list[Signal]) -> int:
    domain = _extract_domain(sender) or ""
    domain_norm = _normalize_homoglyphs(domain)
    parts = domain_norm.split(".")
    # Registered domain = last two parts (e.g. "google.com")
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else domain_norm
    for brand in KNOWN_BRANDS:
        brand_norm = _normalize_homoglyphs(brand.replace(" ", ""))
        if brand_norm not in domain_norm:
            continue
        # Skip if brand legitimately owns the registered domain
        if brand_norm in registered:
            continue
        signals.append(Signal(
            type="homoglyph_domain",
            severity=Severity.CRITICAL,
            value=domain,
        ))
        return 75
    return 0


def _check_attachments(attachment_names: list[str], signals: list[Signal]) -> int:
    floor = 0
    for name in attachment_names:
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in DANGEROUS_EXTENSIONS:
            signals.append(Signal(
                type="dangerous_attachment",
                severity=Severity.CRITICAL,
                value=name,
            ))
            floor = max(floor, 65)
    return floor


def _check_urls(body: str, signals: list[Signal]) -> int:
    floor = 0
    urls = _extract_urls(body)
    for url in urls[:20]:  # cap to avoid regex DoS on body with many links
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        except Exception:
            continue

        if _is_private_ip(host):
            signals.append(Signal(type="ssrf_risk_url", severity=Severity.CRITICAL, value=url[:80]))
            floor = max(floor, 80)
            continue

        tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            signals.append(Signal(type="suspicious_tld", severity=Severity.HIGH, value=host))
            floor = max(floor, 45)

        if host in URL_SHORTENERS:
            signals.append(Signal(type="url_shortener", severity=Severity.MEDIUM, value=host))
            floor = max(floor, 25)

        # IP address as hostname (bypasses domain-based filters)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            signals.append(Signal(type="ip_as_hostname", severity=Severity.HIGH, value=host))
            floor = max(floor, 55)

    return floor


def _check_urgency(body: str, signals: list[Signal]) -> int:
    matches = URGENCY_PATTERNS.findall(body)
    if len(matches) >= 2:
        signals.append(Signal(type="urgency_language", severity=Severity.MEDIUM, value=f"{len(matches)} patterns"))
        return 20
    if matches:
        signals.append(Signal(type="urgency_language", severity=Severity.LOW, value=matches[0]))
        return 10
    return 0


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_heuristics(
    sender: str,
    reply_to: str | None,
    subject: str,
    body: str,
    headers,
    attachment_names: list[str],
) -> HeuristicResult:
    signals: list[Signal] = []
    floor = 0

    floor = max(floor, _check_auth_headers(headers, signals))
    floor = max(floor, _check_reply_to_mismatch(sender, reply_to, signals))
    floor = max(floor, _check_display_name_spoofing(sender, signals))
    floor = max(floor, _check_homoglyph_domain(sender, signals))
    floor = max(floor, _check_attachments(attachment_names, signals))
    floor = max(floor, _check_urls(body, signals))
    floor = max(floor, _check_urgency(body, signals))

    return HeuristicResult(signals=signals, score_floor=floor)
