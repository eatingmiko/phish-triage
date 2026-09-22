"""
phish_triage.py - A command-line phishing triage tool for .eml files.

Parses an email and reports on headers, authentication results, URLs and
attachments to support Tier 1 SOC phishing triage.

Safety: this tool never visits URLs, downloads anything, or opens attachments.
"""

import argparse
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
from html.parser import HTMLParser
import difflib
import ipaddress
from urllib.parse import urlparse
import hashlib

AUTH_METHODS = ("spf", "dkim", "dmarc")

# Matches "spf=pass", "dkim = fail" etc. Group 1 = method, group 2 = result.
AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)

# Matches the DMARC policy in brackets, e.g. "(p=none)". Group 1 = policy.
DMARC_POLICY_PATTERN = re.compile(r"\(p=([a-z]+)", re.IGNORECASE)

# (method, result) -> severity. Results not listed here (e.g. pass) are not findings.
AUTH_FAILURE_SEVERITY = {
    ("spf", "fail"): "medium",
    ("spf", "softfail"): "low",
    ("spf", "none"): "low",
    ("dkim", "fail"): "medium",
    ("dkim", "none"): "low",
    ("dmarc", "fail"): "high",
    ("dmarc", "none"): "low",
}

# Parts of a Received header. Group 1 of each pattern is the value we want.
RECEIVED_FROM_PATTERN = re.compile(r"\bfrom\s+([\w.-]+)", re.IGNORECASE)
RECEIVED_BY_PATTERN = re.compile(r"\bby\s+([\w.-]+)", re.IGNORECASE)
RECEIVED_WITH_PATTERN = re.compile(r"\bwith\s+(\w+)", re.IGNORECASE)

# An IPv4 address inside square brackets, e.g. [198.51.100.23].
IPV4_IN_BRACKETS_PATTERN = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")

# "(unknown [" means the receiving server found no reverse DNS for the sender's IP.
UNKNOWN_RDNS_PATTERN = re.compile(r"\(unknown\s*\[", re.IGNORECASE)

# http:// or https:// followed by everything up to whitespace, a quote or an angle bracket.
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

# Punctuation often stuck to the end of a URL in prose, e.g. "visit https://x.com."
URL_TRAILING_PUNCTUATION = ".,;:!?)]}"

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# Commonly impersonated brands -> the real domains they use.
BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"},
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com"},
    "amazon": {"amazon.com", "amazon.com.au"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "commbank": {"commbank.com.au"},
    "westpac": {"westpac.com.au"},
    "auspost": {"auspost.com.au"},
    "mygov": {"my.gov.au"},
}

# Characters attackers swap in to imitate letters.
HOMOGLYPH_TABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"})
MULTI_CHAR_HOMOGLYPHS = {"rn": "m", "vv": "w"}

LOOKALIKE_SIMILARITY = 0.85  # difflib ratio at or above this counts as a lookalike
MIN_BRAND_LENGTH_FOR_FUZZY = 5  # short brand names cause too many fuzzy false positives

# A domain name appearing in link text, e.g. "account.microsoft.com".
DOMAIN_IN_TEXT_PATTERN = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)

# File types that can run code directly when opened.
HIGH_RISK_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "dll", "cpl",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "lnk", "jar", "reg",
    "iso", "img", "vhd", "vhdx", "xll",
}

# Common malware carriers: macro documents, archives, HTML smuggling, OneNote.
MEDIUM_RISK_EXTENSIONS = {
    "docm", "xlsm", "pptm", "dotm", "xlsb",
    "zip", "rar", "7z", "gz", "tar", "cab",
    "html", "htm", "svg", "one",
}

# Harmless-looking extensions attackers place before the real one, e.g. invoice.pdf.exe
DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}

# Extensions where Windows executable content is expected.
EXECUTABLE_EXTENSIONS = {"exe", "dll", "scr", "com", "cpl", "sys"}

# File signatures ("magic bytes"): the first bytes reveal the real file type.
FILE_SIGNATURES = {
    b"MZ": "Windows executable",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP archive (also docx/xlsx/pptx)",
    b"\xd0\xcf\x11\xe0": "Legacy Office document (doc/xls/ppt)",
    b"Rar!": "RAR archive",
    b"7z\xbc\xaf": "7-Zip archive",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
}

# Unicode right-to-left override: reverses how the following text is displayed.
RTLO_CHARACTER = "\u202e"

# http:// or https:// (group 1 keeps the optional "s") for defanging.
DEFANG_SCHEME_PATTERN = re.compile(r"\bhttp(s?)://", re.IGNORECASE)

# IPv4 addresses or domain names, whose dots get defanged.
DEFANG_HOST_PATTERN = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)

# The headers shown in the triage report, in display order.
KEY_HEADERS = ["From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID"]

# Suffixes where the organisation's domain has three labels (e.g. example.com.au).
# A simplified stand-in for the Public Suffix List.
MULTI_PART_SUFFIXES = {
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.nz", "org.nz", "govt.nz",
}


def load_email(path):
    """Read a .eml file and return it as an EmailMessage object."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_key_headers(msg):
    """Return a dict of the key headers. Missing headers are stored as None."""
    headers = {}
    for name in KEY_HEADERS:
        value = msg.get(name)
        headers[name] = str(value) if value is not None else None
    return headers


def print_headers(headers):
    """Print the key headers as an aligned table."""
    print("=== Key Headers ===")
    for name, value in headers.items():
        print(f"{name:<12} : {value if value else '(missing)'}")

def extract_domain(header_value):
    """Return the lowercase domain from an address header, or None if there isn't one."""
    if not header_value:
        return None
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().strip(".")


def get_base_domain(domain):
    """Reduce a domain to its organisational domain, e.g. mail.example.com -> example.com."""
    if not domain:
        return None
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def check_mismatches(headers):
    """Compare the From domain with Reply-To and Return-Path. Return a list of findings."""
    findings = []
    from_domain = get_base_domain(extract_domain(headers.get("From")))

    if from_domain is None:
        findings.append({
            "severity": "medium",
            "message": "From header is missing or contains no valid address",
        })
        return findings

    # Reply-To mismatches are a stronger indicator than Return-Path mismatches,
    # because bulk mail services legitimately use their own bounce domains.
    checks = {"Reply-To": "medium", "Return-Path": "low"}

    for name, severity in checks.items():
        other_domain = get_base_domain(extract_domain(headers.get(name)))
        if other_domain and other_domain != from_domain:
            findings.append({
                "severity": severity,
                "message": f"{name} domain ({other_domain}) does not match "
                           f"From domain ({from_domain})",
            })
    return findings


def print_findings(title, findings):
    """Print a section heading and each finding with its severity."""
    print(f"\n=== {title} ===")
    if not findings:
        print("No issues found")
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['message']}")

def parse_auth_results(msg):
    """Extract SPF, DKIM and DMARC results from the topmost Authentication-Results header.

    Returns a dict with a result (or None) for each method, the DMARC policy,
    and how many Authentication-Results headers were found.
    """
    all_headers = msg.get_all("Authentication-Results") or []
    results = {method: None for method in AUTH_METHODS}
    results["dmarc_policy"] = None
    results["header_count"] = len(all_headers)

    if not all_headers:
        return results

    # Only trust the topmost header: it was added by our own receiving server.
    top_header = str(all_headers[0])

    for method, result in AUTH_RESULT_PATTERN.findall(top_header):
        method = method.lower()
        if results[method] is None:  # keep the first result for each method
            results[method] = result.lower()

    policy_match = DMARC_POLICY_PATTERN.search(top_header)
    if policy_match:
        results["dmarc_policy"] = policy_match.group(1).lower()

    return results


def check_auth_results(results):
    """Turn authentication results into a list of findings."""
    findings = []

    if results["header_count"] == 0:
        findings.append({
            "severity": "low",
            "message": "No Authentication-Results header; sender authentication could not be verified",
        })
        return findings

    for method in AUTH_METHODS:
        result = results[method]
        if result is None:
            findings.append({
                "severity": "low",
                "message": f"{method.upper()} result not present in Authentication-Results",
            })
            continue

        severity = AUTH_FAILURE_SEVERITY.get((method, result))
        if severity:
            message = f"{method.upper()} = {result}"
            if method == "dmarc" and results["dmarc_policy"]:
                message += f" (sender domain policy: p={results['dmarc_policy']})"
            findings.append({"severity": severity, "message": message})

    return findings


def print_auth_results(results):
    """Print the raw SPF, DKIM and DMARC results."""
    print("\n=== Authentication Results ===")
    print(f"{'Headers found':<13} : {results['header_count']} (using the topmost)")
    for method in AUTH_METHODS:
        print(f"{method.upper():<13} : {results[method] or '(not present)'}")

def _first_group(pattern, text):
    """Return group 1 of the first match of pattern in text, or None."""
    match = pattern.search(text)
    return match.group(1) if match else None


def parse_received_chain(msg):
    """Parse Received headers into a list of hops, in the order the email travelled."""
    raw_headers = msg.get_all("Received") or []
    hops = []

    # Headers are stacked newest-first, so reverse them to get origin-first.
    for number, raw in enumerate(reversed(raw_headers), start=1):
        text = " ".join(str(raw).split())  # collapse line breaks and tabs
        timestamp = text.rsplit(";", 1)[1].strip() if ";" in text else None

        hops.append({
            "hop": number,
            "from_host": _first_group(RECEIVED_FROM_PATTERN, text),
            "ip": _first_group(IPV4_IN_BRACKETS_PATTERN, text),
            "by_host": _first_group(RECEIVED_BY_PATTERN, text),
            "protocol": _first_group(RECEIVED_WITH_PATTERN, text),
            "timestamp": timestamp,
            "unknown_rdns": bool(UNKNOWN_RDNS_PATTERN.search(text)),
        })
    return hops


def get_originating_ip(hops):
    """Return the IP of the earliest hop that recorded one, or None."""
    for hop in hops:
        if hop["ip"]:
            return hop["ip"]
    return None


def check_received_chain(hops):
    """Turn the Received chain into a list of findings."""
    findings = []

    if not hops:
        findings.append({
            "severity": "low",
            "message": "No Received headers found; delivery path cannot be traced",
        })
        return findings

    for hop in hops:
        if hop["unknown_rdns"]:
            findings.append({
                "severity": "low",
                "message": f"Hop {hop['hop']}: sending server {hop['ip'] or '(no IP)'} "
                           f"has no reverse DNS (shown as 'unknown')",
            })
    return findings


def print_received_chain(hops):
    """Print each hop in travel order, then the originating IP."""
    print("\n=== Received Chain (origin first) ===")
    if not hops:
        print("(no Received headers)")
        return

    for hop in hops:
        print(f"Hop {hop['hop']}: {hop['from_host'] or '?'} [{hop['ip'] or 'no IP'}] -> "
              f"{hop['by_host'] or '?'} via {hop['protocol'] or '?'}")
        print(f"       {hop['timestamp'] or '(no timestamp)'}")
    print(f"Originating IP : {get_originating_ip(hops) or '(not found)'}")

class LinkExtractor(HTMLParser):
    """Collect every <a href="..."> link and its visible text from an HTML document.

    HTMLParser reads the HTML and calls the handle_* methods below as it meets
    each start tag, piece of text and end tag. Nothing is rendered or executed.
    """

    def __init__(self):
        super().__init__()
        self.links = []            # list of (href, visible_text) tuples
        self._current_href = None  # set while we are inside an <a> tag
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._current_href = href.strip()
                self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            text = " ".join("".join(self._current_text).split())
            self.links.append((self._current_href, text))
            self._current_href = None


def get_bodies(msg):
    """Return (plain_text, html) from the email body, skipping attachments."""
    plain_parts = []
    html_parts = []

    for part in msg.walk():
        if part.is_multipart():
            continue  # containers hold other parts, not content
        if part.get_content_disposition() == "attachment":
            continue  # never treat attachments as body text

        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError):
            # Unknown or broken charset: decode the raw bytes as best we can.
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")

        if content_type == "text/plain":
            plain_parts.append(content)
        else:
            html_parts.append(content)

    return "\n".join(plain_parts), "\n".join(html_parts)


def extract_urls(plain_text, html):
    """Return a de-duplicated list of URL records from the plain-text and HTML bodies.

    Each record is a dict: {"url": ..., "source": ..., "link_text": ...}.
    """
    urls = []
    seen = set()

    # HTML first, so links keep their visible text if the same URL
    # also appears in the plain-text version.
    if html:
        extractor = LinkExtractor()
        extractor.feed(html)
        for href, text in extractor.links:
            if not href.lower().startswith(("http://", "https://")):
                continue  # skip mailto:, tel:, #anchors etc.
            if href not in seen:
                seen.add(href)
                urls.append({"url": href, "source": "HTML", "link_text": text})

    for match in URL_PATTERN.findall(plain_text):
        url = match.rstrip(URL_TRAILING_PUNCTUATION)
        if url not in seen:
            seen.add(url)
            urls.append({"url": url, "source": "plain text", "link_text": None})

    return urls


def print_urls(urls):
    """Print each extracted URL with where it came from and any link text."""
    print(f"\n=== URLs Found ({len(urls)}) ===")
    if not urls:
        print("(none)")
        return

    for number, record in enumerate(urls, start=1):
        print(f"{number}. {record['url']}")
        line = f"   source: {record['source']}"
        if record["link_text"]:
            text = record["link_text"]
            line += f' | link text: "{text}"'
        print(line)

def is_ip_address(host):
    """Return True if host is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalise_homoglyphs(text):
    """Replace common lookalike characters with the letters they imitate."""
    text = text.lower().translate(HOMOGLYPH_TABLE)
    for fake, real in MULTI_CHAR_HOMOGLYPHS.items():
        text = text.replace(fake, real)
    return text


def find_lookalike_brand(host):
    """Return the brand a hostname appears to imitate, or None."""
    base = get_base_domain(host)
    if base is None:
        return None

    # A genuine brand domain is not a lookalike.
    if any(base in legit_domains for legit_domains in BRAND_DOMAINS.values()):
        return None

    tokens = re.split(r"[.-]", normalise_homoglyphs(host))
    for brand in BRAND_DOMAINS:
        for token in tokens:
            if token == brand:
                return brand
            if len(brand) >= MIN_BRAND_LENGTH_FOR_FUZZY:
                similarity = difflib.SequenceMatcher(None, token, brand).ratio()
                if similarity >= LOOKALIKE_SIMILARITY:
                    return brand
    return None


def analyse_url(record):
    """Check one URL record for phishing indicators. Return a list of findings."""
    url = record["url"]
    findings = []

    def add(severity, reason):
        findings.append({"severity": severity, "message": f"{url} -> {reason}"})

    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        host = None

    if not host:
        add("low", "hostname could not be parsed")
        return findings

    if parsed.username:
        add("high", f"contains an '@' trick; the browser would actually go to {host}")

    host_is_ip = is_ip_address(host)
    if host_is_ip:
        add("medium", "uses a raw IP address instead of a domain name")

    if "xn--" in host:
        add("medium", "punycode (internationalised) domain; possible homograph attack")

    base = host if host_is_ip else get_base_domain(host)
    if base in URL_SHORTENERS:
        add("low", "URL shortener hides the real destination")

    link_text = record["link_text"]
    if link_text:
        text_match = DOMAIN_IN_TEXT_PATTERN.search(link_text)
        if text_match:
            shown = get_base_domain(text_match.group(1).lower())
            if shown != base:
                add("high", f"link text shows {shown} but the link goes to {base}")

    if not host_is_ip:
        brand = find_lookalike_brand(host)
        if brand:
            add("high", f"domain imitates '{brand}'")

    return findings


def check_urls(urls):
    """Analyse every URL and return all findings as one list."""
    findings = []
    for record in urls:
        findings.extend(analyse_url(record))
    return findings

def safe_filename(name):
    """Make a filename safe to print by exposing hidden direction-changing characters."""
    return name.replace(RTLO_CHARACTER, "[RTLO]")


def get_extensions(filename):
    """Return every extension in a filename, lowercased: 'a.PDF.exe' -> ['pdf', 'exe']."""
    parts = filename.lower().split(".")
    return [part.strip() for part in parts[1:]]


def identify_signature(data):
    """Identify a file's real type from its first bytes. Returns a description."""
    for signature, description in FILE_SIGNATURES.items():
        if data.startswith(signature):
            return description
    return "unknown"


def extract_attachments(msg):
    """Return a list of attachment records.

    Attachment content is decoded and hashed in memory only. It is never
    written to disk, opened or executed.
    """
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue  # ordinary body text, not an attachment

        data = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": filename or "(no filename)",
            "declared_type": part.get_content_type(),
            "detected_type": identify_signature(data),
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return attachments


def check_attachments(attachments):
    """Check each attachment for risky types and disguise tricks. Return findings."""
    findings = []

    for attachment in attachments:
        name = attachment["filename"]
        extensions = get_extensions(name)
        final_ext = extensions[-1] if extensions else ""
        reasons = []

        if RTLO_CHARACTER in name:
            reasons.append(("high", "filename contains a right-to-left override "
                                    "character that disguises the real extension"))

        if final_ext in HIGH_RISK_EXTENSIONS:
            reasons.append(("high", f"high-risk file type (.{final_ext}) that can run code"))
        elif final_ext in MEDIUM_RISK_EXTENSIONS:
            reasons.append(("medium", f"risky file type (.{final_ext}); a common malware carrier"))

        if (len(extensions) >= 2
                and extensions[-2] in DECOY_EXTENSIONS
                and final_ext in HIGH_RISK_EXTENSIONS | MEDIUM_RISK_EXTENSIONS):
            reasons.append(("high", f"double extension disguises a .{final_ext} "
                                    f"as a .{extensions[-2]}"))

        if (attachment["detected_type"] == "Windows executable"
                and final_ext not in EXECUTABLE_EXTENSIONS):
            reasons.append(("high", "content is a Windows executable despite its filename"))

        for severity, reason in reasons:
            findings.append({
                "severity": severity,
                "message": f"{safe_filename(name)} -> {reason}",
            })

    return findings


def print_attachments(attachments):
    """Print each attachment's details and hash."""
    print(f"\n=== Attachments ({len(attachments)}) ===")
    if not attachments:
        print("(none)")
        return

    for number, attachment in enumerate(attachments, start=1):
        print(f"{number}. {safe_filename(attachment['filename'])}")
        print(f"   declared type : {attachment['declared_type']}")
        print(f"   detected type : {attachment['detected_type']}")
        print(f"   size          : {attachment['size_bytes']} bytes")
        print(f"   SHA256        : {attachment['sha256']}")

def defang_text(text):
    """Defang URLs, domains and IPs in a string: http://a.com -> hxxp://a[.]com."""
    text = DEFANG_SCHEME_PATTERN.sub(r"hxxp\1://", text)
    return DEFANG_HOST_PATTERN.sub(lambda match: match.group(0).replace(".", "[.]"), text)


def defang_value(value):
    """Recursively defang every string inside dicts and lists."""
    if isinstance(value, str):
        return defang_text(value)
    if isinstance(value, dict):
        return {key: defang_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [defang_value(item) for item in value]
    return value  # numbers, booleans and None are left unchanged


def defang_report(report):
    """Return a defanged copy of the report for display. The original is not changed.

    Attachment filenames are kept as-is: they are not clickable or resolvable,
    and defanging them would only make them harder to read.
    """
    safe = defang_value(report)
    safe["attachments"] = report["attachments"]
    safe["findings"]["Attachment Findings"] = report["findings"]["Attachment Findings"]
    return safe

def build_report(msg):
    """Run every analysis step and collect the results into one dictionary."""
    headers = get_key_headers(msg)
    auth = parse_auth_results(msg)
    hops = parse_received_chain(msg)
    plain_text, html = get_bodies(msg)
    urls = extract_urls(plain_text, html)
    attachments = extract_attachments(msg)

    return {
        "headers": headers,
        "auth": auth,
        "received_chain": hops,
        "originating_ip": get_originating_ip(hops),
        "urls": urls,
        "attachments": attachments,
        "findings": {
            "Header Mismatches": check_mismatches(headers),
            "Authentication Findings": check_auth_results(auth),
            "Received Chain Findings": check_received_chain(hops),
            "URL Findings": check_urls(urls),
            "Attachment Findings": check_attachments(attachments),
        },
    }


def print_report(report):
    """Print every section of the report to the console."""
    findings = report["findings"]

    print_headers(report["headers"])
    print_findings("Header Mismatches", findings["Header Mismatches"])

    print_auth_results(report["auth"])
    print_findings("Authentication Findings", findings["Authentication Findings"])

    print_received_chain(report["received_chain"])
    print_findings("Received Chain Findings", findings["Received Chain Findings"])

    print_urls(report["urls"])
    print_findings("URL Findings", findings["URL Findings"])

    print_attachments(report["attachments"])
    print_findings("Attachment Findings", findings["Attachment Findings"])

def main():
    parser = argparse.ArgumentParser(
        description="Analyse a .eml file and produce a phishing triage report."
    )
    parser.add_argument("eml_file", help="Path to the .eml file to analyse")
    parser.add_argument(
        "--no-defang",
        action="store_true",
        help="Show URLs, domains and IPs in live (clickable) form. Use with care.",
    )
    args = parser.parse_args()

    try:
        msg = load_email(args.eml_file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.eml_file}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied: {args.eml_file}", file=sys.stderr)
        sys.exit(1)

    report = build_report(msg)
    display_report = report if args.no_defang else defang_report(report)
    print_report(display_report)


if __name__ == "__main__":
    main()