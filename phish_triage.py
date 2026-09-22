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


def main():
    parser = argparse.ArgumentParser(
        description="Analyse a .eml file and produce a phishing triage report."
    )
    parser.add_argument("eml_file", help="Path to the .eml file to analyse")
    args = parser.parse_args()

    try:
        msg = load_email(args.eml_file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.eml_file}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied: {args.eml_file}", file=sys.stderr)
        sys.exit(1)

    headers = get_key_headers(msg)
    print_headers(headers)
    print_findings("Header Mismatches", check_mismatches(headers))

    auth = parse_auth_results(msg)
    print_auth_results(auth)
    print_findings("Authentication Findings", check_auth_results(auth))

    hops = parse_received_chain(msg)
    print_received_chain(hops)
    print_findings("Received Chain Findings", check_received_chain(hops))

    plain_text, html = get_bodies(msg)
    urls = extract_urls(plain_text, html)
    print_urls(urls)


if __name__ == "__main__":
    main()