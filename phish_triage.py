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


if __name__ == "__main__":
    main()