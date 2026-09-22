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

# The headers shown in the triage report, in display order.
KEY_HEADERS = ["From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID"]


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


if __name__ == "__main__":
    main()