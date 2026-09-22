"""Tests for phish_triage.py.

Run from the project root with:  pytest -v
"""

import json
from pathlib import Path

import pytest

from phish_triage import (
    analyse_url,
    build_metadata,
    build_report,
    calculate_risk,
    check_attachments,
    defang_report,
    defang_text,
    extract_domain,
    find_lookalike_brand,
    get_base_domain,
    get_extensions,
    load_email,
    safe_filename,
    write_report,
)

# Build the samples path from this file's location, so tests work from any folder.
SAMPLES = Path(__file__).parent.parent / "samples"


# ---------- Fixtures: shared setup reused by several tests ----------

@pytest.fixture
def phishing_report():
    """The full analysis report for the fake phishing sample."""
    return build_report(load_email(SAMPLES / "phishing_email.eml"))


@pytest.fixture
def legit_report():
    """The full analysis report for the legitimate sample."""
    return build_report(load_email(SAMPLES / "legit_email.eml"))


# ---------- Unit tests: individual functions ----------

@pytest.mark.parametrize("header_value, expected", [
    ("Microsoft 365 Security <security@micros0ft-support.com>", "micros0ft-support.com"),
    ("<bounce-7781@mailer-d4x9.net>", "mailer-d4x9.net"),
    ("User@EXAMPLE.COM", "example.com"),
    ("<>", None),
    (None, None),
])
def test_extract_domain(header_value, expected):
    assert extract_domain(header_value) == expected


@pytest.mark.parametrize("domain, expected", [
    ("mail.example.com", "example.com"),
    ("example.com", "example.com"),
    ("mail.example.com.au", "example.com.au"),
    ("bounce.mail.example.co.uk", "example.co.uk"),
])
def test_get_base_domain(domain, expected):
    assert get_base_domain(domain) == expected


@pytest.mark.parametrize("host, expected", [
    ("micros0ft-support.com", "microsoft"),           # homoglyph: zero for o
    ("rnicrosoft.com", "microsoft"),                  # homoglyph: rn for m
    ("micorsoft.com", "microsoft"),                   # typo, caught by difflib
    ("microsoft.com.secure-login.net", "microsoft"),  # brand hidden in a subdomain
    ("login.microsoftonline.com", None),              # genuine Microsoft domain
    ("pineapple.com", None),                          # contains 'apple' but isn't a lookalike
])
def test_find_lookalike_brand(host, expected):
    assert find_lookalike_brand(host) == expected


@pytest.mark.parametrize("text, expected", [
    ("http://evil.com/login", "hxxp://evil[.]com/login"),
    ("https://sub.evil.com", "hxxps://sub[.]evil[.]com"),
    ("from 198.51.100.23", "from 198[.]51[.]100[.]23"),
])
def test_defang_text(text, expected):
    assert defang_text(text) == expected


def test_defang_is_idempotent():
    """Defanging already-defanged text must not change it again."""
    once = defang_text("http://a.example.com")
    assert defang_text(once) == once


def test_get_extensions():
    assert get_extensions("Invoice_4471.PDF.exe") == ["pdf", "exe"]
    assert get_extensions("invoice.pdf     .exe") == ["pdf", "exe"]  # space padding trick
    assert get_extensions("readme") == []


@pytest.mark.parametrize("severities, expected_level, expected_score", [
    ([], "Low", 0),
    (["low", "low"], "Low", 2),
    (["high"], "Medium", 5),               # any high finding means at least Medium
    (["medium", "medium"], "Medium", 6),
    (["high", "high"], "High", 10),
])
def test_calculate_risk(severities, expected_level, expected_score):
    findings = {"Test": [{"severity": s, "message": "x"} for s in severities]}
    risk = calculate_risk(findings)
    assert risk["level"] == expected_level
    assert risk["score"] == expected_score


def test_link_text_mismatch_is_flagged():
    record = {
        "url": "http://203.0.113.45/login.php",
        "source": "HTML",
        "link_text": "https://account.microsoft.com/verify",
    }
    findings = analyse_url(record)
    assert any(
        f["severity"] == "high" and "link text shows microsoft.com" in f["message"]
        for f in findings
    )


def test_at_sign_trick_is_flagged():
    record = {"url": "http://microsoft.com@evil.example/login", "source": "plain text", "link_text": None}
    findings = analyse_url(record)
    assert any("'@' trick" in f["message"] for f in findings)


def test_safe_filename_exposes_rtlo():
    name = "Invoice_\u202efdp.exe"
    assert safe_filename(name) == "Invoice_[RTLO]fdp.exe"
    findings = check_attachments([{"filename": name, "detected_type": "unknown"}])
    assert len(findings) == 2
    assert all(f["severity"] == "high" for f in findings)


# ---------- Integration tests: full analysis of the sample emails ----------

def test_phishing_sample_is_high_risk(phishing_report):
    # Regression test: if you change the scoring weights, update this number on purpose.
    assert phishing_report["risk"]["level"] == "High"
    assert phishing_report["risk"]["score"] == 43


def test_legit_sample_is_low_risk_with_no_findings(legit_report):
    assert legit_report["risk"]["level"] == "Low"
    assert legit_report["risk"]["score"] == 0
    assert all(len(findings) == 0 for findings in legit_report["findings"].values())


def test_phishing_auth_results(phishing_report):
    auth = phishing_report["auth"]
    assert auth["spf"] == "pass"
    assert auth["dkim"] == "none"
    assert auth["dmarc"] == "fail"
    assert auth["dmarc_policy"] == "none"


def test_phishing_originating_ip(phishing_report):
    assert phishing_report["originating_ip"] == "198.51.100.23"


def test_phishing_attachment_hash(phishing_report):
    attachment = phishing_report["attachments"][0]
    assert attachment["filename"] == "Invoice_4471.pdf.exe"
    assert attachment["sha256"] == (
        "947d4fcd2d3a08dc046876bc199a074ce7148f477028e02ec31a6be3a0c26162"
    )


def test_defang_report_does_not_change_original(phishing_report):
    safe = defang_report(phishing_report)
    assert safe["originating_ip"] == "198[.]51[.]100[.]23"
    assert phishing_report["originating_ip"] == "198.51.100.23"          # original untouched
    assert safe["attachments"][0]["filename"] == "Invoice_4471.pdf.exe"   # filenames not defanged


def test_json_report_is_written(phishing_report, tmp_path):
    output = tmp_path / "reports" / "report.json"  # the folder doesn't exist yet
    phishing_report["metadata"] = build_metadata(SAMPLES / "phishing_email.eml", defanged=False)

    write_report(phishing_report, output)

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["risk"]["level"] == "High"
    assert data["metadata"]["analysed_file"] == "phishing_email.eml"