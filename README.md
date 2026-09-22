# phish-triage

![tests](https://github.com/eatingmiko/phish-triage/actions/workflows/tests.yml/badge.svg)

A command-line tool that analyses a suspicious email (`.eml` file) and produces a phishing triage report: header analysis, SPF/DKIM/DMARC results, the delivery path, URL and attachment indicators, defanged IOCs and an explainable Low/Medium/High risk score.

Built with the Python standard library only. It never visits URLs, downloads anything or opens attachments.

## Why I built it

Phishing triage is one of the most common Tier 1 SOC tasks. A user reports a suspicious email, and an analyst has to decide quickly whether it's safe, spam or malicious. I work in IT support and am moving into security operations. I built this tool to understand that process properly: how email authentication works, how attackers get around it, and what an analyst actually looks for in the headers, links and attachments.

## Features

- **Key headers**: From, Reply-To, Return-Path, Subject, Date and Message-ID.
- **Header mismatch detection**: compares the From, Reply-To and Return-Path domains at the organisational-domain level (handles `.com.au` and similar).
- **Sender impersonation**: flags lookalike From domains and display-name spoofing.
- **Email authentication**: reports SPF, DKIM and DMARC results, plus the DMARC policy, from the topmost `Authentication-Results` header.
- **Received chain**: shows every hop in travel order, with the originating IP, and flags missing reverse DNS.
- **URL analysis** across plain-text and HTML bodies. It flags:
  - link text that shows a different domain from the real link
  - raw IP-address URLs
  - URL shorteners
  - lookalike domains (`micros0ft`, `rnicrosoft`, typos, brand names hidden in subdomains)
  - the `@` userinfo trick and punycode (`xn--`) domains
- **Attachment analysis** without opening anything. It reports each file's name, declared type, real type from magic bytes, size and SHA256. It flags risky extensions, double extensions (`.pdf.exe`), right-to-left override filenames and executables in disguise.
- **Defanged output** by default (`hxxp://example[.]com`), with `--no-defang` for live values.
- **An explainable risk score**: every finding has a severity and points, and the total maps to Low, Medium or High with each reason listed.
- **Report files**: optional JSON (for SIEM/SOAR platforms or scripts) or Markdown (for tickets) alongside the console output. Reports include run metadata and the SHA256 of the analysed `.eml`.
- **35 automated tests** with pytest, run on every push via GitHub Actions.

## Safety

The tool is designed to be safe to run on real phishing emails:

- URLs are extracted as text. They are never visited, resolved or previewed.
- HTML is parsed, never rendered, so scripts and remote images never load.
- Attachments are decoded and hashed in memory. They are never written to disk, opened or executed.
- IOCs are defanged by default, so reports can be shared without creating clickable links.

The samples in this repo are fake and use reserved documentation domains and IP ranges. **Never commit real phishing emails**: they contain real people's personal data and may contain live malware. The `.gitignore` excludes `samples/real/` for local testing.

## Installation

Requires Python 3.10 or newer. The tool itself has no dependencies: `requirements.txt` only contains pytest, for running the tests.

```bash
git clone https://github.com/eatingmiko/phish-triage.git
cd phish-triage
python -m venv .venv
# Windows:      .venv\Scripts\Activate.ps1
# Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python phish_triage.py samples/phishing_email.eml
python phish_triage.py samples/phishing_email.eml -o reports/phishing.json
python phish_triage.py samples/phishing_email.eml -o reports/phishing.md
python phish_triage.py samples/phishing_email.eml --no-defang
```

| Option | Description |
|---|---|
| `eml_file` | Path to the `.eml` file to analyse |
| `-o`, `--output` | Also write the report to a `.json` or `.md` file |
| `--no-defang` | Show URLs, domains and IPs in live form (use with care) |

Save the original message as a `.eml` file rather than forwarding it, because forwarding usually strips or rewrites the headers.

## Example output

Analysing the fake phishing sample (output trimmed):

```
=== Sender Findings ===
[HIGH] From domain (micros0ft-support[.]com) imitates 'microsoft'
[MEDIUM] Display name 'Microsoft 365 Security' mentions 'microsoft' but the sender domain is micros0ft-support[.]com

=== Authentication Results ===
Headers found : 1 (using the topmost)
SPF           : pass
DKIM          : none
DMARC         : fail

=== URL Findings ===
[MEDIUM] hxxp://203[.]0[.]113[.]45/login[.]php -> uses a raw IP address instead of a domain name
[HIGH] hxxp://203[.]0[.]113[.]45/login[.]php -> link text shows microsoft[.]com but the link goes to 203[.]0[.]113[.]45
[LOW] hxxps://bit[.]ly/3xFakeLnk -> URL shortener hides the real destination
[HIGH] hxxp://micros0ft-support[.]com/reset?user=jordan[.]smith -> domain imitates 'microsoft'

=== Attachments (1) ===
1. Invoice_4471.pdf.exe
   declared type : application/octet-stream
   detected type : unknown
   size          : 18 bytes
   SHA256        : 947d4fcd2d3a08dc046876bc199a074ce7148f477028e02ec31a6be3a0c26162

=== Risk Assessment ===
Risk level : HIGH (score 43)
Findings   : 6 high, 3 medium, 4 low
Reasons (highest impact first):
  +5  Sender Findings: From domain (micros0ft-support[.]com) imitates 'microsoft'
  +5  Authentication Findings: DMARC = fail (sender domain policy: p=none)
  ...
```

Note that SPF **passed**. The attacker sent from their own domain, which has a valid SPF record. Only DMARC checks alignment with the visible From address, and it failed.

A full Markdown report is in [`examples/phishing_report.md`](examples/phishing_report.md).

## How it maps to SOC phishing triage

| Analyst step | What the tool does |
|---|---|
| Get the original email with full headers | Reads the `.eml` directly and records its SHA256 for evidence integrity |
| Check whether the sender is who they claim to be | SPF/DKIM/DMARC results, header mismatches, lookalike and display-name checks |
| Trace where it came from | Received chain in travel order and the originating IP |
| Extract IOCs | URLs, domains, IPs and attachment hashes, defanged for safe sharing |
| Assess the indicators | Flags deceptive links, lookalike domains, and risky or disguised attachments |
| Decide and document | Explainable risk score with reasons, and a JSON or Markdown report for the ticket |

The analyst still owns the remaining steps:
- reputation lookups and sandboxing
- scoping (who else received the email) and purging it
- blocking senders, domains and URLs
- user follow-up, such as password resets

Relevant MITRE ATT&CK techniques:
- T1566 Phishing (T1566.001 Spearphishing Attachment, T1566.002 Spearphishing Link)
- T1036.007 Masquerading: Double File Extension
- T1036.002 Masquerading: Right-to-Left Override

## Scoring

| Severity | Points |
|---|---|
| Low | 1 |
| Medium | 3 |
| High | 5 |

A total of 10 or more is **High**. A total of 4 to 9, or any single high-severity finding, is **Medium**. Anything else is **Low**.

The weights are judgement calls, defined as constants in `phish_triage.py`. In a production SOC, they would be tuned against historical reported emails to balance false positives against missed phish.

## Limitations

This is a **triage aid, not a replacement for sandboxing, threat intelligence or analyst judgement**. Known limitations:

- **No reputation lookups.** A clean result doesn't mean a URL, IP or file is safe.
- **Header trust assumptions.** It trusts the topmost `Authentication-Results` header and the earliest Received hop, rather than verifying which headers your own mail servers added.
- **Approximate organisational domains.** These use a small built-in suffix list, not the full Public Suffix List.
- **Limited lookalike detection.** It uses a fixed brand list and ASCII homoglyphs only. Unicode lookalikes are only caught when they appear as punycode.
- **One result per authentication method.** Only the first is used, although emails can carry multiple DKIM signatures.
- **Missed address formats.** Decimal or hex-encoded IP URLs (`http://3405803777/`) and IPv6 addresses in Received headers are not detected.
- **No archive inspection.** Archive contents aren't inspected, and password-protected archives aren't identified.
- **Some content isn't analysed:** QR codes in images ("quishing"), `javascript:` and `data:` links, and HTML forms.
- **Findings can stack.** Related findings can inflate the score, e.g. a lookalike domain may appear in both the sender and URL sections.
- **`.eml` only.** Outlook `.msg` files aren't supported.

## Future improvements

- VirusTotal, URLScan and AbuseIPDB lookups (hash and URL lookups only, never uploading files)
- Automatic MITRE ATT&CK tagging of each finding
- Batch processing of a folder of `.eml` files, with a summary report
- Public Suffix List support via `tldextract`
- Configurable trusted mail servers for authentication and Received chain parsing
- Archive inspection, QR code decoding and `.msg` support

## Project structure

```
phish-triage/
├── .github/workflows/       # CI: runs the tests on every push
├── phish_triage.py          # the tool
├── samples/                 # fake, safe test emails
├── examples/                # example report generated from the fake sample
├── tests/                   # pytest suite
├── pyproject.toml           # pytest configuration
├── requirements.txt         # test dependency (pytest)
└── LICENSE
```

## Running the tests

```bash
pytest -v
```

## License

MIT. See [LICENSE](LICENSE).