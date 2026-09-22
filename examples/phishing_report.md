# Phishing Triage Report

**Risk level: HIGH** (score 43: 6 high, 3 medium, 4 low)

| Field | Value |
|---|---|
| Analysed file | `phishing_email.eml` |
| File SHA256 | `1801a39f63c3b1e58eac4c1f5a957d99290d12cbca8f822266854995d04c3a3a` |
| Generated (UTC) | `2026-09-22T09:11:25+00:00` |
| Tool version | `0.1.0` |
| IOCs defanged | Yes |

## Key Headers

| Header | Value |
|---|---|
| From | `Microsoft 365 Security <security@micros0ft-support[.]com>` |
| Reply-To | `account-verify@secure-helpdesk[.]example` |
| Return-Path | `<bounce-7781@mailer-d4x9[.]net>` |
| Subject | `URGENT: Unusual sign-in activity detected on your account` |
| Date | `Tue, 22 Sep 2026 03:12:38 +1000` |
| Message-ID | `<a81f93c2e4@smtp[.]mailer-d4x9[.]net>` |

## Authentication Results

| Check | Result |
|---|---|
| SPF | `pass` |
| DKIM | `none` |
| DMARC | `fail` |

## Received Chain (origin first)

1. `smtp[.]mailer-d4x9[.]net` `198[.]51[.]100[.]23` -> `mx[.]example[.]com` via ESMTP
2. `mx[.]example[.]com` `192[.]0[.]2[.]25` -> `mailbox[.]example[.]com` via LMTP

**Originating IP:** `198[.]51[.]100[.]23`

## URLs

| # | URL | Source | Link text |
|---|---|---|---|
| 1 | `hxxp://203[.]0[.]113[.]45/login[.]php` | HTML | `hxxps://account[.]microsoft[.]com/verify` |
| 2 | `hxxps://bit[.]ly/3xFakeLnk` | HTML | `Review activity` |
| 3 | `hxxp://micros0ft-support[.]com/reset?user=jordan[.]smith` | plain text | - |

## Attachments

| Filename | Declared type | Detected type | Size (bytes) | SHA256 |
|---|---|---|---|---|
| `Invoice_4471.pdf.exe` | `application/octet-stream` | unknown | 18 | `947d4fcd2d3a08dc046876bc199a074ce7148f477028e02ec31a6be3a0c26162` |

## Findings

### Header Mismatches

- **MEDIUM** Reply-To domain (secure-helpdesk[.]example) does not match From domain (micros0ft-support[.]com)
- **LOW** Return-Path domain (mailer-d4x9[.]net) does not match From domain (micros0ft-support[.]com)

### Sender Findings

- **HIGH** From domain (micros0ft-support[.]com) imitates 'microsoft'
- **MEDIUM** Display name 'Microsoft 365 Security' mentions 'microsoft' but the sender domain is micros0ft-support[.]com

### Authentication Findings

- **LOW** DKIM = none
- **HIGH** DMARC = fail (sender domain policy: p=none)

### Received Chain Findings

- **LOW** Hop 1: sending server 198[.]51[.]100[.]23 has no reverse DNS (shown as 'unknown')

### URL Findings

- **MEDIUM** hxxp://203[.]0[.]113[.]45/login[.]php -> uses a raw IP address instead of a domain name
- **HIGH** hxxp://203[.]0[.]113[.]45/login[.]php -> link text shows microsoft[.]com but the link goes to 203[.]0[.]113[.]45
- **LOW** hxxps://bit[.]ly/3xFakeLnk -> URL shortener hides the real destination
- **HIGH** hxxp://micros0ft-support[.]com/reset?user=jordan[.]smith -> domain imitates 'microsoft'

### Attachment Findings

- **HIGH** Invoice_4471.pdf.exe -> high-risk file type (.exe) that can run code
- **HIGH** Invoice_4471.pdf.exe -> double extension disguises a .exe as a .pdf

## Risk Reasons (highest impact first)

- +5 Sender Findings: From domain (micros0ft-support[.]com) imitates 'microsoft'
- +5 Authentication Findings: DMARC = fail (sender domain policy: p=none)
- +5 URL Findings: hxxp://203[.]0[.]113[.]45/login[.]php -> link text shows microsoft[.]com but the link goes to 203[.]0[.]113[.]45
- +5 URL Findings: hxxp://micros0ft-support[.]com/reset?user=jordan[.]smith -> domain imitates 'microsoft'
- +5 Attachment Findings: Invoice_4471.pdf.exe -> high-risk file type (.exe) that can run code
- +5 Attachment Findings: Invoice_4471.pdf.exe -> double extension disguises a .exe as a .pdf
- +3 Header Mismatches: Reply-To domain (secure-helpdesk[.]example) does not match From domain (micros0ft-support[.]com)
- +3 Sender Findings: Display name 'Microsoft 365 Security' mentions 'microsoft' but the sender domain is micros0ft-support[.]com
- +3 URL Findings: hxxp://203[.]0[.]113[.]45/login[.]php -> uses a raw IP address instead of a domain name
- +1 Header Mismatches: Return-Path domain (mailer-d4x9[.]net) does not match From domain (micros0ft-support[.]com)
- +1 Authentication Findings: DKIM = none
- +1 Received Chain Findings: Hop 1: sending server 198[.]51[.]100[.]23 has no reverse DNS (shown as 'unknown')
- +1 URL Findings: hxxps://bit[.]ly/3xFakeLnk -> URL shortener hides the real destination

---

_This report is a triage aid, not a verdict. Confirm with sandboxing and threat intelligence._
