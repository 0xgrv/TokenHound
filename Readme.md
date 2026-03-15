# TokenHound

A passive Burp Suite extension for hunting client-side encryption vulnerabilities, exposed cryptographic keys, hardcoded secrets, and weak JWT implementations in web application traffic.

---

## What it does

Once loaded, TokenHound runs in the background while you browse a target through Burp proxy. It inspects every request and response and flags anything suspicious. No active requests, no replaying traffic — it just watches.

**What it hunts for:**

- Client-side encryption libraries — JSEncrypt, CryptoJS, Web Crypto API, node-forge in JS responses
- Public key exposure — RSA/EC PEM blocks, `publicKey` fields in JSON, key distribution API endpoints
- Hardcoded secrets — AWS keys, GitHub tokens, Google API keys, Slack tokens, SendGrid keys, database connection strings, JWT secrets in JS source
- Weak crypto — hardcoded AES/DES keys, inline CryptoJS keys, hardcoded IVs
- JWT issues — `alg: none`, HMAC algorithms, expired tokens, long-lived tokens, admin role claims, sensitive data in payload
- Key flow correlation — tracks which endpoint served a public key and which POST request used it (client-side encryption bypass pattern)

---

## Requirements

- **Burp Suite** (Community or Pro)
- **Jython 2.7 standalone JAR**

Burp runs Python extensions through Jython, not your system Python install. You need the standalone JAR specifically — download it from [jython.org/download](https://www.jython.org/download). Get the file named something like `jython-standalone-2.7.3.jar`. No pip installs or external libraries needed — everything runs on standard Jython and built-in Java classes.

---

## Installation

**1. Point Burp at Jython**

- Open Burp Suite
- Go to **Extender** → **Options**
- Under *Python Environment*, click **Select file** and pick your `jython-standalone-2.7.x.jar`

**2. Load the extension**

- Go to **Extender** → **Extensions** → **Add**
- Set *Extension type* to **Python**
- Select `TokenHound.py`
- Click **Next**

You should see `[TokenHound] Loaded OK` in the output pane and a new **TokenHound** tab in Burp's main tab bar.

---

## Usage

Browse your target normally through Burp — TokenHound picks up everything automatically.

### Tabs

**Findings** — main results table with Severity, Confidence, Category, Type, URL and a snippet of evidence. Click any row to see the full request/response. Right-click for Send to Repeater, Send to Intruder, copy options. Filter by severity, category or confidence level. Export to CSV.

**Key Flow** — correlates public-key endpoints with encrypted POST requests from the same host. A `CONFIRMED` status means the host that served a public key also received a base64-blob POST — the classic client-side encryption bypass pattern.

**Request Detail** — full request and response for the selected finding, plus a confidence score breakdown showing exactly why the finding was or wasn't flagged with high confidence.

**JWT Analyzer** — paste any JWT to decode it and see a security analysis. The history table auto-fills with every JWT seen in traffic (both tokens issued in responses and Bearer tokens from requests). Click any row to load it into the analyzer. Checks for weak algorithms, expiry issues, privileged role claims, sensitive data in payload, and more.

**Configuration** — toggle detection modules, set scope restrictions, control severity logging.

### Scan Proxy History

The **Scan Proxy History** button in the top-right bar retroactively scans everything already captured in Burp's proxy history. Useful if you've been browsing for a while before loading the extension.

---

## Confidence scoring

Every finding gets scored 0–100 and bucketed into a confidence level so you can quickly triage what's worth looking at.

| Level | Score | What it means |
|---|---|---|
| CONFIRMED | 80–100 | Multiple strong signals — format validates, high entropy, right context |
| LIKELY | 55–79 | Pattern match with at least one supporting signal |
| POSSIBLE | 30–54 | Pattern match alone, generic context |
| UNLIKELY | 0–29 | Weak match, placeholder-looking value, or suspicious context |

Signals evaluated: Shannon entropy of the matched value, content-type of the response, URL path (API endpoint vs static asset), placeholder detection (`changeme`, `your_key_here` etc.), comment context, and type-specific format validation (AWS key length, JWT header base64 decode, PEM begin/end markers, DB URI format).

---

## False positive handling

A few things are intentionally suppressed:

- Binary and image responses are skipped entirely — avatars, PDFs and fonts won't trigger key pattern matches
- `Authorization: Bearer` tokens in request headers are captured for the JWT analyzer but never flagged as findings — a Bearer token in a request is normal
- JWT findings only fire when a token is **issued in a response body** (e.g. `"access_token": "eyJ..."`) or when a secret is hardcoded in JS source
- AWS and Google API key patterns require word boundaries so they don't match inside base64-encoded binary data

---

## A note on active scanning

TokenHound is fully passive. It only reads traffic that passes through your proxy — it never initiates HTTP requests, never replays captured requests, and never uses Burp's active scanner. Safe to run on authorized engagements without generating extra traffic or triggering rate limits.

---

## Author

**Garv Kamra**

Built during security research at [Ampcus Cyber](https://ampcuscyber.com), with guidance and encouragement from Pranshu Tiwari.

---

*For authorized security testing only.*