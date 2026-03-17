# -*- coding: utf-8 -*-
# TokenHound - Burp Suite Extension
# Passive scanner for client-side encryption, exposed API keys and hardcoded secrets
# Author: Garv Kamra | CyberSecurity Analyst
#
# How it works (high level):
#   1. Burp calls processHttpMessage() for every request/response passing through
#      the proxy. We read the raw bytes and run regex patterns against them.
#
#   2. Each pattern in PATTERNS has an optional validator function. The regex fires
#      first (cheap), and if it matches the validator does a context check (e.g.
#      "is this inside a comment?", "does the surrounding code look like a real key
#      assignment?"). If the validator returns False the finding is dropped silently.
#      This is the main false-positive reduction layer.
#
#   3. Every finding that survives goes through _score_confidence(), which builds a
#      0-100 score from independent signals: pattern specificity, content-type,
#      URL path, Shannon entropy of the value, placeholder word detection, comment
#      context, and format-specific checks (AWS key length, PEM END marker, etc.).
#      The score maps to CONFIRMED / LIKELY / POSSIBLE / UNLIKELY.
#
#   4. JWTs seen in traffic (both Authorization: Bearer headers and response body
#      issuance) are decoded and analyzed separately in _decode_jwt(). Checks
#      include: alg=none, HMAC vs asymmetric, expiry, privileged role claims,
#      sensitive fields in payload, and kid header injection.
#
#   5. Key Flow tracking watches for the pattern: GET /api/public-key followed by
#      a POST with a large base64 body from the same host. That pair is what
#      client-side RSA encryption looks like on the wire.
#
# Requires: Jython 2.7 standalone JAR (Extender > Options > Python Environment)

from burp import IBurpExtender, ITab, IScannerCheck, IHttpListener
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton,
                          JLabel, JTextField, JTextArea, JSplitPane, JCheckBox,
                          BorderFactory, JComboBox, SwingUtilities, JMenuItem,
                          JMenu, JPopupMenu, JFileChooser, JSpinner, SpinnerNumberModel)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from javax.swing.text import DefaultHighlighter
from java.awt import (Color, Font, Dimension, BorderLayout, FlowLayout,
                       GridBagLayout, GridBagConstraints, Insets, GridLayout)
from java.awt.event import MouseAdapter
from java.io import File, FileWriter, BufferedWriter
import re, threading, math, base64
from datetime import datetime


# ---------------------------------------------------------------------------
# Severity and confidence colour maps used by the cell renderers and the
# JWT analyzer alg label.
# ---------------------------------------------------------------------------
SEV_COLORS = {
    'CRITICAL': Color(200, 30,  30),
    'HIGH':     Color(210, 100,  0),
    'MEDIUM':   Color(160, 120,  0),
    'LOW':      Color(30,  100, 200),
    'INFO':     Color(110, 110, 110),
}
CONF_COLORS = {
    'CONFIRMED': Color(0,  150,  0),
    'LIKELY':    Color(30, 100, 200),
    'POSSIBLE':  Color(160, 130,  0),
    'UNLIKELY':  Color(160, 160, 160),
}

# Yellow background used to highlight matched evidence in the text areas.
HIGHLIGHT_COLOR = Color(255, 230, 80)


# ---------------------------------------------------------------------------
# Validator functions
#
# Every validator receives (match_object, full_content_string).
# Return True  -> keep the finding.
# Return False -> suppress it (false positive).
#
# Validators only run when the regex already matched, so they are a
# second-pass context filter — they never generate findings on their own.
# ---------------------------------------------------------------------------

def _val_google_api_key(m, content):
    """
    AIza... keys are legitimately embedded in public Maps/Firebase SDKs and
    are not secrets in that context. Only flag when the key appears on the
    right-hand side of an assignment or as a JSON value — not inside a URL
    or a comment block.
    """
    ev  = m.group(0)
    ctx = content[max(0, m.start() - 120): m.start() + 80].lower()
    if any(x in ctx for x in ['googleapis.com', 'maps.googleapis',
                               '//', '<!--', '/*', ' * ']):
        return False
    if re.search(r'(?:=|:)\s*["\']?' + re.escape(ev),
                 content[max(0, m.start() - 30): m.end() + 5]):
        return True
    return False


def _val_password(m, content):
    """
    The word 'password' appears constantly in login forms, labels and comments.
    Only flag when the surrounding 60-char window contains none of the common
    non-secret contexts AND the actual value has meaningful entropy (>2.5 bits).
    """
    non_secret_ctx = [
        'password_field', 'input type', 'placeholder', 'label', 'confirm',
        '{{', '${', 'process.env', 'getenv', 'os.environ', 'config[',
        'settings.', 'your_', 'change_me', 'changeme', 'enter your',
        'type here', '//',
    ]
    window = content[max(0, m.start() - 60): m.end() + 60].lower()
    if any(fp in window for fp in non_secret_ctx):
        return False
    val_match = re.search(r'[=:]\s*["\']([^"\']{6,})["\']', m.group(0))
    if val_match and _shannon_entropy(val_match.group(1)) < 2.5:
        return False
    return True


def _val_jwt_response(m, content):
    """
    Confirm a token shaped like a JWT is structurally valid by base64-decoding
    the header and checking for the 'alg' or 'typ' fields. Prevents random
    dot-separated base64 strings from being flagged.
    """
    token = m.group(1) if m.lastindex >= 1 else m.group(0)
    parts = token.split('.')
    if len(parts) != 3:
        return False
    try:
        hdr = parts[0] + '=' * (4 - len(parts[0]) % 4)
        decoded = base64.b64decode(hdr.replace('-', '+').replace('_', '/'))
        return b'"alg"' in decoded or b'"typ"' in decoded
    except Exception:
        return False


def _val_aws_key(m, content):
    """
    AWS access key IDs are exactly 20 characters (prefix + 16 uppercase chars).
    Anything else is a coincidental regex match. Also drop matches inside comments.
    """
    key = m.group(0)
    if len(key) != 20:
        return False
    preceding = content[max(0, m.start() - 60): m.start()]
    if '//' in preceding or '#' in preceding or '<!--' in preceding:
        return False
    return True


def _val_private_key(m, content):
    """
    A PEM private key block is only useful when complete. Require a matching
    END marker within 3000 chars of the BEGIN header.
    """
    snippet = content[m.start(): min(len(content), m.start() + 3000)]
    return 'END' in snippet and 'PRIVATE KEY' in snippet


def _val_cryptojs_hardcoded(m, content):
    """
    CryptoJS.AES.encrypt(data, key) is only suspicious when the key argument
    is a string literal. If it is a variable the actual value is unknown and
    may be loaded securely elsewhere.
    """
    ev = m.group(0)
    if re.search(
        r'CryptoJS\.AES\.(?:en|de)crypt\([^,]+,\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)',
        ev
    ):
        return False
    return True


def _val_connection_string(m, content):
    """
    Drop connection strings that still contain template placeholders like
    <user>:<password> or {DB_PASS}. Those are documentation examples.
    """
    ev = m.group(0)
    if re.search(r'<[^>]+>', ev) or re.search(r'\{[^}]+\}', ev):
        return False
    return True


def _val_subtle_crypto(m, content):
    """
    window.crypto.subtle / crypto.subtle is a standard browser API whose mere
    presence is not a finding. Only flag it when the surrounding 200 chars show
    a genuinely sensitive operation:
      - importKey / exportKey / generateKey / deriveKey  (key material handling)
      - encrypt() or decrypt() with a named algorithm like AES-GCM or RSA-OAEP

    This kills the common false positive where minified code calls
    crypto.subtle.digest() for hashing — digest is completely harmless.
    """
    ctx = content[max(0, m.start() - 200): m.end() + 200]
    if re.search(r'importKey|exportKey|generateKey|deriveKey|deriveBits', ctx):
        return True
    if re.search(r'encrypt\s*\(|decrypt\s*\(', ctx):
        if re.search(r'(?:AES-GCM|AES-CBC|RSA-OAEP|ECDH|name\s*:\s*["\'])', ctx):
            return True
    return False


def _val_slack_token(m, content):
    """Slack token must have at least three dash-separated segments."""
    return len(m.group(0).split('-')) >= 3


def _val_not_in_base64_blob(m, content):
    """
    Tokens like Square (EAAAl...), Twilio (SK.../AC...), Mailgun (key-...)
    can appear as random substrings inside base64-encoded binary data
    (images, fonts, etc.) embedded in JSON or HTML as data: URIs.
    Suppress when the 500-char window before the match contains 'data:' or
    'base64,' — those are embedded asset blobs, not secrets.
    Also suppress when the match is inside a continuous run of base64
    characters longer than 500 chars with no whitespace or punctuation.
    """
    ctx_before = content[max(0, m.start() - 500): m.start()].lower()
    if 'data:' in ctx_before or 'base64,' in ctx_before:
        return False
    # Check if the match is surrounded by a long unbroken base64 run
    # (real tokens appear in code, not in the middle of a multi-KB blob)
    run_start = m.start()
    while run_start > 0 and content[run_start - 1] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-':
        run_start -= 1
    run_end = m.end()
    while run_end < len(content) and content[run_end] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-':
        run_end += 1
    if (run_end - run_start) > 500:
        return False
    return True


# ---------------------------------------------------------------------------
# Pattern table
#
# Format: (category, regex, label, severity, validator_fn or None)
#
# Categories group related patterns in the UI filters. The regex runs with
# re.IGNORECASE | re.DOTALL so multi-line PEM blocks and mixed-case keywords
# both match. The validator (if present) is the second-pass context check.
# ---------------------------------------------------------------------------
PATTERNS = [

    # -- Asymmetric Keys -----------------------------------------------------
    # PEM blocks: captures the header + at least 50 chars of body so an empty
    # or truncated block does not fire.
    ('Asymmetric Key', r'-----BEGIN PUBLIC KEY-----[\s\S]{50,}',
        'RSA/EC Public Key (PEM)', 'HIGH', None),
    ('Asymmetric Key', r'-----BEGIN RSA PUBLIC KEY-----[\s\S]{50,}',
        'RSA Public Key (PKCS1)', 'HIGH', None),
    ('Asymmetric Key', r'-----BEGIN PRIVATE KEY-----[\s\S]{50,}',
        'Private Key EXPOSED (PKCS8)', 'CRITICAL', _val_private_key),
    ('Asymmetric Key', r'-----BEGIN RSA PRIVATE KEY-----[\s\S]{50,}',
        'RSA Private Key EXPOSED', 'CRITICAL', _val_private_key),
    ('Asymmetric Key', r'-----BEGIN EC PRIVATE KEY-----[\s\S]{50,}',
        'EC Private Key EXPOSED', 'CRITICAL', _val_private_key),

    # Obfuscated PEM: developers sometimes base64-encode a key and decode it
    # at runtime with atob() to hide it from simple grep searches.
    ('Asymmetric Key',
        r'(?:atob|decodeURIComponent|fromBase64)\s*\(["\'][A-Za-z0-9+/=\n]{80,}["\']',
        'Possible Base64-Encoded Key (Obfuscated)', 'HIGH', None),

    # JSON structures that describe RSA key configuration.
    ('Asymmetric Key', r'"keySpec"\s*:\s*"RSA"',
        'RSA Key Spec in JSON', 'MEDIUM', None),
    ('Asymmetric Key', r'"keyUsage"\s*:\s*"ENCRYPT_DECRYPT"',
        'Encrypt/Decrypt Key Usage', 'MEDIUM', None),
    ('Asymmetric Key', r'"publicKey"\s*:\s*"[A-Za-z0-9+/=\-\n]{100,}"',
        'Public Key in JSON Response', 'HIGH', None),

    # SSH public keys served over HTTP (e.g. from a key distribution endpoint).
    ('Asymmetric Key', r'ssh-rsa\s+[A-Za-z0-9+/=]{100,}',
        'SSH RSA Public Key', 'MEDIUM', None),
    ('Asymmetric Key', r'ssh-ed25519\s+[A-Za-z0-9+/=]{40,}',
        'SSH Ed25519 Key', 'MEDIUM', None),

    # -- Symmetric Keys ------------------------------------------------------
    # JSON fields that are unambiguously key containers, followed by a
    # base64 value long enough to be a real 128/256-bit key.
    ('Symmetric Key',
        r'"(?:secretKey|secret_key|aesKey|aes_key|encKey|enc_key|encryptionKey|encryption_key)"\s*:\s*"[A-Za-z0-9+/=]{24,}"',
        'Symmetric Key in JSON', 'CRITICAL', None),

    # Variable assignment: AESKey = "...", DES_KEY = "..."
    ('Symmetric Key',
        r'(?:AES|DES|3DES|ChaCha20)\s*(?:key|Key|KEY)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']',
        'Hardcoded Symmetric Key', 'CRITICAL', None),

    # IV hardcoded as hex (16 bytes = 32 hex chars for AES).
    ('Symmetric Key', r'\biv\s*=\s*["\'][A-Fa-f0-9]{16,32}["\']',
        'Hardcoded IV', 'HIGH', None),

    # CryptoJS.AES.encrypt(data, "literalKey") — validator ensures the second
    # argument is a string literal and not a variable.
    ('Symmetric Key',
        r'CryptoJS\.AES\.(?:en|de)crypt\([^,]+,\s*["\'][^"\']{8,}["\']',
        'CryptoJS Hardcoded Key', 'CRITICAL', _val_cryptojs_hardcoded),

    # Node.js crypto.createSecretKey("literal") pattern.
    ('Symmetric Key',
        r'createSecretKey\s*\(\s*(?:Buffer\.from\s*\()?\s*["\'][A-Za-z0-9+/=]{16,}["\']',
        'Node createSecretKey Hardcoded', 'CRITICAL', None),

    # -- Crypto Library Usage ------------------------------------------------
    # JSEncrypt is a pure-JS RSA library. Loading it is informational;
    # creating an instance or calling setPublicKey() is more significant.
    ('Crypto Library',
        r'cdn\.jsdelivr\.net/npm/jsencrypt|from\s+["\']jsencrypt["\']|require\s*\(\s*["\']jsencrypt["\']',
        'JSEncrypt Library Loaded', 'MEDIUM', None),
    ('Crypto Library', r'new\s+JSEncrypt\s*\(\)',
        'JSEncrypt Instance Created', 'HIGH', None),
    ('Crypto Library', r'\.setPublicKey\s*\(',
        'setPublicKey() Called', 'HIGH', None),

    # encrypt(JSON.stringify(...)) means the entire request body is encrypted
    # client-side before being sent to the server.
    ('Crypto Library', r'\.encrypt\s*\(\s*JSON\.stringify',
        'Client-Side JSON Encryption', 'HIGH', None),

    ('Crypto Library', r'CryptoJS\s*\.',
        'CryptoJS Usage', 'MEDIUM', None),
    ('Crypto Library', r'forge\.pki\.|require\s*\(\s*["\']node-forge["\']',
        'node-forge Usage', 'MEDIUM', None),

    # Web Crypto API — only flagged when paired with key-handling operations
    # (see _val_subtle_crypto). Plain digest() calls are suppressed.
    ('Crypto Library', r'window\.crypto\.subtle\.|crypto\.subtle\.',
        'Web Crypto API (subtle)', 'LOW', _val_subtle_crypto),

    # SubtleCrypto method calls are higher severity because they confirm
    # actual cryptographic work, not just API availability.
    ('Crypto Library',
        r'subtle\.(?:encrypt|decrypt|sign|verify|deriveKey|importKey|exportKey)',
        'SubtleCrypto Operation', 'HIGH', None),
    ('Crypto Library', r'importKey\s*\(\s*["\'](?:raw|pkcs8|spki)["\']',
        'SubtleCrypto Key Import', 'HIGH', None),

    # Node.js built-in crypto ciphers.
    ('Crypto Library', r'crypto\.createCipheriv|crypto\.createDecipheriv',
        'Node crypto cipher', 'HIGH', None),
    ('Crypto Library', r'crypto\.createSign|crypto\.createVerify',
        'Node crypto sign/verify', 'MEDIUM', None),

    # Third-party crypto library imports.
    ('Crypto Library',
        r'require\s*\(\s*["\'](?:crypto-js|elliptic|tweetnacl|openpgp)["\']',
        'Crypto Library Import', 'MEDIUM', None),

    # postMessage() used to send an encrypted payload across frames or workers.
    ('Crypto Library',
        r'postMessage\s*\(\s*(?:JSON\.stringify\s*\()?(?:encrypted|ciphertext|encData|encryptedPayload)',
        'postMessage Crypto Data Leak', 'HIGH', None),

    # eval(atob("...")) is a classic technique to hide code or keys from
    # static analysis; the base64 is decoded and executed at runtime.
    ('Crypto Library', r'eval\s*\(\s*atob\s*\(',
        'eval(atob()) Obfuscation Pattern', 'HIGH', None),

    # Storing a secret in localStorage/sessionStorage means it is readable by
    # any JS on the same origin — a well-known OWASP risk.
    ('Crypto Library',
        r'(?:localStorage|sessionStorage)\.setItem\s*\(["\'][^"\']*(?:key|secret|token|password|private)[^"\']*["\']',
        'Secret Stored in Web Storage', 'HIGH', None),

    # -- Key Flow ------------------------------------------------------------
    # URLs that suggest an endpoint whose job is to hand out a public key.
    ('Key Flow', r'/(?:encryption|crypto|security)/public-?key',
        'Public Key Endpoint URL', 'HIGH', None),
    ('Key Flow', r'"publicKey"\s*:',
        'Public Key in Response Body', 'HIGH', None),
    ('Key Flow', r'/(?:api|v\d+)/(?:keys?|pubkey|rsa|encrypt)(?:[/?]|$)',
        'Key API Endpoint', 'HIGH', None),
    ('Key Flow', r'"(?:rsaPublicKey|encryptionKey|serverPublicKey)"\s*:',
        'Named Public Key in JSON', 'HIGH', None),

    # -- Hardcoded Secrets ---------------------------------------------------
    # AWS: the four known prefixes followed by exactly 16 uppercase chars.
    # Validator enforces exact 20-char length and no comment context.
    ('Hardcoded Secret',
        r'(?<![A-Za-z0-9/+])(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Za-z0-9/+=])',
        'AWS Access Key ID', 'CRITICAL', _val_aws_key),
    ('Hardcoded Secret',
        r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?[A-Za-z0-9/+]{40}["\']?',
        'AWS Secret Key', 'CRITICAL', None),

    # Google API key — context-validated.
    ('Hardcoded Secret',
        r'(?<![A-Za-z0-9/+])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9/+=])',
        'Google API Key', 'HIGH', _val_google_api_key),

    # GitHub token formats. Each has a fixed prefix GitHub introduced to make
    # tokens machine-detectable.
    ('Hardcoded Secret', r'ghp_[A-Za-z0-9]{36}',
        'GitHub Personal Access Token (Classic)', 'CRITICAL', None),
    ('Hardcoded Secret', r'github_pat_[A-Za-z0-9_]{59}',
        'GitHub Fine-Grained PAT', 'CRITICAL', None),
    ('Hardcoded Secret', r'ghs_[A-Za-z0-9]{36}',
        'GitHub Actions Token', 'CRITICAL', None),
    ('Hardcoded Secret', r'ghr_[A-Za-z0-9]{36}',
        'GitHub Refresh Token', 'CRITICAL', None),

    # Slack: xoxb=bot, xoxp=user, xoxa=workspace app, xoxo=legacy.
    ('Hardcoded Secret',
        r'xox[bpoa]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}',
        'Slack Token', 'HIGH', _val_slack_token),

    # Stripe: sk_live_ is the live secret key. sk_test_ is excluded — test
    # keys have no financial value.
    ('Hardcoded Secret', r'sk_live_[A-Za-z0-9]{24,}',
        'Stripe Live Secret Key', 'CRITICAL', None),
    ('Hardcoded Secret', r'pk_live_[A-Za-z0-9]{24,}',
        'Stripe Live Publishable Key', 'HIGH', None),

    ('Hardcoded Secret', r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
        'SendGrid API Key', 'HIGH', None),

    # Twilio SIDs: SK... = API key (32 hex chars), AC... = account SID.
    ('Hardcoded Secret', r'SK[0-9a-fA-F]{32}',
        'Twilio API Key SID', 'HIGH', _val_not_in_base64_blob),
    ('Hardcoded Secret', r'AC[0-9a-fA-F]{32}',
        'Twilio Account SID', 'MEDIUM', _val_not_in_base64_blob),

    ('Hardcoded Secret', r'key-[0-9a-zA-Z]{32}',
        'Mailgun API Key', 'HIGH', _val_not_in_base64_blob),

    ('Hardcoded Secret', r'shpss_[a-fA-F0-9]{32}',
        'Shopify Shared Secret', 'CRITICAL', None),
    ('Hardcoded Secret', r'shpat_[a-fA-F0-9]{32}',
        'Shopify Access Token', 'CRITICAL', None),
    ('Hardcoded Secret', r'EAAAl[a-zA-Z0-9\-_]{40,}',
        'Square Access Token', 'CRITICAL', _val_not_in_base64_blob),

    # JWT signing secret hardcoded as a string literal.
    ('Hardcoded Secret',
        r'(?:jwt_secret|jwtSecret|JWT_SECRET|token_secret|TOKEN_SECRET)\s*[=:]\s*["\'][^"\']{8,}["\']',
        'JWT Secret Hardcoded', 'CRITICAL', None),

    # JWT issued in a response body (login endpoint, token refresh).
    # Validator base64-decodes the header to confirm alg/typ fields.
    ('Hardcoded Secret',
        r'"(?:token|access_token|id_token|refresh_token)"\s*:\s*"(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"',
        'JWT Issued in Response Body', 'MEDIUM', _val_jwt_response),

    # Password literal — validator cuts nearly all FPs from form fields and
    # environment variable references.
    ('Hardcoded Secret',
        r'(?<![a-zA-Z])password\s*[=:]\s*["\'][^"\']{6,}["\']',
        'Hardcoded Password', 'HIGH', _val_password),

    # Database connection strings with embedded credentials.
    ('Hardcoded Secret',
        r'mongodb(?:\+srv)?://[^@\s"\'<>]+:[^@\s"\'<>]+@[^\s"\'<>]{5,}',
        'MongoDB Connection String', 'CRITICAL', _val_connection_string),
    ('Hardcoded Secret',
        r'(?:postgresql|postgres)://[^@\s"\'<>]+:[^@\s"\'<>]+@[^\s"\'<>]{5,}',
        'PostgreSQL Connection String', 'CRITICAL', _val_connection_string),
    ('Hardcoded Secret',
        r'mysql://[^@\s"\'<>]+:[^@\s"\'<>]+@[^\s"\'<>]{5,}',
        'MySQL Connection String', 'CRITICAL', _val_connection_string),
    ('Hardcoded Secret',
        r'redis://:?[^@\s"\'<>]+@[^\s"\'<>]{5,}',
        'Redis Connection String', 'CRITICAL', _val_connection_string),

    ('Hardcoded Secret', r'npm_[A-Za-z0-9]{36}',
        'NPM Access Token', 'CRITICAL', None),
    ('Hardcoded Secret', r'pypi-[A-Za-z0-9_\-]{40,}',
        'PyPI API Token', 'CRITICAL', None),

    # LLM provider API keys.
    ('Hardcoded Secret', r'sk-ant-[A-Za-z0-9\-_]{80,}',
        'Anthropic API Key', 'CRITICAL', None),
    ('Hardcoded Secret', r'sk-[A-Za-z0-9]{48}',
        'OpenAI API Key', 'CRITICAL', None),
    ('Hardcoded Secret', r'hf_[A-Za-z0-9]{34,}',
        'HuggingFace API Token', 'CRITICAL', None),

    # Passphrase used to decrypt a private key file.
    ('Hardcoded Secret',
        r'(?:passphrase|PASSPHRASE|key_password)\s*[=:]\s*["\'][^"\']{6,}["\']',
        'Private Key Passphrase', 'CRITICAL', None),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class NonEditableTableModel(DefaultTableModel):
    """JTable model that prevents any cell from being edited by the user."""
    def isCellEditable(self, row, col):
        return False


class Finding(object):
    """
    All data associated with one detected issue.
    The class-level counter gives each finding a stable numeric ID that
    survives table filtering and sorting.
    """
    _counter = [0]

    def __init__(self, url, method, category, finding_type, severity, evidence,
                 request_response, confidence='LIKELY', confidence_score=50,
                 confidence_reasons=None, match_start=-1, match_end=-1,
                 found_in='response'):
        Finding._counter[0] += 1
        self.num               = Finding._counter[0]
        self.timestamp         = datetime.now().strftime('%H:%M:%S')
        self.url               = url
        self.method            = method
        self.category          = category
        self.finding_type      = finding_type
        self.severity          = severity
        self.evidence          = (evidence or '')[:400]
        self.request_response  = request_response
        self.confidence        = confidence
        self.confidence_score  = confidence_score
        self.confidence_reasons = confidence_reasons or []
        self.match_start       = match_start   # byte offset in raw content
        self.match_end         = match_end
        self.found_in          = found_in      # 'request' or 'response'
        self.is_fp             = False         # user-marked false positive
        self.severity_override = None          # user-overridden severity


def _shannon_entropy(s):
    """
    Shannon entropy in bits per character.

    Real secrets (API keys, AES keys, etc.) score >3.5 because each character
    is roughly random. Human-chosen passwords and placeholder strings score <2.5
    because they use common words with repeated characters.

    H = -sum( p(c) * log2(p(c)) ) for each unique character c in s.
    """
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = float(len(s))
    return -sum((v / n) * math.log(v / n, 2) for v in freq.values())


def _score_confidence(finding, content_type, url, full_content, entropy_threshold=3.5):
    """
    Build a 0-100 confidence score from eight independent signals and map it to:
      CONFIRMED (>=80), LIKELY (>=55), POSSIBLE (>=30), UNLIKELY (<30).

    Signal breakdown:
      +40  pattern is in HIGH_SPEC set (very specific format, rare FPs)
      +25  pattern is in MED_SPEC set
      +10  generic pattern
      +20  content-type is JavaScript or JSON
      +5   content-type is HTML
      +8   content-type unknown
      +15  URL path looks like an API endpoint
      -15  URL path looks like a static asset
      +25  value entropy >= threshold+0.5 (likely a random key)
      +12  value entropy >= threshold
      -25  value entropy below threshold (looks like a word or placeholder)
      -35  evidence contains a known placeholder word
      -30  match is inside a comment block
      +20  JWT header decodes with alg/typ fields present
      +20  AWS key is exactly 20 chars
      +20  PEM block has both BEGIN and END markers
      +20  connection string matches user:pass@host format
      +5   response body is substantial (>5000 bytes)
    """
    score, reasons = 0, []
    ev    = finding.evidence
    ftype = finding.finding_type
    cat   = finding.category
    ct    = (content_type or '').lower()

    HIGH_SPEC = {
        'AWS Access Key ID', 'AWS Secret Key',
        'GitHub Personal Access Token (Classic)', 'GitHub Fine-Grained PAT',
        'GitHub Actions Token', 'GitHub Refresh Token',
        'SendGrid API Key', 'Slack Token', 'Stripe Live Secret Key',
        'RSA Private Key EXPOSED', 'EC Private Key EXPOSED',
        'Private Key EXPOSED (PKCS8)', 'MongoDB Connection String',
        'PostgreSQL Connection String', 'MySQL Connection String',
        'Redis Connection String', 'NPM Access Token', 'PyPI API Token',
        'Anthropic API Key', 'OpenAI API Key', 'HuggingFace API Token',
        'Shopify Shared Secret', 'Shopify Access Token', 'Square Access Token',
        'CryptoJS Hardcoded Key', 'Node createSecretKey Hardcoded',
    }
    MED_SPEC = {
        'Google API Key', 'JWT Secret Hardcoded', 'RSA/EC Public Key (PEM)',
        'RSA Public Key (PKCS1)', 'Symmetric Key in JSON',
        'JSEncrypt Instance Created', 'Client-Side JSON Encryption',
        'Encrypted Payload (base64 blob POST)', 'Public Key Distribution Endpoint',
        'Public Key in JSON Response', 'Named Public Key in JSON',
        'SubtleCrypto Key Import', 'JWT Issued in Response Body',
        'Twilio API Key SID', 'Mailgun API Key', 'Stripe Live Publishable Key',
        'Private Key Passphrase',
    }

    if ftype in HIGH_SPEC:
        score += 40; reasons.append("High-specificity pattern")
    elif ftype in MED_SPEC:
        score += 25; reasons.append("Medium-specificity pattern")
    else:
        score += 10; reasons.append("Generic pattern")

    if any(x in ct for x in ['javascript', 'application/json',
                               'x-javascript', 'ecmascript']):
        score += 20; reasons.append("JS/JSON content-type")
    elif 'text/html' in ct:
        score += 5;  reasons.append("HTML content-type")
    elif not ct:
        score += 8;  reasons.append("Unknown content-type")

    url_l = url.lower()
    if any(x in url_l for x in ['/api/', '/v1/', '/v2/', '/v3/', '/internal/',
                                  '/admin/', '/backend/', '/graphql']):
        score += 15; reasons.append("API endpoint URL")
    elif any(x in url_l for x in ['/static/', '/assets/', '/public/', '/cdn/']):
        score -= 15; reasons.append("Static asset URL (lower trust)")

    # Entropy check: isolate the value portion from a key=value or "key":"value" pattern.
    if cat in ('Hardcoded Secret', 'Symmetric Key') and ev:
        val = ev
        for sep in ['=', ':', '"']:
            if sep in ev:
                candidate = ev.split(sep)[-1].strip().strip('"\'')
                if len(candidate) >= 8:
                    val = candidate
                    break
        e = _shannon_entropy(val)
        if e >= entropy_threshold + 0.5:
            score += 25; reasons.append("High entropy ({:.2f} bits)".format(e))
        elif e >= entropy_threshold:
            score += 12; reasons.append("Moderate entropy ({:.2f} bits)".format(e))
        else:
            score -= 25; reasons.append("Low entropy — placeholder? ({:.2f})".format(e))

    PLACEHOLDERS = ['your_', 'yourkey', 'example', 'placeholder', 'changeme',
                    'insert_', 'replace_', 'xxxxxxx', 'aaaaaaa', '123456',
                    'test', 'demo', 'sample', 'dummy', 'fake', 'todo',
                    'my_secret', '<key>', '<token>', '<secret>', 'abcdef']
    if any(p in ev.lower() for p in PLACEHOLDERS):
        score -= 35; reasons.append("Placeholder value detected")

    stripped = ev.strip()
    if stripped.startswith('//') or stripped.startswith('#') or '/**' in ev or '/*' in ev:
        score -= 30; reasons.append("Inside a comment block")

    # Format-specific validation: these add confidence when the value
    # structurally matches what a real secret should look like.
    if ftype == 'JWT Issued in Response Body' and ev:
        m2 = re.search(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', ev)
        if m2:
            try:
                hdr = m2.group(0).split('.')[0]
                hdr += '=' * (4 - len(hdr) % 4)
                decoded = base64.b64decode(hdr.replace('-', '+').replace('_', '/'))
                if b'"alg"' in decoded or b'"typ"' in decoded:
                    score += 20; reasons.append("JWT header decodes correctly")
            except Exception:
                pass

    if ftype == 'AWS Access Key ID':
        m3 = re.search(r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}', ev)
        if m3 and len(m3.group(0)) == 20:
            score += 20; reasons.append("AWS key is exactly 20 chars")

    if 'Private Key' in ftype and 'END' in full_content and 'BEGIN' in full_content:
        score += 20; reasons.append("PEM block has BEGIN+END markers")

    if 'Connection String' in ftype:
        if re.search(r'://[^:]+:[^@]+@[a-zA-Z0-9._\-]+', ev):
            score += 20; reasons.append("user:pass@host format valid")

    if len(full_content) > 5000:
        score += 5; reasons.append("Large response ({} bytes)".format(len(full_content)))

    score = max(0, min(100, score))
    if   score >= 80: label = 'CONFIRMED'
    elif score >= 55: label = 'LIKELY'
    elif score >= 30: label = 'POSSIBLE'
    else:             label = 'UNLIKELY'
    return label, score, reasons


# ---------------------------------------------------------------------------
# JWT decoder
#
# JWTs are three base64url-encoded JSON objects joined by dots:
#   header.payload.signature
#
# The header carries the signing algorithm. The payload carries the claims
# (who the token is for, when it expires, what roles/scopes it grants).
# The signature is a cryptographic proof the header+payload were signed by
# whoever holds the secret or private key.
#
# We decode the first two parts and run security checks. We never verify the
# signature — that is out of scope for a passive scanner.
# ---------------------------------------------------------------------------

def _b64_decode_jwt_part(part):
    """
    Decode a base64url-encoded JWT part.
    base64url differs from standard base64: uses - instead of +, _ instead of /,
    and omits padding. We restore both differences before decoding.
    """
    try:
        padding = 4 - len(part) % 4
        padded  = part + ('=' * (padding % 4))
        decoded = base64.b64decode(padded.replace('-', '+').replace('_', '/'))
        return decoded.decode('utf-8', errors='replace')
    except Exception as ex:
        return '(decode error: {})'.format(ex)


def _decode_jwt(token):
    """
    Decode a JWT and return a dict with decoded parts and security warnings.

    Security checks:
      - alg=none:          no signature at all, trivially forgeable
      - HMAC (HS256/384):  shared secret — brute-forceable if weak
      - Asymmetric:        standard, informational only
      - Expiry:            warn if expired or lifetime > 24 hours
      - Privileged roles:  admin, root, superuser, owner, etc.
      - Sensitive payload: password, ssn, card, cvv embedded in claims
      - kid injection:     path separators or SQL chars in the key ID field
      - Empty/short sig:   indicates unsigned or tampered token
    """
    result = {
        'header_raw': '', 'payload_raw': '', 'signature_raw': '',
        'header_json': '', 'payload_json': '',
        'alg': '', 'sub': '', 'iss': '', 'exp': '', 'iat': '',
        'claims': {}, 'warnings': []
    }
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        result['warnings'].append(
            'Not a valid JWT (expected 3 parts, got {})'.format(len(parts)))
        return result

    result['header_raw']    = parts[0]
    result['payload_raw']   = parts[1]
    result['signature_raw'] = parts[2]

    hdr_str     = _b64_decode_jwt_part(parts[0])
    payload_str = _b64_decode_jwt_part(parts[1])
    result['header_json']  = hdr_str
    result['payload_json'] = payload_str

    try:
        alg_m = re.search(r'"alg"\s*:\s*"([^"]+)"', hdr_str)
        result['alg'] = alg_m.group(1) if alg_m else 'unknown'
    except Exception:
        result['alg'] = 'unknown'

    try:
        for key in ['sub', 'iss', 'exp', 'iat', 'role', 'email', 'name',
                    'username', 'userId', 'scope', 'permissions', 'groups']:
            m = re.search(r'"' + key + r'"\s*:\s*"?([^",}\s]+)"?', payload_str)
            if m:
                val = m.group(1).strip('"')
                result['claims'][key] = val
                if key in ('sub', 'iss', 'exp', 'iat'):
                    result[key] = val
    except Exception:
        pass

    alg = result['alg'].upper()
    if alg == 'NONE':
        result['warnings'].append(
            'CRITICAL: alg=none — signature verification is disabled')
    elif alg.startswith('HS'):
        result['warnings'].append(
            'MEDIUM: HMAC algorithm ({}). Shared secret signing — brute-forceable if weak'.format(alg))
    elif alg.startswith(('RS', 'ES', 'PS')):
        result['warnings'].append(
            'INFO: Asymmetric algorithm ({}) — standard public/private key signing'.format(alg))

    exp_val = result.get('exp', '')
    if exp_val:
        try:
            import time
            exp_ts = int(exp_val)
            now_ts = int(time.time())
            if exp_ts < now_ts:
                result['warnings'].append(
                    'INFO: Token is EXPIRED (exp={})'.format(exp_val))
            else:
                diff_h = (exp_ts - now_ts) / 3600.0
                if diff_h > 168:
                    result['warnings'].append(
                        'HIGH: Very long-lived token — expires in {:.1f} hours'.format(diff_h))
                elif diff_h > 24:
                    result['warnings'].append(
                        'LOW: Long-lived token — expires in {:.1f} hours'.format(diff_h))
        except Exception:
            pass

    claims = result['claims']
    if 'role' in claims:
        if any(r in claims['role'].lower() for r in
               ['admin', 'root', 'superuser', 'god', 'system', 'owner']):
            result['warnings'].append(
                'HIGH: Privileged role claim: ' + claims['role'])

    if 'scope' in claims:
        if any(s in claims['scope'].lower() for s in
               ['write:all', 'admin', 'sudo', 'root']):
            result['warnings'].append(
                'MEDIUM: Broad scope claim: ' + claims['scope'])

    if not parts[2]:
        result['warnings'].append('CRITICAL: Empty signature — token is unsigned')
    elif len(parts[2]) < 10:
        result['warnings'].append('HIGH: Very short signature — possible tampering')

    for sk in ['password', 'passwd', 'secret', 'ssn', 'credit',
               'card', 'cvv', 'pin', 'private']:
        if sk in payload_str.lower():
            result['warnings'].append(
                'HIGH: Sensitive field "{}" found in JWT payload'.format(sk))

    # kid (key ID) injection: if the server looks up the signing key by kid value
    # in a database or file, injecting path separators or SQL chars can redirect
    # verification to an attacker-controlled key.
    if '"kid"' in hdr_str:
        kid_m = re.search(r'"kid"\s*:\s*"([^"]+)"', hdr_str)
        if kid_m:
            kid_val = kid_m.group(1)
            if any(c in kid_val for c in ['../', '|', ';', '`', '$', '&&', "'", '"']):
                result['warnings'].append(
                    'CRITICAL: Possible kid injection in header: ' + kid_val)

    return result


# ---------------------------------------------------------------------------
# JWT Auditor — payload generation engine
#
# Generates test cases from a real captured token. Each test mutates the
# original token in a specific way, sends it through Burp's HTTP stack, and
# records whether the server accepted (2xx) or rejected (4xx/5xx) it.
#
# Tests are grouped by attack class:
#   SIGNATURE  — alg confusion, alg:none, empty/stripped signature
#   CLAIMS     — expired token, future iat, privilege escalation in role/sub
#   STRUCTURE  — truncated token, extra dots, null bytes in header
#   INJECTION  — kid header SQLi/path traversal, x5u/jku SSRF placeholders
#
# The auditor only runs when the user clicks "Run Audit". It never fires
# automatically to avoid account lockout on authenticated endpoints.
# ---------------------------------------------------------------------------

def _b64url_encode(data):
    """Encode bytes to base64url without padding."""
    if isinstance(data, unicode if hasattr(__builtins__, 'unicode') else str):
        data = data.encode('utf-8')
    return base64.b64encode(data).rstrip('=').replace('+', '-').replace('/', '_').decode('ascii')


def _b64url_encode_str(s):
    """Encode a string to base64url."""
    return _b64url_encode(s.encode('utf-8') if isinstance(s, str) else s)


def _forge_token(header_json, payload_json, signature=''):
    """
    Build a JWT from raw JSON strings.
    signature is a raw string — pass '' for alg:none tests.
    """
    h = _b64url_encode_str(header_json)
    p = _b64url_encode_str(payload_json)
    return '{}.{}.{}'.format(h, p, signature)


def _build_jwt_test_cases(token):
    """
    Analyse a real JWT and return a list of test case dicts:
      {
        'name':        str  — short label shown in the results table
        'class':       str  — SIGNATURE / CLAIMS / STRUCTURE / INJECTION
        'description': str  — what this test checks
        'token':       str  — the mutated token to send
        'risk':        str  — CRITICAL / HIGH / MEDIUM / LOW
      }

    The token argument is the raw eyJ... string from the input field.
    We parse the original header and payload so mutations stay realistic.
    """
    import json as _json

    cases = []
    parts = token.strip().split('.')
    if len(parts) != 3:
        return cases

    # Decode original header and payload
    try:
        hdr_str     = _b64_decode_jwt_part(parts[0])
        payload_str = _b64_decode_jwt_part(parts[1])
        orig_hdr    = _json.loads(hdr_str)
        orig_pay    = _json.loads(payload_str)
    except Exception:
        return cases

    orig_alg = orig_hdr.get('alg', 'HS256')
    orig_sig = parts[2]

    # ── SIGNATURE tests ──────────────────────────────────────────────────

    # Test 1: alg=none (no signature)
    # If the server accepts this, it skips signature verification entirely.
    none_hdr = dict(orig_hdr); none_hdr['alg'] = 'none'
    cases.append({
        'name':        'alg=none (no signature)',
        'class':       'SIGNATURE',
        'description': 'Header changed to alg=none with empty signature. '
                       'Acceptance means the server skips signature verification.',
        'token':       _forge_token(_json.dumps(none_hdr, separators=(',', ':')),
                                    _json.dumps(orig_pay, separators=(',', ':')), ''),
        'risk':        'CRITICAL',
    })

    # Test 2: alg=none with "None" capitalisation variants
    for variant in ['None', 'NONE', 'nOnE']:
        v_hdr = dict(orig_hdr); v_hdr['alg'] = variant
        cases.append({
            'name':        'alg={} variant'.format(variant),
            'class':       'SIGNATURE',
            'description': 'Some parsers check alg case-insensitively; '
                           'others only block the exact string "none".',
            'token':       _forge_token(_json.dumps(v_hdr, separators=(',', ':')),
                                        _json.dumps(orig_pay, separators=(',', ':')), ''),
            'risk':        'CRITICAL',
        })

    # Test 3: empty signature (keep original alg)
    cases.append({
        'name':        'Empty signature (original alg)',
        'class':       'SIGNATURE',
        'description': 'Original algorithm kept but signature removed. '
                       'Acceptance means the library does not validate signature presence.',
        'token':       '{}.{}.'.format(parts[0], parts[1]),
        'risk':        'HIGH',
    })

    # Test 4: RS→HS confusion (only if original is RS256/RS384/RS512)
    # Attacker uses the server's public key as the HMAC secret.
    if orig_alg.upper().startswith('RS'):
        hs_alg = orig_alg.upper().replace('RS', 'HS')
        hs_hdr = dict(orig_hdr); hs_hdr['alg'] = hs_alg
        cases.append({
            'name':        'RS→{} algorithm confusion'.format(hs_alg),
            'class':       'SIGNATURE',
            'description': 'Changed from {} to {}. If the server accepts the public key '
                           'as an HMAC secret, an attacker who has the public key can '
                           'forge valid tokens.'.format(orig_alg, hs_alg),
            'token':       _forge_token(_json.dumps(hs_hdr, separators=(',', ':')),
                                        _json.dumps(orig_pay, separators=(',', ':')),
                                        'ATTACKER_WOULD_SIGN_WITH_PUBLIC_KEY'),
            'risk':        'CRITICAL',
        })

    # Test 5: ES→HS confusion (only if original is ES256/ES384/ES512)
    if orig_alg.upper().startswith('ES'):
        hs_alg = orig_alg.upper().replace('ES', 'HS')
        hs_hdr = dict(orig_hdr); hs_hdr['alg'] = hs_alg
        cases.append({
            'name':        'ES→{} algorithm confusion'.format(hs_alg),
            'class':       'SIGNATURE',
            'description': 'Changed from {} to {}. Same attack as RS→HS but for '
                           'ECDSA keys.'.format(orig_alg, hs_alg),
            'token':       _forge_token(_json.dumps(hs_hdr, separators=(',', ':')),
                                        _json.dumps(orig_pay, separators=(',', ':')),
                                        'ATTACKER_WOULD_SIGN_WITH_EC_PUBLIC_KEY'),
            'risk':        'CRITICAL',
        })

    # Test 6: original token with signature stripped to single dot
    cases.append({
        'name':        'Signature = single dot',
        'class':       'SIGNATURE',
        'description': 'Signature replaced with a single "." to test for '
                       'off-by-one errors in signature parsers.',
        'token':       '{}.{}.{}'.format(parts[0], parts[1], '.'),
        'risk':        'MEDIUM',
    })

    # ── CLAIMS tests ─────────────────────────────────────────────────────

    # Test 7: expired token (exp set to 1 — Unix epoch)
    import time as _time
    pay_expired = dict(orig_pay)
    pay_expired['exp'] = 1
    cases.append({
        'name':        'Expired token (exp=1)',
        'class':       'CLAIMS',
        'description': 'exp claim set to 1 (1970-01-01). Acceptance means the '
                       'server does not validate token expiry.',
        'token':       _forge_token(_json.dumps(orig_hdr, separators=(',', ':')),
                                    _json.dumps(pay_expired, separators=(',', ':')),
                                    orig_sig),
        'risk':        'HIGH',
    })

    # Test 8: future iat (issued-at 10 years ahead)
    pay_future = dict(orig_pay)
    pay_future['iat'] = int(_time.time()) + 315360000   # +10 years
    cases.append({
        'name':        'Future iat (issued 10 years ahead)',
        'class':       'CLAIMS',
        'description': 'iat claim set 10 years in the future. '
                       'A strict server should reject tokens not yet valid.',
        'token':       _forge_token(_json.dumps(orig_hdr, separators=(',', ':')),
                                    _json.dumps(pay_future, separators=(',', ':')),
                                    orig_sig),
        'risk':        'LOW',
    })

    # Test 9: privilege escalation — elevate role to admin
    if 'role' in orig_pay or 'roles' in orig_pay or 'scope' in orig_pay:
        pay_priv = dict(orig_pay)
        if 'role' in pay_priv:
            pay_priv['role'] = 'admin'
        if 'roles' in pay_priv:
            pay_priv['roles'] = ['admin', 'superuser']
        if 'scope' in pay_priv:
            pay_priv['scope'] = 'admin read write delete'
        cases.append({
            'name':        'Privilege escalation (role→admin)',
            'class':       'CLAIMS',
            'description': 'role/scope claims changed to admin. If accepted with '
                           'original signature, the server does not verify claims '
                           'match the signature.',
            'token':       _forge_token(_json.dumps(orig_hdr, separators=(',', ':')),
                                        _json.dumps(pay_priv, separators=(',', ':')),
                                        orig_sig),
            'risk':        'CRITICAL',
        })

    # Test 10: sub manipulation (change subject to "admin" or "1")
    if 'sub' in orig_pay:
        pay_sub = dict(orig_pay)
        orig_sub = str(orig_pay['sub'])
        # If numeric ID, try 1 (common admin ID). If string, try "admin".
        pay_sub['sub'] = '1' if orig_sub.isdigit() else 'admin'
        cases.append({
            'name':        'sub manipulation ({} → {})'.format(orig_sub, pay_sub['sub']),
            'class':       'CLAIMS',
            'description': 'Subject claim changed. If accepted with original '
                           'signature, IDOR or privilege escalation is possible.',
            'token':       _forge_token(_json.dumps(orig_hdr, separators=(',', ':')),
                                        _json.dumps(pay_sub, separators=(',', ':')),
                                        orig_sig),
            'risk':        'CRITICAL',
        })

    # Test 11: no exp claim (remove expiry entirely)
    if 'exp' in orig_pay:
        pay_noexp = dict(orig_pay)
        del pay_noexp['exp']
        cases.append({
            'name':        'Missing exp claim',
            'class':       'CLAIMS',
            'description': 'exp claim removed entirely. Some libraries treat '
                           'a missing exp as "never expires".',
            'token':       _forge_token(_json.dumps(orig_hdr, separators=(',', ':')),
                                        _json.dumps(pay_noexp, separators=(',', ':')),
                                        orig_sig),
            'risk':        'MEDIUM',
        })

    # ── STRUCTURE tests ───────────────────────────────────────────────────

    # Test 12: extra dot (4 parts instead of 3)
    cases.append({
        'name':        'Extra dot (4-part token)',
        'class':       'STRUCTURE',
        'description': 'An extra dot appended. Tests robustness of the JWT parser '
                       'against malformed token structure.',
        'token':       token + '.',
        'risk':        'LOW',
    })

    # Test 13: truncated — only header.payload (no signature part)
    cases.append({
        'name':        'Truncated (header.payload only)',
        'class':       'STRUCTURE',
        'description': 'Signature segment missing entirely. '
                       'Tests whether the server requires all three parts.',
        'token':       '{}.{}'.format(parts[0], parts[1]),
        'risk':        'MEDIUM',
    })

    # Test 14: empty payload
    cases.append({
        'name':        'Empty payload ({})',
        'class':       'STRUCTURE',
        'description': 'Payload replaced with an empty JSON object. '
                       'Tests how the server handles a token with no claims.',
        'token':       _forge_token(_json.dumps(orig_hdr, separators=(',', ':')),
                                    '{}', orig_sig),
        'risk':        'LOW',
    })

    # ── INJECTION tests ───────────────────────────────────────────────────

    # Test 15: kid SQL injection
    inj_hdr = dict(orig_hdr)
    inj_hdr['kid'] = "' OR '1'='1"
    cases.append({
        'name':        'kid SQL injection',
        'class':       'INJECTION',
        'description': 'kid claim set to a classic SQL injection payload. '
                       'If the server uses kid to query a key database without '
                       'sanitisation, this may return the wrong key or bypass '
                       'verification.',
        'token':       _forge_token(_json.dumps(inj_hdr, separators=(',', ':')),
                                    _json.dumps(orig_pay, separators=(',', ':')),
                                    orig_sig),
        'risk':        'HIGH',
    })

    # Test 16: kid path traversal
    pt_hdr = dict(orig_hdr)
    pt_hdr['kid'] = '../../dev/null'
    cases.append({
        'name':        'kid path traversal (../../dev/null)',
        'class':       'INJECTION',
        'description': 'kid set to a path traversal string. If the server reads '
                       'the key from the filesystem using kid as a path, this '
                       'forces verification against /dev/null (empty key).',
        'token':       _forge_token(_json.dumps(pt_hdr, separators=(',', ':')),
                                    _json.dumps(orig_pay, separators=(',', ':')),
                                    orig_sig),
        'risk':        'HIGH',
    })

    # Test 17: jku header injection (SSRF — point to attacker-controlled URL)
    jku_hdr = dict(orig_hdr)
    jku_hdr['jku'] = 'https://attacker.example.com/jwks.json'
    cases.append({
        'name':        'jku SSRF (attacker JWKS URL)',
        'class':       'INJECTION',
        'description': 'jku (JWK Set URL) header added pointing to an attacker '
                       'URL. If the server fetches the key from jku without '
                       'pinning the domain, it will use the attacker key.',
        'token':       _forge_token(_json.dumps(jku_hdr, separators=(',', ':')),
                                    _json.dumps(orig_pay, separators=(',', ':')),
                                    orig_sig),
        'risk':        'CRITICAL',
    })

    # Test 18: x5u header injection (similar SSRF via certificate URL)
    x5u_hdr = dict(orig_hdr)
    x5u_hdr['x5u'] = 'https://attacker.example.com/cert.pem'
    cases.append({
        'name':        'x5u SSRF (attacker certificate URL)',
        'class':       'INJECTION',
        'description': 'x5u (X.509 certificate URL) header added. Same class '
                       'of attack as jku but via the certificate chain.',
        'token':       _forge_token(_json.dumps(x5u_hdr, separators=(',', ':')),
                                    _json.dumps(orig_pay, separators=(',', ':')),
                                    orig_sig),
        'risk':        'CRITICAL',
    })

    # Test 19: embedded JWK (attacker-supplied public key in header)
    jwk_hdr = dict(orig_hdr)
    jwk_hdr['jwk'] = {
        'kty': 'RSA', 'use': 'sig',
        'n': 'ATTACKER_PUBLIC_KEY_MODULUS',
        'e': 'AQAB'
    }
    cases.append({
        'name':        'Embedded JWK (self-signed)',
        'class':       'INJECTION',
        'description': 'jwk header added containing an attacker-controlled public '
                       'key. If the server trusts the embedded jwk without '
                       'pinning, the attacker can sign with their own key.',
        'token':       _forge_token(_json.dumps(jwk_hdr, separators=(',', ':')),
                                    _json.dumps(orig_pay, separators=(',', ':')),
                                    orig_sig),
        'risk':        'CRITICAL',
    })

    return cases


# ---------------------------------------------------------------------------
# Main extension class
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab, IHttpListener, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks        = callbacks
        self._helpers          = callbacks.getHelpers()
        self._findings         = []       # list of Finding objects
        self._lock             = threading.Lock()
        self._key_endpoints    = {}       # host -> URL for Key Flow correlation
        self._paused           = False
        self._statusLabel      = None
        self._selected_finding = None
        self._jwt_history      = []       # list of decoded JWT entry dicts
        self._audit_source_rr  = None     # IHttpRequestResponse for JWT audit replay
        self._audit_results    = []       # list of audit result dicts

        callbacks.setExtensionName("TokenHound")
        # All UI construction must happen on the Swing event dispatch thread.
        SwingUtilities.invokeLater(self._buildUI)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        print("[TokenHound] Loaded — {} patterns active".format(len(PATTERNS)))

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.add(self._buildHeader(), BorderLayout.NORTH)
        self._mainPanel.add(self._buildTabs(),   BorderLayout.CENTER)
        self._mainPanel.add(self._buildStatus(), BorderLayout.SOUTH)
        self._callbacks.addSuiteTab(self)
        self._updateStats()

    def _buildHeader(self):
        p = JPanel(BorderLayout())
        p.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
            EmptyBorder(5, 8, 5, 8)))

        left = JLabel("TokenHound  |  Secrets & Client-Side Crypto Detector")
        left.setFont(Font("Dialog", Font.BOLD, 13))
        p.add(left, BorderLayout.WEST)

        right = JPanel(FlowLayout(FlowLayout.RIGHT, 10, 0))
        right.setOpaque(False)

        self._lblCritical = JLabel("CRITICAL: 0")
        self._lblCritical.setFont(Font("Dialog", Font.BOLD, 11))
        self._lblCritical.setForeground(SEV_COLORS['CRITICAL'])
        self._lblHigh = JLabel("HIGH: 0")
        self._lblHigh.setFont(Font("Dialog", Font.BOLD, 11))
        self._lblHigh.setForeground(SEV_COLORS['HIGH'])
        self._lblMedium = JLabel("MEDIUM: 0")
        self._lblMedium.setFont(Font("Dialog", Font.BOLD, 11))
        self._lblMedium.setForeground(SEV_COLORS['MEDIUM'])
        self._lblLow = JLabel("LOW: 0")
        self._lblLow.setFont(Font("Dialog", Font.BOLD, 11))
        self._lblLow.setForeground(SEV_COLORS['LOW'])
        self._lblTotal = JLabel("Total: 0")
        self._lblTotal.setFont(Font("Dialog", Font.PLAIN, 11))

        scanBtn = JButton("Scan Proxy History")
        scanBtn.setFont(Font("Dialog", Font.PLAIN, 11))
        scanBtn.addActionListener(lambda e: self._scanProxyHistory())

        for w in [self._lblCritical, self._lblHigh, self._lblMedium,
                  self._lblLow, self._lblTotal, scanBtn]:
            right.add(w)
        p.add(right, BorderLayout.EAST)
        return p

    def _buildTabs(self):
        self._tabs = JTabbedPane()
        self._tabs.addTab("Findings",       self._buildFindingsTab())       # 0
        self._tabs.addTab("Key Flow",       self._buildKeyFlowTab())        # 1
        self._tabs.addTab("Request Detail", self._buildDetailTab())         # 2
        self._tabs.addTab("JWT Analyzer",   self._buildJWTTab())            # 3
        self._tabs.addTab("Payloads",       self._buildPayloadsTab())       # 4
        self._tabs.addTab("Configuration",  self._buildConfigTab())         # 5
        return self._tabs

    def _buildFindingsTab(self):
        outer = JPanel(BorderLayout())

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY))

        toolbar.add(JLabel("Severity:"))
        self._sevFilter = JComboBox(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self._sevFilter.setPreferredSize(Dimension(95, 22))
        toolbar.add(self._sevFilter)

        toolbar.add(JLabel("Category:"))
        self._catFilter = JComboBox(["ALL", "Asymmetric Key", "Symmetric Key",
                                     "Crypto Library", "Key Flow", "Hardcoded Secret"])
        self._catFilter.setPreferredSize(Dimension(130, 22))
        toolbar.add(self._catFilter)

        toolbar.add(JLabel("Confidence:"))
        self._confFilter = JComboBox(["ALL", "CONFIRMED", "LIKELY", "POSSIBLE", "UNLIKELY"])
        self._confFilter.setPreferredSize(Dimension(95, 22))
        toolbar.add(self._confFilter)

        toolbar.add(JLabel("Search:"))
        self._searchField = JTextField(14)
        toolbar.add(self._searchField)

        btnFilter = JButton("Apply Filter")
        btnFilter.addActionListener(lambda e: self._applyFilter())
        toolbar.add(btnFilter)

        btnClear = JButton("Clear All")
        btnClear.addActionListener(lambda e: self._clearFindings())
        toolbar.add(btnClear)

        btnExport = JButton("Export CSV")
        btnExport.addActionListener(lambda e: self._exportCSV())
        toolbar.add(btnExport)

        self._pauseBtn = JButton("Pause")
        self._pauseBtn.addActionListener(lambda e: self._togglePause())
        toolbar.add(self._pauseBtn)

        self._cbHideFP = JCheckBox("Hide FP")
        self._cbHideFP.setToolTipText("Hide findings you have marked as false positives")
        self._cbHideFP.addActionListener(lambda e: self._applyFilter())
        toolbar.add(self._cbHideFP)

        outer.add(toolbar, BorderLayout.NORTH)

        cols = ["#", "Time", "Severity", "Confidence", "Category",
                "Type", "Found In", "Method", "URL", "Evidence"]
        self._tableModel = NonEditableTableModel(cols, 0)
        self._table = JTable(self._tableModel)
        self._table.setRowHeight(20)
        self._table.setFont(Font("Dialog", Font.PLAIN, 11))
        self._table.getTableHeader().setFont(Font("Dialog", Font.BOLD, 11))
        self._table.setAutoCreateRowSorter(True)

        cm = self._table.getColumnModel()
        cm.getColumn(0).setMaxWidth(40)
        cm.getColumn(1).setMaxWidth(65)
        cm.getColumn(2).setMaxWidth(80)
        cm.getColumn(3).setMaxWidth(90)
        cm.getColumn(4).setMaxWidth(125)
        cm.getColumn(5).setPreferredWidth(185)
        cm.getColumn(6).setMaxWidth(75)
        cm.getColumn(7).setMaxWidth(55)
        cm.getColumn(8).setPreferredWidth(240)
        cm.getColumn(9).setPreferredWidth(200)

        cm.getColumn(2).setCellRenderer(SeverityCellRenderer())
        cm.getColumn(3).setCellRenderer(ConfidenceCellRenderer())

        extRef = self
        class TableMouse(MouseAdapter):
            def mouseClicked(self, e):
                row = extRef._table.rowAtPoint(e.getPoint())
                if row < 0: return
                extRef._table.setRowSelectionInterval(row, row)
                model_row = extRef._table.convertRowIndexToModel(row)
                extRef._selected_finding = extRef._findingForRow(model_row)
                if e.getButton() == 3:
                    extRef._showContextMenu(e, extRef._selected_finding)
                else:
                    extRef._showDetail(extRef._selected_finding)
                    extRef._tabs.setSelectedIndex(2)
        self._table.addMouseListener(TableMouse())

        outer.add(JScrollPane(self._table), BorderLayout.CENTER)
        return outer

    def _buildKeyFlowTab(self):
        p = JPanel(BorderLayout())
        p.setBorder(EmptyBorder(8, 8, 8, 8))

        info = JLabel(
            "<html><b>Key Flow Tracker</b> — correlates public-key fetches "
            "with encrypted POST requests on the same host</html>")
        info.setBorder(EmptyBorder(0, 0, 6, 0))
        p.add(info, BorderLayout.NORTH)

        self._keyFlowModel = NonEditableTableModel(
            ["Key Endpoint", "Key Type", "Consumer Endpoint", "Method", "Status", "Time"], 0)
        self._keyFlowTable = JTable(self._keyFlowModel)
        self._keyFlowTable.setRowHeight(20)
        self._keyFlowTable.setFont(Font("Dialog", Font.PLAIN, 11))
        self._keyFlowTable.getTableHeader().setFont(Font("Dialog", Font.BOLD, 11))
        self._keyFlowTable.setAutoCreateRowSorter(True)
        p.add(JScrollPane(self._keyFlowTable), BorderLayout.CENTER)

        note = JLabel(
            "CONFIRMED = large base64 POST seen from a host that previously served a public key.")
        note.setFont(Font("Dialog", Font.ITALIC, 10))
        note.setBorder(EmptyBorder(5, 0, 0, 0))
        p.add(note, BorderLayout.SOUTH)
        return p

    def _buildDetailTab(self):
        p = JPanel(BorderLayout())

        # Metadata grid: 5 rows x 4 cols (label + value pairs).
        self._detailHeader = JPanel(GridLayout(5, 4, 4, 2))
        self._detailHeader.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
            EmptyBorder(6, 8, 6, 8)))

        self._detailLabels = {}
        for field in ["Type", "Severity", "Confidence", "Score",
                      "Category", "URL", "Method", "Time",
                      "Pattern matched", "Evidence"]:
            k = JLabel(field + ":")
            k.setFont(Font("Dialog", Font.BOLD, 11))
            v = JLabel("-")
            v.setFont(Font("Dialog", Font.PLAIN, 11))
            self._detailHeader.add(k)
            self._detailHeader.add(v)
            self._detailLabels[field] = v

        btnRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        btnRow.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY))
        b1 = JButton("Send to Repeater")
        b1.addActionListener(lambda e: self._sendToRepeater())
        btnRow.add(b1)
        b2 = JButton("Send to Intruder")
        b2.addActionListener(lambda e: self._sendToIntruder())
        btnRow.add(b2)
        b3 = JButton("Highlight in Proxy")
        b3.addActionListener(lambda e: self._highlightInProxy())
        btnRow.add(b3)
        b4 = JButton("Send JWT to Analyzer")
        b4.addActionListener(lambda e: self._sendJWTFromDetail())
        btnRow.add(b4)

        top = JPanel(BorderLayout())
        top.add(self._detailHeader, BorderLayout.CENTER)
        top.add(btnRow, BorderLayout.SOUTH)
        p.add(top, BorderLayout.NORTH)

        self._requestArea  = JTextArea()
        self._requestArea.setEditable(False)
        self._requestArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        # setEditable(False) still allows text selection and Ctrl+C.
        # We add an explicit context menu so right-click > Copy also works.
        self._requestArea.addMouseListener(self._makeTextAreaCopyMenu(lambda: self._requestArea))
        self._responseArea = JTextArea()
        self._responseArea.setEditable(False)
        self._responseArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._responseArea.addMouseListener(self._makeTextAreaCopyMenu(lambda: self._responseArea))

        reqScroll = JScrollPane(self._requestArea)
        reqScroll.setBorder(BorderFactory.createTitledBorder("Request"))
        resScroll = JScrollPane(self._responseArea)
        resScroll.setBorder(BorderFactory.createTitledBorder(
            "Response  (yellow highlight = matched evidence)"))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, reqScroll, resScroll)
        split.setResizeWeight(0.4)
        split.setDividerSize(5)
        p.add(split, BorderLayout.CENTER)
        return p

    def _buildJWTTab(self):
        """
        Layout (top to bottom):
          [token input bar]
          [claims strip  — one inline row of field:value pairs]
          [header pane | payload pane | signature pane]
          [security warnings table]
          [JWT history table]
        """
        p = JPanel(BorderLayout(0, 4))
        p.setBorder(EmptyBorder(6, 6, 6, 6))

        inputPanel = JPanel(BorderLayout(6, 0))
        inputPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Paste JWT Token"),
            EmptyBorder(3, 4, 3, 4)))

        self._jwtInput = JTextField()
        self._jwtInput.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._jwtInput.setToolTipText("Paste eyJ... token or click a row in JWT History")

        btnDecode = JButton("Decode & Analyze")
        btnDecode.addActionListener(lambda e: self._decodeJWT())
        btnClear = JButton("Clear")
        btnClear.addActionListener(lambda e: self._clearJWT())
        btnCopyJwt = JButton("Copy Token")
        btnCopyJwt.addActionListener(
            lambda e: self._copyToClipboard(self._jwtInput.getText().strip()))

        btnRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        btnRow.setOpaque(False)
        btnRow.add(btnDecode)
        btnRow.add(btnClear)
        btnRow.add(btnCopyJwt)

        inputPanel.add(self._jwtInput, BorderLayout.CENTER)
        inputPanel.add(btnRow,         BorderLayout.EAST)
        p.add(inputPanel, BorderLayout.NORTH)

        # Claims strip.
        claimsStrip = JPanel(FlowLayout(FlowLayout.LEFT, 16, 2))
        claimsStrip.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Decoded Claims"),
            EmptyBorder(2, 4, 2, 4)))
        self._jwtClaimLabels = {}
        for field in ['alg', 'sub', 'iss', 'exp', 'iat', 'role', 'scope', 'email']:
            lk = JLabel(field + ":")
            lk.setFont(Font("Dialog", Font.BOLD, 11))
            lv = JLabel("-")
            lv.setFont(Font("Monospaced", Font.PLAIN, 11))
            lv.setForeground(Color(30, 100, 200))
            claimsStrip.add(lk)
            claimsStrip.add(lv)
            self._jwtClaimLabels[field] = lv

        # Three decoded panes side by side.
        self._jwtHeaderArea  = JTextArea()
        self._jwtHeaderArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._jwtHeaderArea.setEditable(False)
        self._jwtHeaderArea.setLineWrap(True)

        self._jwtPayloadArea = JTextArea()
        self._jwtPayloadArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._jwtPayloadArea.setEditable(False)
        self._jwtPayloadArea.setLineWrap(True)

        self._jwtSigArea = JTextArea()
        self._jwtSigArea.setFont(Font("Monospaced", Font.PLAIN, 10))
        self._jwtSigArea.setEditable(False)
        self._jwtSigArea.setLineWrap(True)
        self._jwtSigArea.setForeground(Color(100, 100, 100))

        hdrScroll = JScrollPane(self._jwtHeaderArea)
        hdrScroll.setBorder(BorderFactory.createTitledBorder("Header (JSON)"))
        payScroll = JScrollPane(self._jwtPayloadArea)
        payScroll.setBorder(BorderFactory.createTitledBorder("Payload (claims)"))
        sigScroll = JScrollPane(self._jwtSigArea)
        sigScroll.setBorder(BorderFactory.createTitledBorder("Signature"))

        hdrPaySplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, hdrScroll, payScroll)
        hdrPaySplit.setResizeWeight(0.35)
        hdrPaySplit.setDividerSize(4)
        decodedSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, hdrPaySplit, sigScroll)
        decodedSplit.setResizeWeight(0.72)
        decodedSplit.setDividerSize(4)

        # Security warnings table.
        self._jwtWarningsModel = NonEditableTableModel(["Sev", "Security Finding"], 0)
        self._jwtWarningsTable = JTable(self._jwtWarningsModel)
        self._jwtWarningsTable.setRowHeight(19)
        self._jwtWarningsTable.setFont(Font("Dialog", Font.PLAIN, 11))
        self._jwtWarningsTable.getTableHeader().setFont(Font("Dialog", Font.BOLD, 11))
        self._jwtWarningsTable.getColumnModel().getColumn(0).setMaxWidth(65)
        self._jwtWarningsTable.getColumnModel().getColumn(0).setCellRenderer(SeverityCellRenderer())
        self._jwtWarningsTable.getColumnModel().getColumn(1).setPreferredWidth(600)
        warnScroll = JScrollPane(self._jwtWarningsTable)
        warnScroll.setBorder(BorderFactory.createTitledBorder("Security Analysis"))
        warnScroll.setPreferredSize(Dimension(0, 130))

        centerPanel = JPanel(BorderLayout(0, 4))
        centerPanel.add(claimsStrip,  BorderLayout.NORTH)
        centerPanel.add(decodedSplit, BorderLayout.CENTER)
        centerPanel.add(warnScroll,   BorderLayout.SOUTH)

        # JWT history: auto-populated as tokens are seen in traffic.
        self._jwtHistModel = NonEditableTableModel(
            ["Time", "Source", "URL", "alg", "sub", "role", "exp", "Warnings"], 0)
        self._jwtHistTable = JTable(self._jwtHistModel)
        self._jwtHistTable.setRowHeight(18)
        self._jwtHistTable.setFont(Font("Dialog", Font.PLAIN, 10))
        self._jwtHistTable.getTableHeader().setFont(Font("Dialog", Font.BOLD, 10))
        self._jwtHistTable.setAutoCreateRowSorter(True)
        self._jwtHistTable.getColumnModel().getColumn(0).setMaxWidth(60)
        self._jwtHistTable.getColumnModel().getColumn(1).setMaxWidth(100)
        self._jwtHistTable.getColumnModel().getColumn(3).setMaxWidth(70)
        self._jwtHistTable.getColumnModel().getColumn(7).setMaxWidth(100)

        extRef = self
        class JWTHistMouse(MouseAdapter):
            def mouseClicked(self, e):
                row = extRef._jwtHistTable.rowAtPoint(e.getPoint())
                if row < 0: return
                mr = extRef._jwtHistTable.convertRowIndexToModel(row)
                if mr < len(extRef._jwt_history):
                    extRef._jwtInput.setText(extRef._jwt_history[mr]['token'])
                    extRef._decodeJWT()
        self._jwtHistTable.addMouseListener(JWTHistMouse())

        histScroll = JScrollPane(self._jwtHistTable)
        histScroll.setBorder(BorderFactory.createTitledBorder(
            "JWT History  (auto-captured from traffic — click row to analyze)"))
        histScroll.setPreferredSize(Dimension(0, 140))

        mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, centerPanel, histScroll)
        mainSplit.setResizeWeight(0.68)
        mainSplit.setDividerSize(5)
        p.add(mainSplit, BorderLayout.CENTER)
        return p

    # -----------------------------------------------------------------------
    # Payloads tab — home for active testing tools (JWT Auditor + future modules)
    # -----------------------------------------------------------------------

    def _buildPayloadsTab(self):
        """
        Top-level Payloads tab. Currently holds only the JWT Auditor subtab.
        Future subtabs (header injection, CORS, etc.) slot in here without
        touching the rest of the UI.
        """
        p = JPanel(BorderLayout())
        inner = JTabbedPane()
        inner.addTab("JWT Auditor", self._buildJWTAuditorTab())
        p.add(inner, BorderLayout.CENTER)
        return p

    def _buildJWTAuditorTab(self):
        """
        JWT Auditor layout:
          [target config: URL + header name]
          [Run Audit button + progress label]
          [results table: Name | Class | Risk | Status | Response Code | Notes]
          [detail pane: payload sent + raw response]

        The auditor takes the token from the JWT Analyzer input field,
        generates test cases from _build_jwt_test_cases(), and replays the
        original captured request once per test case with the mutated token
        substituted into the Authorization: Bearer header (or a custom header).
        """
        p = JPanel(BorderLayout(0, 4))
        p.setBorder(EmptyBorder(6, 6, 6, 6))

        # ── Target config bar ────────────────────────────────────────────
        cfgPanel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        cfgPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Target (taken from captured request — override if needed)"),
            EmptyBorder(2, 4, 2, 4)))

        cfgPanel.add(JLabel("URL:"))
        self._auditUrl = JTextField(35)
        self._auditUrl.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._auditUrl.setToolTipText(
            "Full URL to test. Auto-filled when you use 'Send JWT to Analyzer' "
            "from a finding. Edit if needed.")
        cfgPanel.add(self._auditUrl)

        cfgPanel.add(JLabel("Token header:"))
        self._auditHeader = JTextField("Authorization", 14)
        self._auditHeader.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._auditHeader.setToolTipText(
            "Header name that carries the JWT. Usually 'Authorization'. "
            "Change to 'X-Auth-Token' etc. if needed.")
        cfgPanel.add(self._auditHeader)

        cfgPanel.add(JLabel("Header value prefix:"))
        self._auditPrefix = JTextField("Bearer ", 8)
        self._auditPrefix.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._auditPrefix.setToolTipText(
            "Text that comes before the token in the header. "
            "Usually 'Bearer ' (with trailing space). Leave blank for raw token.")
        cfgPanel.add(self._auditPrefix)

        p.add(cfgPanel, BorderLayout.NORTH)

        # ── Audit control bar ─────────────────────────────────────────────
        ctrlBar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        ctrlBar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY))

        btnRun = JButton("Run Audit")
        btnRun.setFont(Font("Dialog", Font.BOLD, 11))
        btnRun.setToolTipText(
            "Generate test payloads from the current JWT Analyzer token and "
            "replay the request once per test case. "
            "WARNING: each test sends a real HTTP request. Do NOT run on "
            "endpoints with account lockout or rate limiting without first "
            "checking with the target team.")
        btnRun.addActionListener(lambda e: self._runJWTAudit())
        ctrlBar.add(btnRun)

        btnClear = JButton("Clear Results")
        btnClear.addActionListener(lambda e: self._auditResultsModel.setRowCount(0))
        ctrlBar.add(btnClear)

        btnExport = JButton("Export Results")
        btnExport.addActionListener(lambda e: self._exportAuditResults())
        ctrlBar.add(btnExport)

        self._auditStatusLabel = JLabel("No audit run yet.")
        self._auditStatusLabel.setFont(Font("Dialog", Font.ITALIC, 11))
        self._auditStatusLabel.setForeground(Color(80, 80, 80))
        ctrlBar.add(self._auditStatusLabel)

        # ── Results table ─────────────────────────────────────────────────
        cols = ["#", "Test Name", "Class", "Risk", "Status", "HTTP", "Notes"]
        self._auditResultsModel = NonEditableTableModel(cols, 0)
        self._auditResultsTable = JTable(self._auditResultsModel)
        self._auditResultsTable.setRowHeight(20)
        self._auditResultsTable.setFont(Font("Dialog", Font.PLAIN, 11))
        self._auditResultsTable.getTableHeader().setFont(Font("Dialog", Font.BOLD, 11))
        self._auditResultsTable.setAutoCreateRowSorter(True)

        acm = self._auditResultsTable.getColumnModel()
        acm.getColumn(0).setMaxWidth(35)
        acm.getColumn(2).setMaxWidth(90)
        acm.getColumn(3).setMaxWidth(75)
        acm.getColumn(4).setMaxWidth(90)
        acm.getColumn(5).setMaxWidth(55)
        acm.getColumn(1).setPreferredWidth(230)
        acm.getColumn(6).setPreferredWidth(300)

        acm.getColumn(3).setCellRenderer(SeverityCellRenderer())
        acm.getColumn(4).setCellRenderer(AuditStatusCellRenderer())

        # ── Detail pane ───────────────────────────────────────────────────
        self._auditPayloadArea = JTextArea()
        self._auditPayloadArea.setFont(Font("Monospaced", Font.PLAIN, 10))
        self._auditPayloadArea.setEditable(False)
        self._auditPayloadArea.setLineWrap(True)
        self._auditPayloadArea.addMouseListener(
            self._makeTextAreaCopyMenu(lambda: self._auditPayloadArea))

        self._auditResponseArea = JTextArea()
        self._auditResponseArea.setFont(Font("Monospaced", Font.PLAIN, 10))
        self._auditResponseArea.setEditable(False)
        self._auditResponseArea.setLineWrap(True)
        self._auditResponseArea.addMouseListener(
            self._makeTextAreaCopyMenu(lambda: self._auditResponseArea))

        payScroll = JScrollPane(self._auditPayloadArea)
        payScroll.setBorder(BorderFactory.createTitledBorder("Mutated Token Sent"))
        resScroll = JScrollPane(self._auditResponseArea)
        resScroll.setBorder(BorderFactory.createTitledBorder("Server Response"))

        detailSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, payScroll, resScroll)
        detailSplit.setResizeWeight(0.4)
        detailSplit.setDividerSize(4)
        detailSplit.setPreferredSize(Dimension(0, 180))

        # Click a result row to see the payload and response
        extRef = self
        class AuditTableMouse(MouseAdapter):
            def mouseClicked(self, e):
                row = extRef._auditResultsTable.rowAtPoint(e.getPoint())
                if row < 0: return
                mr = extRef._auditResultsTable.convertRowIndexToModel(row)
                if mr < len(extRef._audit_results):
                    r = extRef._audit_results[mr]
                    extRef._auditPayloadArea.setText(r.get('token', ''))
                    extRef._auditPayloadArea.setCaretPosition(0)
                    extRef._auditResponseArea.setText(r.get('response_raw', ''))
                    extRef._auditResponseArea.setCaretPosition(0)
        self._auditResultsTable.addMouseListener(AuditTableMouse())

        # Store raw results for detail pane
        self._audit_results = []

        tableScroll = JScrollPane(self._auditResultsTable)
        tableScroll.setBorder(BorderFactory.createTitledBorder(
            "Audit Results  (click a row to see the token and response)"))

        mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailSplit)
        mainSplit.setResizeWeight(0.70)
        mainSplit.setDividerSize(5)

        center = JPanel(BorderLayout(0, 4))
        center.add(ctrlBar,    BorderLayout.NORTH)
        center.add(mainSplit,  BorderLayout.CENTER)
        p.add(center, BorderLayout.CENTER)

        # Warning label at bottom
        warn = JLabel(
            "<html><b>Warning:</b> Each test sends a real HTTP request. "
            "Use only on authorised targets. Be cautious on endpoints with "
            "account lockout or rate limiting.</html>")
        warn.setFont(Font("Dialog", Font.PLAIN, 10))
        warn.setForeground(Color(160, 80, 0))
        warn.setBorder(EmptyBorder(4, 4, 2, 4))
        p.add(warn, BorderLayout.SOUTH)
        return p

    def _buildConfigTab(self):
        p = JPanel(BorderLayout())
        p.setBorder(EmptyBorder(12, 16, 12, 16))

        grid = JPanel(GridBagLayout())
        grid.setOpaque(False)
        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(3, 0, 3, 12)
        row = [0]

        def section(title):
            gbc.gridx = 0; gbc.gridy = row[0]; gbc.gridwidth = 2
            lbl = JLabel(title)
            lbl.setFont(Font("Dialog", Font.BOLD, 12))
            lbl.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                EmptyBorder(6, 0, 2, 0)))
            grid.add(lbl, gbc)
            gbc.gridwidth = 1
            row[0] += 1

        def cb(label, default=True):
            gbc.gridx = 0; gbc.gridy = row[0]
            c = JCheckBox(label)
            c.setSelected(default)
            c.setOpaque(False)
            grid.add(c, gbc)
            row[0] += 1
            return c

        section("Detection Modules")
        self._cbAsymmetric   = cb("Asymmetric Keys (RSA, EC PEM, obfuscated)", True)
        self._cbSymmetric    = cb("Symmetric Keys (AES, CryptoJS, createSecretKey)", True)
        self._cbCryptoLibs   = cb("Crypto Library (JSEncrypt, SubtleCrypto, eval/atob, Web Storage)", True)
        self._cbKeyFlow      = cb("Key Flow (public-key endpoint + encrypted POST correlation)", True)
        self._cbHardcoded    = cb("Hardcoded Secrets (40+ token formats)", True)
        self._cbJWT          = cb("JWT (auto-capture + alg:none / kid injection / privilege checks)", True)

        section("Scope & Noise Reduction")
        self._cbInScope      = cb("Only scan in-scope targets", False)
        self._cbSkipStatic   = cb("Skip static files (.png .jpg .gif .woff .ttf .pdf)", True)
        self._cbSkipUnlikely = cb("Hide UNLIKELY confidence findings from table", False)

        section("Severity to log")
        self._cbCritical     = cb("CRITICAL", True)
        self._cbHigh         = cb("HIGH", True)
        self._cbMedium       = cb("MEDIUM", True)
        self._cbLow          = cb("LOW", True)
        self._cbInfo         = cb("INFO", False)

        section("Output")
        self._cbHighlight    = cb("Auto-highlight matched requests in Proxy history", True)

        # Raise this to reduce false positives; lower it to catch weaker secrets.
        gbc.gridx = 0; gbc.gridy = row[0]
        grid.add(JLabel("Min entropy for secret detection (bits/char):"), gbc)
        gbc.gridx = 1
        self._entropySpinner = JSpinner(SpinnerNumberModel(3.5, 1.0, 5.0, 0.1))
        self._entropySpinner.setPreferredSize(Dimension(70, 22))
        grid.add(self._entropySpinner, gbc)
        row[0] += 1

        p.add(JScrollPane(grid), BorderLayout.CENTER)
        return p

    def _buildStatus(self):
        bar = JPanel(BorderLayout())
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY),
            EmptyBorder(3, 8, 3, 8)))
        self._statusLabel = JLabel("Ready")
        self._statusLabel.setFont(Font("Dialog", Font.PLAIN, 11))
        bar.add(self._statusLabel, BorderLayout.WEST)
        ver = JLabel("TokenHound  |  {} patterns".format(len(PATTERNS)))
        ver.setFont(Font("Dialog", Font.PLAIN, 11))
        bar.add(ver, BorderLayout.EAST)
        return bar

    # -----------------------------------------------------------------------
    # ITab
    # -----------------------------------------------------------------------

    def getTabCaption(self):  return "TokenHound"
    def getUiComponent(self): return self._mainPanel

    # -----------------------------------------------------------------------
    # IHttpListener — called by Burp for every proxied message
    # -----------------------------------------------------------------------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self._paused:
            return
        try:
            req_info = self._helpers.analyzeRequest(messageInfo)
            url      = str(req_info.getUrl())
            method   = req_info.getMethod()

            if self._cbInScope.isSelected():
                if not self._callbacks.isInScope(req_info.getUrl()):
                    return

            if self._cbSkipStatic.isSelected():
                path = url.lower().split('?')[0]
                if any(path.endswith(x) for x in
                       ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff',
                        '.woff2', '.ttf', '.eot', '.svg', '.css', '.pdf',
                        '.mp4', '.webp', '.avif', '.mp3', '.zip', '.gz']):
                    return

            if messageIsRequest:
                self._scanRequest(messageInfo, url, method)
            else:
                self._scanResponse(messageInfo, url, method)
        except Exception as ex:
            print("[TokenHound] processHttpMessage error: " + str(ex))

    # -----------------------------------------------------------------------
    # Retroactive proxy history scan
    # -----------------------------------------------------------------------

    def _scanProxyHistory(self):
        def _do():
            try:
                history = self._callbacks.getProxyHistory()
                total   = len(history)
                self._updateStatus("Scanning proxy history ({} items)...".format(total))
                for i, item in enumerate(history):
                    try:
                        req_info = self._helpers.analyzeRequest(item)
                        url      = str(req_info.getUrl())
                        method   = req_info.getMethod()
                        path     = url.lower().split('?')[0]
                        if any(path.endswith(x) for x in
                               ['.png', '.jpg', '.jpeg', '.gif', '.ico',
                                '.woff', '.woff2', '.ttf', '.eot', '.svg',
                                '.css', '.pdf']):
                            continue
                        self._scanRequest(item, url, method)
                        self._scanResponse(item, url, method)
                    except Exception:
                        pass
                    if (i + 1) % 50 == 0:
                        self._updateStatus(
                            "History scan: {}/{} done...".format(i + 1, total))
                self._updateStatus(
                    "History scan complete — {} items processed.".format(total))
            except Exception as ex:
                self._updateStatus("History scan error: " + str(ex))

        t = threading.Thread(target=_do)
        t.setDaemon(True)
        t.start()

    # -----------------------------------------------------------------------
    # Request scanning
    # -----------------------------------------------------------------------

    def _scanRequest(self, msgInfo, url, method):
        try:
            req      = self._helpers.bytesToString(msgInfo.getRequest())
            analyzed = self._helpers.analyzeRequest(msgInfo)
            body     = req[analyzed.getBodyOffset():]
            headers  = req[:analyzed.getBodyOffset()]

            # Capture JWTs from Authorization: Bearer headers for the JWT history
            # tab. Not flagged as findings on their own — only if they have issues.
            if self._cbJWT.isSelected():
                bearer_m = re.search(
                    r'Authorization\s*:\s*Bearer\s+'
                    r'(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)',
                    headers, re.IGNORECASE)
                if bearer_m:
                    self._captureJWT(bearer_m.group(1), url, 'Request Bearer')

            # Encrypted payload: a POST body that is entirely base64 (>200 chars)
            # suggests the browser encrypted the data before sending.
            if method == 'POST' and self._cbKeyFlow.isSelected():
                stripped = body.strip()
                if len(stripped) > 200 and re.match(r'^[A-Za-z0-9+/=]{200,}$', stripped):
                    f = Finding(url, method, 'Key Flow',
                                'Encrypted Payload (base64 blob POST)',
                                'HIGH', stripped[:80] + '...', msgInfo,
                                found_in='request')
                    conf, cs, cr = _score_confidence(
                        f, '', url, stripped,
                        float(self._entropySpinner.getValue()))
                    f.confidence = conf; f.confidence_score = cs
                    f.confidence_reasons = cr
                    self._addFinding(f)
                    host = self._hostOf(url)
                    if host in self._key_endpoints:
                        self._recordKeyFlow(
                            self._key_endpoints[host], url, method, 'CONFIRMED')

            # Scan for hardcoded secrets but strip the legitimate Bearer token
            # that is present on every authenticated request.
            if self._cbHardcoded.isSelected():
                req_no_auth = re.sub(
                    r'Authorization\s*:\s*Bearer\s+'
                    r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
                    'Authorization: Bearer [SUPPRESSED]',
                    req, flags=re.IGNORECASE)
                self._runPatterns(
                    req_no_auth, 'Hardcoded Secret', url, method, msgInfo,
                    found_in='request')

        except Exception as ex:
            print("[TokenHound] scanRequest error: " + str(ex))

    # -----------------------------------------------------------------------
    # Response scanning
    # -----------------------------------------------------------------------

    def _scanResponse(self, msgInfo, url, method):
        try:
            resp = self._helpers.bytesToString(msgInfo.getResponse())
            if not resp:
                return

            analyzed     = self._helpers.analyzeResponse(resp)
            body         = resp[analyzed.getBodyOffset():]
            content_type = ''
            for h in analyzed.getHeaders():
                if 'content-type' in str(h).lower():
                    content_type = str(h).lower()

            # Skip binary responses — regex on binary data produces noise.
            BINARY_TYPES = ['image/', 'audio/', 'video/',
                            'application/octet-stream', 'application/pdf',
                            'application/zip', 'font/']
            body_start = body[:20].strip() if body else ''
            is_binary  = (body_start.startswith('/9j/') or
                          body_start.startswith('iVBOR') or
                          body_start.startswith('JVBER') or
                          '\x00' in body[:100])
            if is_binary or any(bt in content_type for bt in BINARY_TYPES):
                return

            is_code = any(ct in content_type for ct in
                          ['javascript', 'json', 'text/html', 'text/css',
                           'x-www', 'ecmascript'])
            if not content_type:
                is_code = True

            # Capture JWTs issued in response bodies (login / token refresh).
            if self._cbJWT.isSelected():
                for jwt_m in re.finditer(
                    r'"(?:token|access_token|id_token|refresh_token)"\s*:\s*'
                    r'"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"',
                    body):
                    self._captureJWT(jwt_m.group(1), url, 'Response Issued')

            # Key Flow: record this host if the URL looks like a key distribution
            # endpoint so we can correlate with POST requests later.
            if self._cbKeyFlow.isSelected():
                if re.search(
                    r'/(?:encryption|crypto|security|api|v\d+)/'
                    r'(?:public-?key|pubkey|keys?|rsa)',
                    url, re.IGNORECASE):
                    host = self._hostOf(url)
                    self._key_endpoints[host] = url
                    kf = Finding(url, method, 'Key Flow',
                                 'Public Key Distribution Endpoint',
                                 'HIGH', url, msgInfo, found_in='response')
                    kf.confidence = 'CONFIRMED'
                    kf.confidence_score = 90
                    kf.confidence_reasons = ['URL matches public-key endpoint pattern']
                    self._addFinding(kf)

            cats = {
                'Asymmetric Key':   self._cbAsymmetric.isSelected(),
                'Symmetric Key':    self._cbSymmetric.isSelected(),
                'Crypto Library':   self._cbCryptoLibs.isSelected() and is_code,
                'Key Flow':         self._cbKeyFlow.isSelected(),
                'Hardcoded Secret': self._cbHardcoded.isSelected(),
            }
            for cat, enabled in cats.items():
                if enabled:
                    self._runPatterns(resp, cat, url, method, msgInfo,
                                      content_type=content_type,
                                      full_response=resp,
                                      found_in='response')

        except Exception as ex:
            print("[TokenHound] scanResponse error: " + str(ex))

    # -----------------------------------------------------------------------
    # Pattern runner
    # -----------------------------------------------------------------------

    def _runPatterns(self, content, category, url, method, msgInfo,
                     content_type='', full_response='', found_in='response'):
        """
        For each pattern in PATTERNS that belongs to 'category':
          1. Run re.search() against content.
          2. If matched, call the validator (if any). Suppress on False.
          3. Score the surviving match and create a Finding.
          4. Dedup by (url, label) within this scan pass.
        """
        seen = set()
        entropy_thresh = float(self._entropySpinner.getValue()) \
            if hasattr(self, '_entropySpinner') else 3.5

        sev_enabled = {
            'CRITICAL': self._cbCritical.isSelected(),
            'HIGH':     self._cbHigh.isSelected(),
            'MEDIUM':   self._cbMedium.isSelected(),
            'LOW':      self._cbLow.isSelected(),
            'INFO':     self._cbInfo.isSelected(),
        }

        for (cat, pattern, label, severity, validator_fn) in PATTERNS:
            if cat != category:
                continue
            if not sev_enabled.get(severity, True):
                continue
            try:
                m = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
                if not m:
                    continue

                if validator_fn is not None:
                    try:
                        if not validator_fn(m, content):
                            continue
                    except Exception:
                        pass

                key = (url, label)
                if key in seen:
                    continue
                seen.add(key)

                evidence = m.group(0)[:300]
                f = Finding(url, method, category, label, severity,
                            evidence, msgInfo,
                            match_start=m.start(), match_end=m.end(),
                            found_in=found_in)
                conf, cs, cr = _score_confidence(
                    f, content_type, url, full_response or content, entropy_thresh)
                f.confidence = conf
                f.confidence_score = cs
                f.confidence_reasons = cr

                if (hasattr(self, '_cbSkipUnlikely') and
                        self._cbSkipUnlikely.isSelected() and conf == 'UNLIKELY'):
                    continue

                self._addFinding(f)

            except Exception:
                pass

    # -----------------------------------------------------------------------
    # JWT capture and analysis
    # -----------------------------------------------------------------------

    def _captureJWT(self, token, url, source):
        """
        Called when a JWT is seen in traffic. Deduplicates by token value,
        decodes it, and adds a row to the JWT history table. CRITICAL/HIGH
        warnings are promoted to standalone findings in the main tab.
        """
        with self._lock:
            for existing in self._jwt_history:
                if existing['token'] == token:
                    return
        decoded = _decode_jwt(token)
        entry = {
            'token':    token,
            'url':      url,
            'source':   source,
            'time':     datetime.now().strftime('%H:%M:%S'),
            'alg':      decoded['alg'],
            'sub':      decoded['claims'].get('sub', '-'),
            'role':     decoded['claims'].get('role', '-'),
            'exp':      decoded['claims'].get('exp', '-'),
            'warnings': decoded['warnings'],
        }
        with self._lock:
            self._jwt_history.append(entry)

        for w in decoded['warnings']:
            if w.startswith('CRITICAL') or w.startswith('HIGH'):
                sev = 'CRITICAL' if w.startswith('CRITICAL') else 'HIGH'
                f = Finding(url, 'JWT', 'Hardcoded Secret',
                            'JWT Issue: ' + w[:80], sev, token[:120], None)
                f.confidence = 'CONFIRMED'
                f.confidence_score = 95
                f.confidence_reasons = ['JWT decoded; issue confirmed by analysis']
                self._addFinding(f)

        def _ui():
            self._jwtHistModel.addRow([
                entry['time'], source, url[:50], entry['alg'],
                entry['sub'][:20], entry['role'][:20], entry['exp'],
                '{} warning(s)'.format(len(decoded['warnings']))
            ])
        SwingUtilities.invokeLater(_ui)

    def _decodeJWT(self):
        """Decode the token in the input field and populate all JWT tab widgets."""
        token = self._jwtInput.getText().strip()
        if not token:
            return
        # Allow pasting "Bearer eyJ..." — extract just the token.
        m = re.search(
            r'(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)',
            token)
        if m:
            token = m.group(1)
            self._jwtInput.setText(token)

        decoded = _decode_jwt(token)

        def _pretty(raw):
            try:
                import json as _json
                return _json.dumps(_json.loads(raw), indent=2)
            except Exception:
                return raw

        self._jwtHeaderArea.setText(_pretty(decoded['header_json']))
        self._jwtPayloadArea.setText(_pretty(decoded['payload_json']))
        self._jwtSigArea.setText(
            decoded['signature_raw'] if decoded['signature_raw']
            else '(empty — unsigned token!)')

        # Update claims strip. Colour-code alg by risk level.
        for field in self._jwtClaimLabels:
            val = decoded['claims'].get(field, decoded.get(field, ''))
            lbl = self._jwtClaimLabels[field]
            lbl.setText(str(val) if val else '-')
            if field == 'alg':
                alg_upper = str(val).upper() if val else ''
                if alg_upper == 'NONE' or not val:
                    lbl.setForeground(SEV_COLORS['CRITICAL'])
                elif alg_upper.startswith('HS'):
                    lbl.setForeground(SEV_COLORS['MEDIUM'])
                elif alg_upper.startswith(('RS', 'ES', 'PS')):
                    lbl.setForeground(SEV_COLORS['LOW'])
                else:
                    lbl.setForeground(Color(30, 100, 200))

        # Strip "SEVERITY: " prefix from warning text — severity is in its own column.
        self._jwtWarningsModel.setRowCount(0)
        for w in decoded['warnings']:
            sev = 'INFO'
            display_w = w
            for prefix in ('CRITICAL: ', 'HIGH: ', 'MEDIUM: ', 'LOW: ', 'INFO: '):
                if w.startswith(prefix):
                    sev = prefix.rstrip(': ')
                    display_w = w[len(prefix):]
                    break
            self._jwtWarningsModel.addRow([sev, display_w])

        if not decoded['warnings']:
            self._jwtWarningsModel.addRow(['INFO', 'No security issues detected'])

    def _clearJWT(self):
        self._jwtInput.setText('')
        self._jwtHeaderArea.setText('')
        self._jwtPayloadArea.setText('')
        self._jwtSigArea.setText('')
        self._jwtWarningsModel.setRowCount(0)
        for lbl in self._jwtClaimLabels.values():
            lbl.setText('-')

    def _sendJWTFromDetail(self):
        """
        Extract any JWT from the selected finding's request, send to the
        JWT Analyzer, and also pre-fill the Audit URL field with the
        finding's URL so the auditor can replay without manual config.
        """
        f = self._selected_finding
        if not f:
            self._updateStatus("No finding selected.")
            return
        try:
            req = self._helpers.bytesToString(f.request_response.getRequest())
            m = re.search(
                r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
                req)
            if m:
                self._jwtInput.setText(m.group(0))
                self._decodeJWT()
                # Pre-fill audit URL and store the original request/response
                # so the auditor can use it as a template.
                if hasattr(self, '_auditUrl'):
                    self._auditUrl.setText(f.url)
                self._audit_source_rr = f.request_response
                self._tabs.setSelectedIndex(3)
                self._updateStatus("JWT sent to analyzer. Audit URL pre-filled.")
            else:
                self._updateStatus("No JWT found in this request.")
        except Exception as ex:
            self._updateStatus("JWT extract error: " + str(ex))

    # -----------------------------------------------------------------------
    # Finding management
    # -----------------------------------------------------------------------

    def _addFinding(self, finding):
        """
        Add a finding to the list and append a row to the UI table.
        Dedup: same (url, finding_type) with same evidence prefix is suppressed.
        Two different secrets of the same type at the same URL are both kept.
        """
        with self._lock:
            for f in self._findings:
                if (f.url == finding.url and
                        f.finding_type == finding.finding_type and
                        f.evidence[:50] == finding.evidence[:50]):
                    return
            self._findings.append(finding)

        def update():
            display_sev = "FP" if finding.is_fp else (finding.severity_override or finding.severity)
            self._tableModel.addRow([
                str(finding.num), finding.timestamp,
                display_sev, finding.confidence,
                finding.category, finding.finding_type,
                finding.found_in, finding.method,
                finding.url, finding.evidence
            ])
            self._updateStats()
            self._updateStatus("[{}][{}] {} — {}".format(
                finding.severity, finding.confidence,
                finding.finding_type, finding.url[:60]))
            if self._cbHighlight.isSelected() and finding.request_response:
                try:
                    color = {'CRITICAL': 'red', 'HIGH': 'orange',
                             'MEDIUM':   'yellow', 'LOW': 'cyan'}.get(
                        finding.severity, 'gray')
                    finding.request_response.setHighlight(color)
                    finding.request_response.setComment("[TH] " + finding.finding_type)
                except Exception:
                    pass
        SwingUtilities.invokeLater(update)

    def _recordKeyFlow(self, key_ep, consumer_ep, method, status):
        def update():
            self._keyFlowModel.addRow([
                key_ep, 'RSA/Asymmetric', consumer_ep,
                method, status, datetime.now().strftime('%H:%M:%S')
            ])
        SwingUtilities.invokeLater(update)

    # -----------------------------------------------------------------------
    # IScannerCheck — passive only, no active requests
    # -----------------------------------------------------------------------

    def doPassiveScan(self, baseRequestResponse): return None
    def doActiveScan(self, baseRequestResponse, insertionPoint): return None
    def consolidateDuplicateIssues(self, existingIssue, newIssue): return -1

    # -----------------------------------------------------------------------
    # Filter
    # -----------------------------------------------------------------------

    def _applyFilter(self):
        sev      = str(self._sevFilter.getSelectedItem())
        cat      = str(self._catFilter.getSelectedItem())
        conf     = str(self._confFilter.getSelectedItem())
        search   = self._searchField.getText().strip().lower()
        hide_fp  = hasattr(self, '_cbHideFP') and self._cbHideFP.isSelected()

        self._tableModel.setRowCount(0)
        with self._lock:
            findings_copy = list(self._findings)

        for f in findings_copy:
            if hide_fp and f.is_fp:
                continue
            # Use override severity for filtering if set
            display_sev = "FP" if f.is_fp else (f.severity_override or f.severity)
            if sev  != 'ALL' and display_sev != sev:  continue
            if cat  != 'ALL' and f.category   != cat:  continue
            if conf != 'ALL' and f.confidence != conf: continue
            if search and search not in (
                    f.url + f.finding_type + f.evidence + f.category).lower():
                continue
            self._tableModel.addRow([
                str(f.num), f.timestamp, display_sev, f.confidence,
                f.category, f.finding_type, f.found_in,
                f.method, f.url, f.evidence
            ])

    # -----------------------------------------------------------------------
    # Detail view with evidence highlighting
    # -----------------------------------------------------------------------

    def _findingForRow(self, model_row):
        """Look up the Finding object for a given model row index by its ID."""
        if model_row < 0 or self._tableModel.getRowCount() == 0:
            return None
        try:
            num = int(str(self._tableModel.getValueAt(model_row, 0)))
            with self._lock:
                for f in self._findings:
                    if f.num == num:
                        return f
        except Exception:
            pass
        return None

    def _showDetail(self, finding):
        if not finding:
            return
        self._selected_finding = finding

        self._detailLabels["Type"].setText(finding.finding_type)
        sl = self._detailLabels["Severity"]
        sl.setText(finding.severity)
        sl.setForeground(SEV_COLORS.get(finding.severity, Color.BLACK))
        cl = self._detailLabels["Confidence"]
        cl.setText("{} ({}/100)".format(finding.confidence, finding.confidence_score))
        cl.setForeground(CONF_COLORS.get(finding.confidence, Color.BLACK))
        reasons = " | ".join(finding.confidence_reasons) if finding.confidence_reasons else "-"
        self._detailLabels["Score"].setText(reasons[:120])
        self._detailLabels["Category"].setText(finding.category)
        self._detailLabels["URL"].setText(finding.url[:140])
        self._detailLabels["Method"].setText(finding.method)
        self._detailLabels["Time"].setText(finding.timestamp)
        self._detailLabels["Pattern matched"].setText(finding.finding_type)
        self._detailLabels["Evidence"].setText(finding.evidence[:140])

        try:
            req = self._helpers.bytesToString(finding.request_response.getRequest())
            self._requestArea.setText(req[:10000] if req else "(no request)")
            self._requestArea.setCaretPosition(0)
        except Exception:
            self._requestArea.setText("(unavailable)")

        try:
            res = finding.request_response.getResponse()
            res_str = self._helpers.bytesToString(res)[:16000] if res else "(no response)"
            self._responseArea.setText(res_str)
            self._responseArea.setCaretPosition(0)
        except Exception as ex:
            self._responseArea.setText("(unavailable: {})".format(ex))

        # Evidence highlighting — three fallback strategies so at least one
        # will locate the match even in minified or truncated content.
        try:
            self._responseArea.getHighlighter().removeAllHighlights()
            self._requestArea.getHighlighter().removeAllHighlights()

            target  = self._responseArea if finding.found_in == 'response' \
                else self._requestArea
            text    = target.getText()
            painter = DefaultHighlighter.DefaultHighlightPainter(HIGHLIGHT_COLOR)
            found   = False

            # Strategy 1: direct substring match with progressively shorter
            # prefixes of the stored evidence string.
            ev = finding.evidence
            if ev and len(ev) >= 4:
                for length in [min(len(ev), 250), min(len(ev), 100),
                               min(len(ev), 50), 20]:
                    if length < 4:
                        break
                    needle = ev[:length]
                    idx = text.find(needle)
                    if idx >= 0:
                        target.getHighlighter().addHighlight(
                            idx, min(len(text), idx + len(needle)), painter)
                        target.setCaretPosition(max(0, idx - 100))
                        found = True
                        break

            # Strategy 2: re-run the original regex on the display text.
            # Handles cases where evidence was stored with a different prefix.
            if not found:
                for (cat, pattern, label, sev, val_fn) in PATTERNS:
                    if label == finding.finding_type:
                        try:
                            pm = re.search(
                                pattern, text, re.IGNORECASE | re.DOTALL)
                            if pm:
                                target.getHighlighter().addHighlight(
                                    pm.start(), pm.end(), painter)
                                target.setCaretPosition(max(0, pm.start() - 100))
                                found = True
                        except Exception:
                            pass
                        break

            # Strategy 3: find the longest meaningful word from evidence (>=8
            # chars). Catches cases where surrounding context differs but the
            # key value itself is unchanged.
            if not found and finding.evidence:
                words = sorted(
                    [w for w in re.split(r'[\s\'"=:,{}()\[\]]+', finding.evidence)
                     if len(w) >= 8],
                    key=len, reverse=True)
                for word in words[:5]:
                    idx = text.find(word)
                    if idx >= 0:
                        target.getHighlighter().addHighlight(
                            idx, idx + len(word), painter)
                        target.setCaretPosition(max(0, idx - 100))
                        break
        except Exception:
            pass

    def _showContextMenu(self, e, finding):
        if not finding:
            return
        menu = JPopupMenu()

        # Standard actions
        for label, action in [
            ("Send to Repeater",        lambda ev: self._sendToRepeater()),
            ("Send to Intruder",        lambda ev: self._sendToIntruder()),
            ("Highlight in Proxy",      lambda ev: self._highlightInProxy()),
            ("Send JWT to Analyzer",    lambda ev: self._sendJWTFromDetail()),
            ("Copy URL",                lambda ev: self._copyToClipboard(finding.url)),
            ("Copy Evidence",           lambda ev: self._copyToClipboard(finding.evidence)),
            ("Copy Confidence Reasons", lambda ev: self._copyToClipboard(
                " | ".join(finding.confidence_reasons))),
        ]:
            mi = JMenuItem(label)
            mi.addActionListener(action)
            menu.add(mi)

        menu.addSeparator()

        # False positive toggle
        fp_label = "Unmark False Positive" if finding.is_fp else "Mark as False Positive"
        mi_fp = JMenuItem(fp_label)
        mi_fp.addActionListener(lambda ev, f=finding: self._markAsFP(f))
        menu.add(mi_fp)

        # Severity override submenu
        from javax.swing import JMenu
        sev_menu = JMenu("Override Severity")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            mi_sev = JMenuItem(sev)
            mi_sev.addActionListener(lambda ev, s=sev, f=finding: self._changeSeverity(f, s))
            sev_menu.add(mi_sev)
        mi_reset = JMenuItem("Reset to original")
        mi_reset.addActionListener(lambda ev, f=finding: self._changeSeverity(f, None))
        sev_menu.addSeparator()
        sev_menu.add(mi_reset)
        menu.add(sev_menu)

        menu.show(e.getComponent(), e.getX(), e.getY())

    def _sendToRepeater(self):
        f = self._selected_finding
        if not f: return
        try:
            rr = f.request_response
            ri = self._helpers.analyzeRequest(rr)
            h  = ri.getUrl().getHost()
            pt = ri.getUrl().getPort()
            if pt == -1:
                pt = 443 if ri.getUrl().getProtocol() == 'https' else 80
            self._callbacks.sendToRepeater(
                h, pt, ri.getUrl().getProtocol().lower() == 'https',
                rr.getRequest(), "TokenHound")
            self._updateStatus("Sent to Repeater: " + f.url[:60])
        except Exception as ex:
            self._updateStatus("Repeater error: " + str(ex))

    def _sendToIntruder(self):
        f = self._selected_finding
        if not f: return
        try:
            rr = f.request_response
            ri = self._helpers.analyzeRequest(rr)
            h  = ri.getUrl().getHost()
            pt = ri.getUrl().getPort()
            if pt == -1:
                pt = 443 if ri.getUrl().getProtocol() == 'https' else 80
            self._callbacks.sendToIntruder(
                h, pt, ri.getUrl().getProtocol().lower() == 'https',
                rr.getRequest())
            self._updateStatus("Sent to Intruder: " + f.url[:60])
        except Exception as ex:
            self._updateStatus("Intruder error: " + str(ex))

    def _highlightInProxy(self):
        f = self._selected_finding
        if not f: return
        try:
            f.request_response.setHighlight('red')
            f.request_response.setComment("[TH] " + f.finding_type)
            self._updateStatus("Highlighted: " + f.url[:60])
        except Exception as ex:
            self._updateStatus("Highlight error: " + str(ex))

    def _copyToClipboard(self, text):
        try:
            from java.awt import Toolkit
            from java.awt.datatransfer import StringSelection
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(text), None)
            self._updateStatus("Copied.")
        except Exception as ex:
            self._updateStatus("Copy error: " + str(ex))

    def _makeTextAreaCopyMenu(self, area_fn):
        """
        Returns a MouseAdapter that shows a right-click context menu with
        Copy (selected text) and Select All on any JTextArea.
        area_fn is a zero-arg lambda that returns the JTextArea at call time.
        """
        extRef = self
        class TextAreaMouse(MouseAdapter):
            def mousePressed(self, e):
                if e.isPopupTrigger():
                    self._show(e)
            def mouseReleased(self, e):
                if e.isPopupTrigger():
                    self._show(e)
            def _show(self, e):
                area = area_fn()
                menu = JPopupMenu()
                mi_copy = JMenuItem("Copy selected text")
                def do_copy(ev):
                    sel = area.getSelectedText()
                    if sel:
                        extRef._copyToClipboard(sel)
                    else:
                        extRef._updateStatus("No text selected — drag to select first.")
                mi_copy.addActionListener(do_copy)
                mi_all = JMenuItem("Select all")
                mi_all.addActionListener(lambda ev: area.selectAll())
                menu.add(mi_copy)
                menu.add(mi_all)
                menu.show(e.getComponent(), e.getX(), e.getY())
        return TextAreaMouse()

    def _markAsFP(self, finding):
        """Toggle false-positive flag on a finding and refresh the table row."""
        if not finding:
            return
        finding.is_fp = not finding.is_fp
        label = "FP" if finding.is_fp else finding.severity_override or finding.severity
        self._refreshTableRow(finding)
        self._updateStatus(
            "Marked as {} — use 'Hide FP' checkbox to filter.".format(
                "False Positive" if finding.is_fp else "active"))

    def _changeSeverity(self, finding, new_sev):
        """Override the displayed severity for a finding without re-scanning."""
        if not finding:
            return
        finding.severity_override = new_sev
        self._refreshTableRow(finding)
        self._updateStatus("Severity overridden to " + new_sev)

    def _refreshTableRow(self, finding):
        """Update the table row for a finding after a manual edit."""
        def update():
            display_sev = finding.severity_override or finding.severity
            if finding.is_fp:
                display_sev = "FP"
            for row in range(self._tableModel.getRowCount()):
                try:
                    if int(str(self._tableModel.getValueAt(row, 0))) == finding.num:
                        self._tableModel.setValueAt(display_sev, row, 2)
                        break
                except Exception:
                    pass
        SwingUtilities.invokeLater(update)

    # -----------------------------------------------------------------------
    # JWT Auditor — run, result storage, and export
    # -----------------------------------------------------------------------

    def _runJWTAudit(self):
        """
        Generate test cases from the current JWT Analyzer token and replay
        the original request once per test. Runs on a background thread so
        the UI stays responsive.

        How request replay works:
          1. We need the original request bytes. If the user arrived here via
             "Send JWT to Analyzer" from a finding, the finding's request_response
             object is stored in self._audit_source_rr. If not, we build a
             minimal GET request to the target URL.
          2. For each test case we swap the Authorization: Bearer <token> header
             value (or the configured header/prefix) with the mutated token.
          3. We call self._callbacks.makeHttpRequest() which sends through Burp's
             proxy stack (so it appears in Proxy history and respects upstream
             proxy settings).
          4. We read the response status code. A 2xx when the original should
             be 2xx is expected — but a 2xx for an alg=none token or an expired
             token is a finding.
        """
        token = self._jwtInput.getText().strip()
        if not token or not token.startswith('eyJ'):
            self._updateAuditStatus("No token in JWT Analyzer input. Decode a token first.")
            return

        url_str = self._auditUrl.getText().strip()
        if not url_str:
            self._updateAuditStatus("No URL set. Fill in the Target URL field.")
            return

        cases = _build_jwt_test_cases(token)
        if not cases:
            self._updateAuditStatus("Could not parse token — check it is a valid JWT.")
            return

        header_name   = self._auditHeader.getText().strip() or 'Authorization'
        header_prefix = self._auditPrefix.getText()   # keep as-is, may have trailing space

        def _do():
            self._audit_results = []
            self._auditResultsModel.setRowCount(0)
            total = len(cases)
            self._updateAuditStatus("Running audit — 0/{} done...".format(total))

            # Parse target URL into host / port / https / path
            try:
                from java.net import URL as JURL
                ju = JURL(url_str)
                host     = ju.getHost()
                port     = ju.getPort()
                protocol = ju.getProtocol().lower()
                use_https = (protocol == 'https')
                if port == -1:
                    port = 443 if use_https else 80
                path = ju.getFile() or '/'
            except Exception as ex:
                self._updateAuditStatus("Invalid URL: " + str(ex))
                return

            # Build a baseline request to use as a template.
            # If we have a captured request from a finding, use that;
            # otherwise synthesise a GET.
            base_req = None
            if hasattr(self, '_audit_source_rr') and self._audit_source_rr:
                try:
                    base_req = self._helpers.bytesToString(
                        self._audit_source_rr.getRequest())
                except Exception:
                    base_req = None

            if not base_req:
                base_req = (
                    "GET {path} HTTP/1.1\r\n"
                    "Host: {host}\r\n"
                    "{hdr}: {prefix}PLACEHOLDER\r\n"
                    "User-Agent: TokenHound-Auditor/1.0\r\n"
                    "Accept: application/json\r\n"
                    "Connection: close\r\n\r\n"
                ).format(path=path, host=host,
                         hdr=header_name, prefix=header_prefix)

            passed = 0
            for i, case in enumerate(cases):
                try:
                    # Swap the JWT in the request.
                    # Replace any existing header value, or inject the header
                    # if it does not exist.
                    mutated_token = case['token']
                    new_header_val = header_prefix + mutated_token

                    # Regex-replace the header value (case-insensitive header name).
                    new_req = re.sub(
                        r'(?m)^(' + re.escape(header_name) + r'\s*:\s*).*$',
                        lambda mv: mv.group(1) + new_header_val,
                        base_req,
                        flags=re.IGNORECASE
                    )
                    # If header was not present, inject it after Host:.
                    if header_name.lower() not in new_req.lower():
                        new_req = re.sub(
                            r'(?m)^(Host\s*:.*$)',
                            lambda mv: mv.group(1) + '\r\n' + header_name + ': ' + new_header_val,
                            new_req, flags=re.IGNORECASE)

                    req_bytes = self._helpers.stringToBytes(new_req)
                    from burp import IHttpService
                    http_svc = self._helpers.buildHttpService(host, port, use_https)
                    resp_obj = self._callbacks.makeHttpRequest(http_svc, req_bytes)
                    resp_bytes = resp_obj.getResponse() if resp_obj else None

                    if resp_bytes:
                        resp_str    = self._helpers.bytesToString(resp_bytes)
                        analyzed    = self._helpers.analyzeResponse(resp_str)
                        status_code = analyzed.getStatusCode()
                        resp_raw    = resp_str[:4000]
                    else:
                        status_code = 0
                        resp_raw    = "(no response)"

                    # Determine result status.
                    # 2xx = ACCEPTED (potentially vulnerable for alg:none etc.)
                    # 4xx = REJECTED (expected behaviour for invalid tokens)
                    # 5xx = ERROR    (server crash — worth noting)
                    if 200 <= status_code < 300:
                        audit_status = 'ACCEPTED'
                    elif 400 <= status_code < 500:
                        audit_status = 'REJECTED'
                    elif status_code >= 500:
                        audit_status = 'SERVER ERROR'
                    elif status_code == 0:
                        audit_status = 'NO RESPONSE'
                    else:
                        audit_status = 'OTHER ({})'.format(status_code)

                    # Generate notes based on result + test class
                    notes = ''
                    if audit_status == 'ACCEPTED' and case['class'] == 'SIGNATURE':
                        notes = '! SIGNATURE BYPASS — server accepted invalid token'
                    elif audit_status == 'ACCEPTED' and case['name'].startswith('Expired'):
                        notes = '! EXPIRY NOT CHECKED — accepted expired token'
                    elif audit_status == 'ACCEPTED' and 'escalation' in case['name'].lower():
                        notes = '! PRIVILEGE ESCALATION — elevated claims accepted'
                    elif audit_status == 'ACCEPTED' and case['class'] == 'INJECTION':
                        notes = '! INJECTION ACCEPTED — check for SSRF / SQLi'
                    elif audit_status == 'SERVER ERROR':
                        notes = 'Server 5xx — possible crash or unhandled exception'
                    elif audit_status == 'REJECTED':
                        notes = 'Expected — server rejected invalid token'

                    result = {
                        'num':          i + 1,
                        'name':         case['name'],
                        'class':        case['class'],
                        'risk':         case['risk'],
                        'status':       audit_status,
                        'http':         str(status_code) if status_code else '-',
                        'notes':        notes,
                        'token':        mutated_token,
                        'description':  case['description'],
                        'response_raw': resp_raw,
                    }
                    self._audit_results.append(result)

                    if audit_status == 'ACCEPTED':
                        passed += 1

                    def add_row(r=result):
                        self._auditResultsModel.addRow([
                            str(r['num']), r['name'], r['class'], r['risk'],
                            r['status'], r['http'], r['notes']
                        ])
                    SwingUtilities.invokeLater(add_row)

                except Exception as ex:
                    err_result = {
                        'num': i + 1, 'name': case['name'], 'class': case['class'],
                        'risk': case['risk'], 'status': 'ERROR', 'http': '-',
                        'notes': 'Request error: ' + str(ex),
                        'token': case['token'], 'description': case['description'],
                        'response_raw': '',
                    }
                    self._audit_results.append(err_result)
                    def add_err_row(r=err_result):
                        self._auditResultsModel.addRow([
                            str(r['num']), r['name'], r['class'], r['risk'],
                            r['status'], r['http'], r['notes']
                        ])
                    SwingUtilities.invokeLater(add_err_row)

                self._updateAuditStatus(
                    "Running audit — {}/{} done...".format(i + 1, total))

            summary = "Audit complete — {}/{} tests ran, {} ACCEPTED (check notes).".format(
                total, total, passed)
            self._updateAuditStatus(summary)

        t = threading.Thread(target=_do)
        t.setDaemon(True)
        t.start()

    def _updateAuditStatus(self, msg):
        def update():
            if hasattr(self, '_auditStatusLabel'):
                self._auditStatusLabel.setText(msg)
        SwingUtilities.invokeLater(update)

    def _exportAuditResults(self):
        """Export audit results table to CSV."""
        if not self._audit_results:
            self._updateAuditStatus("No results to export.")
            return
        try:
            fc = JFileChooser()
            fc.setSelectedFile(File("tokenhound_jwt_audit.csv"))
            if fc.showSaveDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
                return
            path = fc.getSelectedFile().getAbsolutePath()
            bw = BufferedWriter(FileWriter(path))
            bw.write("Num,Name,Class,Risk,Status,HTTP,Notes,Description,Token\r\n")
            for r in self._audit_results:
                def esc(s):
                    return '"' + str(s).replace('"', '""') + '"'
                bw.write(",".join([
                    str(r['num']), esc(r['name']), esc(r['class']),
                    esc(r['risk']), esc(r['status']), esc(r['http']),
                    esc(r['notes']), esc(r['description']), esc(r['token'])
                ]) + "\r\n")
            bw.close()
            self._updateAuditStatus("Exported {} results to {}".format(
                len(self._audit_results), path))
        except Exception as ex:
            self._updateAuditStatus("Export error: " + str(ex))

    # -----------------------------------------------------------------------
    # CSV export
    # -----------------------------------------------------------------------

    def _exportCSV(self):
        try:
            fc = JFileChooser()
            fc.setSelectedFile(File("tokenhound_findings.csv"))
            if fc.showSaveDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
                return
            path = fc.getSelectedFile().getAbsolutePath()
            with self._lock:
                findings_copy = list(self._findings)
            bw = BufferedWriter(FileWriter(path))
            bw.write("Num,Time,Severity,SeverityOverride,FalsePositive,"
                     "Confidence,Score,Category,Type,FoundIn,Method,URL,Evidence,Reasons\r\n")
            for f in findings_copy:
                def esc(s):
                    return '"' + str(s).replace('"', '""') + '"'
                bw.write(",".join([
                    str(f.num), f.timestamp,
                    esc(f.severity),
                    esc(f.severity_override or ""),
                    esc("Yes" if f.is_fp else "No"),
                    esc(f.confidence), str(f.confidence_score),
                    esc(f.category), esc(f.finding_type), esc(f.found_in),
                    esc(f.method), esc(f.url), esc(f.evidence),
                    esc(" | ".join(f.confidence_reasons))
                ]) + "\r\n")
            bw.close()
            self._updateStatus(
                "Exported {} findings to {}".format(len(findings_copy), path))
        except Exception as ex:
            self._updateStatus("Export error: " + str(ex))

    # -----------------------------------------------------------------------
    # Misc
    # -----------------------------------------------------------------------

    def _clearFindings(self):
        with self._lock:
            self._findings = []
            Finding._counter[0] = 0
        self._tableModel.setRowCount(0)
        self._keyFlowModel.setRowCount(0)
        self._key_endpoints.clear()
        self._selected_finding = None
        self._updateStats()
        self._updateStatus("Cleared.")

    def _togglePause(self):
        self._paused = not self._paused
        self._pauseBtn.setText("Resume" if self._paused else "Pause")
        self._updateStatus("Scanning " + ("PAUSED." if self._paused else "RESUMED."))

    def _updateStats(self):
        def update():
            with self._lock:
                counts   = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
                fp_count = 0
                total    = len(self._findings)
                for f in self._findings:
                    if f.is_fp:
                        fp_count += 1
                        continue   # don't count FP findings in severity totals
                    # Use override severity for the header counts too
                    sev = f.severity_override or f.severity
                    counts[sev] = counts.get(sev, 0) + 1
            if hasattr(self, '_lblCritical'):
                self._lblCritical.setText("CRITICAL: " + str(counts['CRITICAL']))
                self._lblHigh.setText    ("HIGH: "     + str(counts['HIGH']))
                self._lblMedium.setText  ("MEDIUM: "   + str(counts['MEDIUM']))
                self._lblLow.setText     ("LOW: "      + str(counts['LOW']))
                fp_str = "  FP: {}".format(fp_count) if fp_count else ""
                self._lblTotal.setText   ("Total: {}{}".format(total, fp_str))
        SwingUtilities.invokeLater(update)

    def _updateStatus(self, msg):
        def update():
            if self._statusLabel:
                self._statusLabel.setText(
                    "[{}]  {}".format(datetime.now().strftime('%H:%M:%S'), msg))
        SwingUtilities.invokeLater(update)

    def _hostOf(self, url):
        try:
            return url.split('/')[2]
        except Exception:
            return url


# ---------------------------------------------------------------------------
# Cell renderers
# ---------------------------------------------------------------------------

class SeverityCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        comp.setForeground(SEV_COLORS.get(str(value), Color.BLACK))
        comp.setFont(Font("Dialog", Font.BOLD, 11))
        return comp


class ConfidenceCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        # Value may be "LIKELY (72/100)" — extract just the label for colour lookup.
        conf_key = str(value).split(' ')[0] if value else ''
        comp.setForeground(CONF_COLORS.get(conf_key, Color.BLACK))
        comp.setFont(Font("Dialog", Font.BOLD, 11))
        return comp


class AuditStatusCellRenderer(DefaultTableCellRenderer):
    """
    Colours the Status column in the JWT Auditor results table.
      ACCEPTED     — red   (potentially vulnerable)
      REJECTED     — green (expected behaviour)
      SERVER ERROR — orange
      NO RESPONSE  — grey
      ERROR        — dark red
    """
    STATUS_COLORS = {
        'ACCEPTED':     Color(200, 30,  30),
        'REJECTED':     Color(0,   150, 0),
        'SERVER ERROR': Color(210, 100, 0),
        'NO RESPONSE':  Color(120, 120, 120),
        'ERROR':        Color(160, 0,   0),
    }

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        status_key = str(value).split('(')[0].strip() if value else ''
        comp.setForeground(self.STATUS_COLORS.get(status_key, Color.BLACK))
        comp.setFont(Font("Dialog", Font.BOLD, 11))
        return comp