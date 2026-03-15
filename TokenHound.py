# -*- coding: utf-8 -*-
# TokenHound - Burp Suite Extension
# Passive scanner for client-side encryption, exposed keys and hardcoded secrets
# Author: Garv Kamra | CyberSecurity Analyst
# Requires: Jython 2.7 standalone JAR (Extender > Options > Python Environment)

from burp import IBurpExtender, ITab, IScannerCheck, IHttpListener, IContextMenuFactory
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JButton,
                          JLabel, JTextField, JTextArea, JSplitPane, JCheckBox,
                          BorderFactory, JComboBox, SwingUtilities, JMenuItem,
                          JPopupMenu, SwingConstants, Box, JFileChooser,
                          JProgressBar, JPasswordField)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.border import EmptyBorder
from java.awt import (Color, Font, Dimension, BorderLayout, FlowLayout,
                       GridBagLayout, GridBagConstraints, Insets, GridLayout)
from java.awt.event import MouseAdapter
from java.io import File, FileWriter, BufferedWriter
import re, threading, math, base64
from datetime import datetime

# --- Colors ---

SEV_COLORS = {
    'CRITICAL': Color(200, 30,  30),
    'HIGH':     Color(210, 100, 0),
    'MEDIUM':   Color(180, 140, 0),
    'LOW':      Color(30,  100, 200),
    'INFO':     Color(100, 100, 100),
}

CONF_COLORS = {
    'CONFIRMED': Color(0,  150, 0),
    'LIKELY':    Color(30, 100, 200),
    'POSSIBLE':  Color(160, 130, 0),
    'UNLIKELY':  Color(160, 160, 160),
}

# --- Detection patterns: (category, regex, label, severity) ---

PATTERNS = [
    # --- Asymmetric Keys ---
    ('Asymmetric Key', r'-----BEGIN PUBLIC KEY-----',                          'RSA/EC Public Key (PEM)',         'HIGH'),
    ('Asymmetric Key', r'-----BEGIN RSA PUBLIC KEY-----',                      'RSA Public Key (PKCS1)',          'HIGH'),
    ('Asymmetric Key', r'-----BEGIN PRIVATE KEY-----',                         'Private Key EXPOSED (PKCS8)',     'CRITICAL'),
    ('Asymmetric Key', r'-----BEGIN RSA PRIVATE KEY-----',                     'RSA Private Key EXPOSED',        'CRITICAL'),
    ('Asymmetric Key', r'-----BEGIN EC PRIVATE KEY-----',                      'EC Private Key EXPOSED',         'CRITICAL'),
    ('Asymmetric Key', r'"keySpec"\s*:\s*"RSA"',                               'RSA Key Spec in JSON',           'HIGH'),
    ('Asymmetric Key', r'"keyUsage"\s*:\s*"ENCRYPT_DECRYPT"',                  'Encrypt/Decrypt Key Usage',      'MEDIUM'),
    ('Asymmetric Key', r'"publicKey"\s*:\s*"[A-Za-z0-9+/=\-\n]{100,}"',       'Public Key in JSON Response',    'HIGH'),
    ('Asymmetric Key', r'ssh-rsa\s+[A-Za-z0-9+/=]{100,}',                     'SSH RSA Public Key',             'MEDIUM'),

    # --- Symmetric Keys ---
    ('Symmetric Key',  r'"(?:secretKey|secret_key|aesKey|aes_key|encKey|enc_key)"\s*:\s*"[A-Za-z0-9+/=]{24,}"',
                                                                                'Symmetric Key in JSON',          'CRITICAL'),
    ('Symmetric Key',  r'(?:AES|DES|3DES|ChaCha20)\s*(?:key|Key|KEY)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']',
                                                                                'Hardcoded Symmetric Key',        'CRITICAL'),
    ('Symmetric Key',  r'\biv\s*=\s*["\'][A-Fa-f0-9]{16,32}["\']',            'Hardcoded IV',                   'HIGH'),
    ('Symmetric Key',  r'CryptoJS\.AES\.(?:en|de)crypt\([^,]+,\s*["\'][^"\']{8,}["\']',
                                                                                'CryptoJS Hardcoded Key',         'CRITICAL'),

    # --- Crypto Library (JS) ---
    ('Crypto Library', r'cdn\.jsdelivr\.net/npm/jsencrypt|from ["\']jsencrypt["\']|require\(["\']jsencrypt["\']',
                                                                                'JSEncrypt Library Loaded',       'MEDIUM'),
    ('Crypto Library', r'new\s+JSEncrypt\s*\(\)',                               'JSEncrypt Instance Created',     'HIGH'),
    ('Crypto Library', r'\.setPublicKey\s*\(',                                  'setPublicKey() Called',          'HIGH'),
    ('Crypto Library', r'\.encrypt\s*\(\s*JSON\.stringify',                     'Client-Side JSON Encryption',    'HIGH'),
    ('Crypto Library', r'CryptoJS\s*\.',                                        'CryptoJS Usage',                 'MEDIUM'),
    ('Crypto Library', r'forge\.pki\.|require\(["\']node-forge["\']',           'node-forge Usage',               'MEDIUM'),
    ('Crypto Library', r'window\.crypto\.subtle\.|crypto\.subtle\.',            'Web Crypto API (subtle)',        'LOW'),
    # More JS crypto patterns
    ('Crypto Library', r'new\s+(?:TextEncoder|TextDecoder)\s*\(\)',             'TextEncoder (likely crypto)',    'LOW'),
    ('Crypto Library', r'crypto\.createCipheriv|crypto\.createDecipheriv',      'Node crypto cipher',             'HIGH'),
    ('Crypto Library', r'crypto\.createSign|crypto\.createVerify',              'Node crypto sign/verify',        'MEDIUM'),
    ('Crypto Library', r'subtle\.(?:encrypt|decrypt|sign|verify|deriveKey|importKey|exportKey)',
                                                                                'SubtleCrypto Operation',         'HIGH'),
    ('Crypto Library', r'(?:RSA-OAEP|RSA-PSS|ECDH|ECDSA|AES-GCM|AES-CBC)',    'WebCrypto Algorithm Name',       'MEDIUM'),
    ('Crypto Library', r'require\(["\'](?:crypto-js|elliptic|tweetnacl|openpgp)["\']',
                                                                                'Crypto Library Import',          'MEDIUM'),
    # Key loading patterns
    ('Crypto Library', r'importKey\s*\(\s*["\'](?:raw|pkcs8|spki)["\']',       'SubtleCrypto Key Import',        'HIGH'),
    ('Crypto Library', r'atob\s*\([^)]{20,}\)',                                 'Base64 Decode (possible key)',   'LOW'),

    # --- Key Flow ---
    ('Key Flow',       r'/(?:encryption|crypto|security)/public-?key',          'Public Key Endpoint URL',        'HIGH'),
    ('Key Flow',       r'"publicKey"\s*:',                                       'Public Key in Response Body',   'HIGH'),
    ('Key Flow',       r'/(?:api|v\d+)/(?:keys?|pubkey|rsa|encrypt)(?:[/?]|$)', 'Key API Endpoint',              'HIGH'),
    ('Key Flow',       r'"(?:rsaPublicKey|encryptionKey|serverPublicKey)"\s*:',  'Named Public Key in JSON',      'HIGH'),

    # --- Hardcoded Secret ---
    ('Hardcoded Secret', r'(?<![A-Za-z0-9/+])(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Za-z0-9/+=])',
                                                                                'AWS Access Key ID',              'CRITICAL'),
    ('Hardcoded Secret', r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?[A-Za-z0-9/+]{40}["\']?',
                                                                                'AWS Secret Key',                 'CRITICAL'),
    ('Hardcoded Secret', r'(?<![A-Za-z0-9/+])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9/+=])',
                                                                                'Google API Key',                 'HIGH'),
    ('Hardcoded Secret', r'ghp_[A-Za-z0-9]{36}',                               'GitHub PAT',                    'CRITICAL'),
    ('Hardcoded Secret', r'github_pat_[A-Za-z0-9_]{59}',                       'GitHub Fine-grained PAT',       'CRITICAL'),
    ('Hardcoded Secret', r'xox[bpoa]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}',
                                                                                'Slack Token',                    'HIGH'),
    ('Hardcoded Secret', r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',       'SendGrid API Key',              'HIGH'),
    # JWT secret hardcoded in JS source (not bearer tokens - those are suppressed separately)
    ('Hardcoded Secret', r'(?:jwt_secret|jwtSecret|JWT_SECRET)\s*[=:]\s*["\'][^"\']{8,}["\']',
                                                                                'JWT Secret Hardcoded',           'CRITICAL'),
    # JWT issued in response body (not Authorization header)
    ('Hardcoded Secret', r'"(?:token|access_token|id_token|refresh_token)"\s*:\s*"(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"',
                                                                                'JWT Issued in Response Body',    'MEDIUM'),
    ('Hardcoded Secret', r'(?:^|[^a-zA-Z])password\s*[=:]\s*["\'][^"\']{6,}["\']',
                                                                                'Hardcoded Password',             'HIGH'),
    ('Hardcoded Secret', r'mongodb(?:\+srv)?://[^@]+:[^@]+@[^\s"\'<>]{5,}',    'MongoDB Connection String',     'CRITICAL'),
    ('Hardcoded Secret', r'(?:postgresql|postgres)://[^@]+:[^@]+@[^\s"\'<>]{5,}',
                                                                                'PostgreSQL Connection String',   'CRITICAL'),
    ('Hardcoded Secret', r'mysql://[^@]+:[^@]+@[^\s"\'<>]{5,}',                'MySQL Connection String',       'CRITICAL'),
]

# --- Helpers ---

class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


class Finding(object):
    _counter = [0]
    def __init__(self, url, method, category, finding_type, severity, evidence,
                 request_response, confidence='LIKELY', confidence_score=50,
                 confidence_reasons=None):
        Finding._counter[0] += 1
        self.num               = Finding._counter[0]
        self.timestamp         = datetime.now().strftime('%H:%M:%S')
        self.url               = url
        self.method            = method
        self.category          = category
        self.finding_type      = finding_type
        self.severity          = severity
        self.evidence          = (evidence or '')[:300]
        self.request_response  = request_response
        self.confidence        = confidence
        self.confidence_score  = confidence_score
        self.confidence_reasons = confidence_reasons or []


# --- Confidence scoring (0-100 across 8 independent signals) ---

def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = float(len(s))
    return -sum((v/n) * math.log(v/n, 2) for v in freq.values())


def _score_confidence(finding, content_type, url, full_response):
    score, reasons = 0, []
    ev    = finding.evidence
    ftype = finding.finding_type
    cat   = finding.category
    ct    = (content_type or '').lower()

    # pattern specificity
    HIGH_SPEC = {
        'AWS Access Key ID', 'AWS Secret Key', 'GitHub PAT',
        'GitHub Fine-grained PAT', 'SendGrid API Key', 'Slack Token',
        'RSA Private Key EXPOSED', 'EC Private Key EXPOSED',
        'Private Key EXPOSED (PKCS8)', 'MongoDB Connection String',
        'PostgreSQL Connection String', 'MySQL Connection String',
    }
    MED_SPEC = {
        'Google API Key', 'JWT Secret Hardcoded', 'RSA/EC Public Key (PEM)',
        'RSA Public Key (PKCS1)', 'CryptoJS Hardcoded Key',
        'Symmetric Key in JSON', 'JSEncrypt Instance Created',
        'Client-Side JSON Encryption', 'Encrypted Payload (base64 blob POST)',
        'Public Key Distribution Endpoint', 'Public Key in JSON Response',
        'Named Public Key in JSON', 'SubtleCrypto Key Import',
        'JWT Issued in Response Body',
    }
    if ftype in HIGH_SPEC:
        score += 40; reasons.append("High-specificity pattern")
    elif ftype in MED_SPEC:
        score += 25; reasons.append("Medium-specificity pattern")
    else:
        score += 10; reasons.append("Generic pattern")

    # content-type context
    if any(x in ct for x in ['javascript', 'application/json', 'x-javascript']):
        score += 20; reasons.append("JS/JSON context")
    elif 'text/html' in ct:
        score += 5; reasons.append("HTML context")
    elif not ct:
        score += 8; reasons.append("Unknown content-type")

    # URL path context
    url_l = url.lower()
    if any(x in url_l for x in ['/api/', '/v1/', '/v2/', '/internal/', '/admin/', '/backend/']):
        score += 15; reasons.append("API endpoint URL")
    elif any(x in url_l for x in ['/static/', '/assets/', '/public/', '/cdn/']):
        score -= 15; reasons.append("Static asset (lower trust)")

    # entropy check
    if cat in ('Hardcoded Secret', 'Symmetric Key') and ev:
        val = ev
        for sep in ['=', ':', '"']:
            if sep in ev:
                candidate = ev.split(sep)[-1].strip().strip('"\'')
                if len(candidate) >= 8:
                    val = candidate; break
        e = _shannon_entropy(val)
        if e >= 4.0:
            score += 20; reasons.append("High entropy ({:.1f} bits)".format(e))
        elif e >= 3.0:
            score += 8;  reasons.append("Medium entropy ({:.1f} bits)".format(e))
        else:
            score -= 20; reasons.append("Low entropy - placeholder? ({:.1f})".format(e))

    # placeholder check
    PLACEHOLDERS = ['your_','yourkey','example','placeholder','changeme',
                    'insert_','replace_','xxxxxxx','aaaaaaa','123456',
                    'test','demo','sample','dummy','fake','todo','my_secret']
    if any(p in ev.lower() for p in PLACEHOLDERS):
        score -= 30; reasons.append("Placeholder value detected")

    # comment context
    stripped = ev.strip()
    if stripped.startswith('//') or stripped.startswith('#') or '/**' in ev or '/*' in ev:
        score -= 25; reasons.append("Inside a comment")

    # format validation
    if ftype == 'JWT Issued in Response Body' and ev:
        m = re.search(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', ev)
        if m:
            parts = m.group(0).split('.')
            try:
                hdr = parts[0] + '=' * (4 - len(parts[0]) % 4)
                decoded = base64.b64decode(hdr)
                if b'"alg"' in decoded or b'"typ"' in decoded:
                    score += 20; reasons.append("JWT header validates (alg/typ)")
            except Exception:
                pass

    if ftype == 'AWS Access Key ID':
        m2 = re.search(r'(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}', ev)
        if m2 and len(m2.group(0)) == 20:
            score += 15; reasons.append("AWS key is exactly 20 chars")

    if 'Private Key' in ftype or 'Public Key (PEM)' in ftype:
        if 'END' in full_response and 'BEGIN' in full_response:
            score += 20; reasons.append("PEM has BEGIN+END markers")
        else:
            score -= 10; reasons.append("PEM missing END marker")

    if 'Connection String' in ftype:
        if re.search(r'://[^:]+:[^@]+@[a-zA-Z0-9._-]+', ev):
            score += 20; reasons.append("user:pass@host format valid")

    # response size
    if len(full_response) > 5000:
        score += 5; reasons.append("Substantial response ({} B)".format(len(full_response)))

    score = max(0, min(100, score))
    if   score >= 80: label = 'CONFIRMED'
    elif score >= 55: label = 'LIKELY'
    elif score >= 30: label = 'POSSIBLE'
    else:             label = 'UNLIKELY'
    return label, score, reasons


# --- JWT decoder (base64url, no external libs needed) ---

def _b64_decode_jwt_part(part):

    try:
        padding = 4 - len(part) % 4
        padded  = part + ('=' * (padding % 4))
        decoded = base64.b64decode(padded.replace('-', '+').replace('_', '/'))
        return decoded.decode('utf-8', errors='replace')
    except Exception as ex:
        return '(decode error: {})'.format(ex)


def _decode_jwt(token):

    result = {
        'header_raw': '', 'payload_raw': '', 'signature_raw': '',
        'header_json': '', 'payload_json': '',
        'alg': '', 'sub': '', 'iss': '', 'exp': '', 'iat': '',
        'claims': {}, 'warnings': []
    }
    token = token.strip()
    parts = token.split('.')
    if len(parts) != 3:
        result['warnings'].append('Not a valid JWT (expected 3 parts, got {})'.format(len(parts)))
        return result

    result['header_raw']    = parts[0]
    result['payload_raw']   = parts[1]
    result['signature_raw'] = parts[2]

    hdr_str     = _b64_decode_jwt_part(parts[0])
    payload_str = _b64_decode_jwt_part(parts[1])
    result['header_json']  = hdr_str
    result['payload_json'] = payload_str

    # Parse header
    try:
        alg_m = re.search(r'"alg"\s*:\s*"([^"]+)"', hdr_str)
        result['alg'] = alg_m.group(1) if alg_m else 'unknown'
    except Exception:
        result['alg'] = 'unknown'

    # Parse payload claims
    try:
        for key in ['sub', 'iss', 'exp', 'iat', 'role', 'email', 'name',
                    'username', 'userId', 'tcStatus', 'key']:
            m = re.search(r'"' + key + r'"\s*:\s*"?([^",}\s]+)"?', payload_str)
            if m:
                val = m.group(1).strip('"')
                result['claims'][key] = val
                if key in ('sub', 'iss', 'exp', 'iat'):
                    result[key] = val
    except Exception:
        pass

    # Security warnings
    alg = result['alg'].upper()
    if alg == 'NONE':
        result['warnings'].append('CRITICAL: alg=none - signature not verified!')
    elif alg == 'HS256' or alg.startswith('HS'):
        result['warnings'].append('MEDIUM: HMAC algorithm ({}). Secret key used for signing - check for weak keys.'.format(alg))
    elif alg.startswith('RS') or alg.startswith('ES') or alg.startswith('PS'):
        result['warnings'].append('INFO: Asymmetric algorithm ({}) - public key verification.'.format(alg))

    # Check expiry
    exp_val = result.get('exp', '')
    if exp_val:
        try:
            exp_ts  = int(exp_val)
            now_ts  = int(datetime.now().strftime('%s')) if hasattr(datetime.now(), 'strftime') else 0
            import time
            now_ts  = int(time.time())
            if exp_ts < now_ts:
                result['warnings'].append('INFO: Token is EXPIRED (exp={})'.format(exp_val))
            else:
                diff_h = (exp_ts - now_ts) / 3600.0
                if diff_h > 24:
                    result['warnings'].append('LOW: Long-lived token - expires in {:.1f} hours'.format(diff_h))
        except Exception:
            pass

    # Check interesting claims
    claims = result['claims']
    if 'role' in claims:
        role = claims['role'].lower()
        if any(r in role for r in ['admin', 'root', 'superuser', 'god', 'system']):
            result['warnings'].append('HIGH: Privileged role claim: ' + claims['role'])

    # Signature length - empty sig = unsigned
    if not parts[2]:
        result['warnings'].append('CRITICAL: Empty signature - token is unsigned!')
    elif len(parts[2]) < 10:
        result['warnings'].append('HIGH: Very short signature - possible tampering')

    # Sensitive data in payload
    SENSITIVE_KEYS = ['password', 'passwd', 'secret', 'ssn', 'credit', 'card', 'cvv', 'pin']
    for sk in SENSITIVE_KEYS:
        if sk in payload_str.lower():
            result['warnings'].append('HIGH: Sensitive field "{}" found in payload'.format(sk))

    return result


# --- Main extension ---

class BurpExtender(IBurpExtender, ITab, IHttpListener, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks        = callbacks
        self._helpers          = callbacks.getHelpers()
        self._findings         = []
        self._lock             = threading.Lock()
        self._key_endpoints    = {}
        self._paused           = False
        self._statusLabel      = None
        self._selected_finding = None
        self._jwt_history      = []   # list of dicts for JWT tab

        callbacks.setExtensionName("TokenHound")
        SwingUtilities.invokeLater(self._buildUI)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        print("[TokenHound] Loaded OK")

    # -- UI --

    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.add(self._buildHeader(), BorderLayout.NORTH)
        self._mainPanel.add(self._buildTabs(),   BorderLayout.CENTER)
        self._mainPanel.add(self._buildStatus(), BorderLayout.SOUTH)
        self._callbacks.addSuiteTab(self)
        self._updateStats()

    # ---- Header ----
    def _buildHeader(self):
        p = JPanel(BorderLayout())
        p.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
            EmptyBorder(5, 8, 5, 8)))

        left = JLabel("TokenHound  |  Client-Side Encryption & Secret Detector")
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

        # Scan Proxy History button
        scanBtn = JButton("Scan Proxy History")
        scanBtn.setFont(Font("Dialog", Font.PLAIN, 11))
        scanBtn.addActionListener(lambda e: self._scanProxyHistory())

        for w in [self._lblCritical, self._lblHigh, self._lblMedium,
                  self._lblLow, self._lblTotal, scanBtn]:
            right.add(w)
        p.add(right, BorderLayout.EAST)
        return p

    # ---- Tabs ----
    def _buildTabs(self):
        self._tabs = JTabbedPane()
        self._tabs.addTab("Findings",       self._buildFindingsTab())
        self._tabs.addTab("Key Flow",       self._buildKeyFlowTab())
        self._tabs.addTab("Request Detail", self._buildDetailTab())
        self._tabs.addTab("JWT Analyzer",   self._buildJWTTab())
        self._tabs.addTab("Configuration",  self._buildConfigTab())
        return self._tabs

    # ---- Findings tab ----
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

        outer.add(toolbar, BorderLayout.NORTH)

        self._tableModel = NonEditableTableModel(
            ["#", "Time", "Severity", "Confidence", "Category", "Type", "Method", "URL", "Evidence"], 0)
        self._table = JTable(self._tableModel)
        self._table.setRowHeight(20)
        self._table.setFont(Font("Dialog", Font.PLAIN, 11))
        self._table.getTableHeader().setFont(Font("Dialog", Font.BOLD, 11))
        self._table.setAutoCreateRowSorter(True)

        cols = self._table.getColumnModel()
        cols.getColumn(0).setMaxWidth(40)
        cols.getColumn(1).setMaxWidth(65)
        cols.getColumn(2).setMaxWidth(80)
        cols.getColumn(3).setMaxWidth(90)
        cols.getColumn(4).setMaxWidth(125)
        cols.getColumn(5).setPreferredWidth(195)
        cols.getColumn(6).setMaxWidth(55)
        cols.getColumn(7).setPreferredWidth(260)
        cols.getColumn(8).setPreferredWidth(200)

        self._table.getColumnModel().getColumn(2).setCellRenderer(SeverityCellRenderer())
        self._table.getColumnModel().getColumn(3).setCellRenderer(ConfidenceCellRenderer())

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

    # ---- Key Flow tab ----
    def _buildKeyFlowTab(self):
        p = JPanel(BorderLayout())
        p.setBorder(EmptyBorder(8, 8, 8, 8))

        info = JLabel("<html><b>Key Flow Tracker</b> - Matches public-key endpoints to encrypted POST requests on same host</html>")
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

        note = JLabel("Flow CONFIRMED = base64-blob POST seen from same host that previously served a public key.")
        note.setFont(Font("Dialog", Font.ITALIC, 10))
        note.setBorder(EmptyBorder(5, 0, 0, 0))
        p.add(note, BorderLayout.SOUTH)
        return p

    # ---- Request Detail tab ----
    def _buildDetailTab(self):
        p = JPanel(BorderLayout())

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

        self._requestArea = JTextArea()
        self._requestArea.setEditable(False)
        self._requestArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._responseArea = JTextArea()
        self._responseArea.setEditable(False)
        self._responseArea.setFont(Font("Monospaced", Font.PLAIN, 11))

        reqScroll = JScrollPane(self._requestArea)
        reqScroll.setBorder(BorderFactory.createTitledBorder("Request"))
        resScroll = JScrollPane(self._responseArea)
        resScroll.setBorder(BorderFactory.createTitledBorder("Response"))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, reqScroll, resScroll)
        split.setResizeWeight(0.45)
        split.setDividerSize(5)
        p.add(split, BorderLayout.CENTER)
        return p

    # ---- JWT Analyzer tab ----
    def _buildJWTTab(self):
        p = JPanel(BorderLayout())
        p.setBorder(EmptyBorder(8, 8, 8, 8))

        # Top: input + decode button
        inputPanel = JPanel(BorderLayout(6, 0))
        inputPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("JWT Token Input"),
            EmptyBorder(4, 4, 4, 4)))

        self._jwtInput = JTextField()
        self._jwtInput.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._jwtInput.setToolTipText("Paste a JWT token (eyJ...) here or click a finding to auto-fill")

        btnDecode = JButton("Decode & Analyze")
        btnDecode.addActionListener(lambda e: self._decodeJWT())
        btnClear  = JButton("Clear")
        btnClear.addActionListener(lambda e: self._clearJWT())

        btnPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        btnPanel.add(btnDecode)
        btnPanel.add(btnClear)

        inputPanel.add(self._jwtInput, BorderLayout.CENTER)
        inputPanel.add(btnPanel,       BorderLayout.EAST)

        # Middle: decoded panels
        self._jwtHeaderArea  = JTextArea(4, 0)
        self._jwtHeaderArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._jwtHeaderArea.setEditable(False)

        self._jwtPayloadArea = JTextArea(10, 0)
        self._jwtPayloadArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._jwtPayloadArea.setEditable(False)

        self._jwtSigArea     = JTextArea(2, 0)
        self._jwtSigArea.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._jwtSigArea.setEditable(False)

        hdrScroll = JScrollPane(self._jwtHeaderArea)
        hdrScroll.setBorder(BorderFactory.createTitledBorder("Header (decoded)"))
        payScroll = JScrollPane(self._jwtPayloadArea)
        payScroll.setBorder(BorderFactory.createTitledBorder("Payload (decoded claims)"))
        sigScroll = JScrollPane(self._jwtSigArea)
        sigScroll.setBorder(BorderFactory.createTitledBorder("Signature (base64url)"))

        decodedSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, hdrScroll, payScroll)
        decodedSplit.setResizeWeight(0.25)
        decodedSplit.setDividerSize(4)

        fullSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, decodedSplit, sigScroll)
        fullSplit.setResizeWeight(0.85)
        fullSplit.setDividerSize(4)

        # Bottom: security warnings
        self._jwtWarningsModel = NonEditableTableModel(["Severity", "Warning"], 0)
        self._jwtWarningsTable = JTable(self._jwtWarningsModel)
        self._jwtWarningsTable.setRowHeight(20)
        self._jwtWarningsTable.setFont(Font("Dialog", Font.PLAIN, 11))
        self._jwtWarningsTable.getTableHeader().setFont(Font("Dialog", Font.BOLD, 11))
        self._jwtWarningsTable.getColumnModel().getColumn(0).setMaxWidth(80)
        self._jwtWarningsTable.getColumnModel().getColumn(0).setCellRenderer(SeverityCellRenderer())

        warningsScroll = JScrollPane(self._jwtWarningsTable)
        warningsScroll.setBorder(BorderFactory.createTitledBorder("Security Findings"))
        warningsScroll.setPreferredSize(Dimension(0, 160))

        # Claims summary
        self._jwtClaimsPanel = JPanel(GridLayout(4, 4, 6, 2))
        self._jwtClaimsPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder("Key Claims"),
            EmptyBorder(4, 4, 4, 4)))
        self._jwtClaimLabels = {}
        for field in ['alg', 'sub', 'iss', 'exp', 'iat', 'role', 'key', 'tcStatus']:
            lk = JLabel(field + ":")
            lk.setFont(Font("Dialog", Font.BOLD, 11))
            lv = JLabel("-")
            lv.setFont(Font("Dialog", Font.PLAIN, 11))
            self._jwtClaimsPanel.add(lk)
            self._jwtClaimsPanel.add(lv)
            self._jwtClaimLabels[field] = lv

        # JWT history table (seen tokens)
        self._jwtHistModel = NonEditableTableModel(
            ["Time", "URL", "alg", "sub", "role", "exp", "Warnings"], 0)
        self._jwtHistTable = JTable(self._jwtHistModel)
        self._jwtHistTable.setRowHeight(18)
        self._jwtHistTable.setFont(Font("Dialog", Font.PLAIN, 10))
        self._jwtHistTable.getTableHeader().setFont(Font("Dialog", Font.BOLD, 10))
        self._jwtHistTable.setAutoCreateRowSorter(True)
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
        histScroll.setBorder(BorderFactory.createTitledBorder("JWT History (auto-captured from traffic)"))

        # Assemble JWT tab layout
        mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, fullSplit, warningsScroll)
        mainSplit.setResizeWeight(0.5)

        centerPanel = JPanel(BorderLayout(0, 6))
        centerPanel.add(self._jwtClaimsPanel, BorderLayout.NORTH)
        centerPanel.add(mainSplit,             BorderLayout.CENTER)
        centerPanel.add(histScroll,            BorderLayout.SOUTH)

        p.add(inputPanel,  BorderLayout.NORTH)
        p.add(centerPanel, BorderLayout.CENTER)
        return p

    # ---- Config tab ----
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
        self._cbAsymmetric = cb("Asymmetric Keys (RSA, EC PEM blocks)", True)
        self._cbSymmetric  = cb("Symmetric Keys (AES, DES, CryptoJS)", True)
        self._cbCryptoLibs = cb("Crypto Library Detection (JSEncrypt, SubtleCrypto, node-forge)", True)
        self._cbKeyFlow    = cb("Key Flow Tracking (public-key fetch + encrypted POST)", True)
        self._cbHardcoded  = cb("Hardcoded Secrets & API Keys", True)
        self._cbJWT        = cb("JWT Auto-Capture (collect all JWTs from traffic)", True)

        section("Scope")
        self._cbInScope    = cb("Only scan in-scope targets", False)
        self._cbSkipStatic = cb("Skip static files (.png, .jpg, .gif, .woff, .ttf)", True)

        section("Severity to log")
        self._cbCritical   = cb("CRITICAL", True)
        self._cbHigh       = cb("HIGH", True)
        self._cbMedium     = cb("MEDIUM", True)
        self._cbLow        = cb("LOW", True)
        self._cbInfo       = cb("INFO", False)

        section("Output")
        self._cbHighlight  = cb("Auto-highlight requests in Proxy history", True)

        p.add(JScrollPane(grid), BorderLayout.CENTER)
        return p

    # ---- Status bar ----
    def _buildStatus(self):
        bar = JPanel(BorderLayout())
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY),
            EmptyBorder(3, 8, 3, 8)))
        self._statusLabel = JLabel("Ready - hunting...")
        self._statusLabel.setFont(Font("Dialog", Font.PLAIN, 11))
        bar.add(self._statusLabel, BorderLayout.WEST)
        ver = JLabel("TokenHound  |  {} patterns loaded".format(len(PATTERNS)))
        ver.setFont(Font("Dialog", Font.PLAIN, 11))
        bar.add(ver, BorderLayout.EAST)
        return bar

    # -- ITab --

    def getTabCaption(self):  return "TokenHound"
    def getUiComponent(self): return self._mainPanel

    # -- IHttpListener: fires for all proxied traffic --

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
                       ['.png','.jpg','.jpeg','.gif','.ico','.woff',
                        '.woff2','.ttf','.eot','.svg','.css','.pdf','.mp4']):
                    return

            if messageIsRequest:
                self._scanRequest(messageInfo, url, method)
            else:
                self._scanResponse(messageInfo, url, method)
        except Exception as ex:
            print("[TokenHound] processHttpMessage error: " + str(ex))

    # -- Retroactive scan of proxy history --

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
                               ['.png','.jpg','.jpeg','.gif','.ico','.woff',
                                '.woff2','.ttf','.eot','.svg','.css','.pdf','.mp4']):
                            continue
                        self._scanRequest(item, url, method)
                        self._scanResponse(item, url, method)
                    except Exception:
                        pass
                    if (i + 1) % 50 == 0:
                        self._updateStatus("History scan: {}/{} done...".format(i+1, total))
                self._updateStatus("History scan complete. {} items processed.".format(total))
            except Exception as ex:
                self._updateStatus("History scan error: " + str(ex))
        t = threading.Thread(target=_do)
        t.setDaemon(True)
        t.start()

    # -- Request scanner --

    def _scanRequest(self, msgInfo, url, method):
        try:
            req      = self._helpers.bytesToString(msgInfo.getRequest())
            analyzed = self._helpers.analyzeRequest(msgInfo)
            body     = req[analyzed.getBodyOffset():]
            headers  = req[:analyzed.getBodyOffset()]

            # collect JWTs from Authorization header (do not flag as findings)
            if self._cbJWT.isSelected():
                bearer_m = re.search(
                    r'Authorization\s*:\s*Bearer\s+(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)',
                    headers, re.IGNORECASE)
                if bearer_m:
                    self._captureJWT(bearer_m.group(1), url, 'Request Bearer')

            # --- Encrypted base64 blob POST
            if method == 'POST' and self._cbKeyFlow.isSelected():
                stripped = body.strip()
                if len(stripped) > 200 and re.match(r'^[A-Za-z0-9+/=]{200,}$', stripped):
                    _f = Finding(url, method, 'Key Flow',
                                 'Encrypted Payload (base64 blob POST)',
                                 'HIGH', stripped[:80] + '...', msgInfo)
                    _conf, _cs, _cr = _score_confidence(_f, '', url, stripped)
                    _f.confidence = _conf; _f.confidence_score = _cs
                    _f.confidence_reasons = _cr
                    self._addFinding(_f)
                    host = self._hostOf(url)
                    if host in self._key_endpoints:
                        self._recordKeyFlow(self._key_endpoints[host], url, method, 'CONFIRMED')

            # --- Secrets in request (exclude Authorization header lines)
            if self._cbHardcoded.isSelected():
                # Strip Authorization header lines before scanning request for JWT patterns
                # so we don't flag every authenticated request
                req_no_auth = re.sub(
                    r'Authorization\s*:\s*Bearer\s+eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
                    'Authorization: Bearer [SUPPRESSED]', req, flags=re.IGNORECASE)
                self._runPatterns(req_no_auth, 'Hardcoded Secret', url, method, msgInfo)

        except Exception as ex:
            print("[TokenHound] scanRequest error: " + str(ex))

    # -- Response scanner --

    def _scanResponse(self, msgInfo, url, method):
        try:
            resp = self._helpers.bytesToString(msgInfo.getResponse())
            if not resp:
                return

            analyzed     = self._helpers.analyzeResponse(resp)
            body         = resp[analyzed.getBodyOffset():]
            content_type = ''
            for h in analyzed.getHeaders():
                hl = str(h).lower()
                if 'content-type' in hl:
                    content_type = hl

            # skip binary responses
            BINARY_TYPES = ['image/', 'audio/', 'video/',
                            'application/octet-stream', 'application/pdf',
                            'application/zip', 'font/', 'text/plain']
            body_start   = body[:20].strip() if body else ''
            is_binary    = (body_start.startswith('/9j/') or
                            body_start.startswith('iVBOR') or
                            body_start.startswith('JVBER') or
                            '\x00' in body[:100])
            is_bin_ct    = any(bt in content_type for bt in BINARY_TYPES)
            if is_binary or is_bin_ct:
                return   # skip entirely

            is_code = any(ct in content_type for ct in
                          ['javascript', 'json', 'text/html', 'text/css', 'x-www'])
            if not content_type:
                is_code = True

            # JWT auto-capture from response body (token issuance)
            if self._cbJWT.isSelected():
                for jwt_m in re.finditer(
                    r'"(?:token|access_token|id_token|refresh_token)"\s*:\s*"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"',
                    body):
                    self._captureJWT(jwt_m.group(1), url, 'Response Issued')

            # Key flow URL detection
            if self._cbKeyFlow.isSelected():
                if re.search(r'/(?:encryption|crypto|security|api|v\d+)/(?:public-?key|pubkey|keys?|rsa)',
                             url, re.IGNORECASE):
                    host = self._hostOf(url)
                    self._key_endpoints[host] = url
                    _kf = Finding(url, method, 'Key Flow',
                                  'Public Key Distribution Endpoint', 'HIGH', url, msgInfo)
                    _kf.confidence = 'CONFIRMED'
                    _kf.confidence_score = 90
                    _kf.confidence_reasons = ['URL matches public-key endpoint pattern']
                    self._addFinding(_kf)

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
                                      content_type=content_type, full_response=resp)

        except Exception as ex:
            print("[TokenHound] scanResponse error: " + str(ex))

    # -- Pattern runner --

    def _runPatterns(self, content, category, url, method, msgInfo,
                     content_type='', full_response=''):
        seen = set()
        for (cat, pattern, label, severity) in PATTERNS:
            if cat != category:
                continue
            sev_ok = {
                'CRITICAL': self._cbCritical.isSelected(),
                'HIGH':     self._cbHigh.isSelected(),
                'MEDIUM':   self._cbMedium.isSelected(),
                'LOW':      self._cbLow.isSelected(),
                'INFO':     self._cbInfo.isSelected(),
            }
            if not sev_ok.get(severity, True):
                continue
            try:
                m = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
                if m:
                    key = (url, label)
                    if key not in seen:
                        seen.add(key)
                        evidence = m.group(0)[:200]
                        f = Finding(url, method, category, label, severity, evidence, msgInfo)
                        cl, cs, cr = _score_confidence(f, content_type, url, full_response or content)
                        f.confidence = cl; f.confidence_score = cs; f.confidence_reasons = cr
                        self._addFinding(f)
            except Exception:
                pass

    # -- JWT capture and analyzer --

    def _captureJWT(self, token, url, source):
    
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

        # Add HIGH/CRITICAL warnings as findings
        for w in decoded['warnings']:
            if w.startswith('CRITICAL') or w.startswith('HIGH'):
                sev = 'CRITICAL' if w.startswith('CRITICAL') else 'HIGH'
                f = Finding(url, 'JWT', 'Hardcoded Secret',
                            'JWT Security Issue: ' + w[:80], sev, token[:120], None)
                f.confidence = 'CONFIRMED'; f.confidence_score = 90
                f.confidence_reasons = ['JWT decoded and analyzed']
                self._addFinding(f)

        def _ui():
            self._jwtHistModel.addRow([
                entry['time'], url[:60], entry['alg'],
                entry['sub'][:20], entry['role'][:20], entry['exp'],
                str(len(decoded['warnings'])) + ' warning(s)'
            ])
        SwingUtilities.invokeLater(_ui)

    def _decodeJWT(self):
        token = self._jwtInput.getText().strip()
        if not token:
            return
        # Extract just the token if pasted as "Bearer eyJ..."
        m = re.search(r'(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)', token)
        if m:
            token = m.group(1)
            self._jwtInput.setText(token)

        decoded = _decode_jwt(token)

        self._jwtHeaderArea.setText(decoded['header_json'])
        self._jwtPayloadArea.setText(decoded['payload_json'])
        self._jwtSigArea.setText(decoded['signature_raw'])

        # Populate claim labels
        for field in ['alg', 'sub', 'iss', 'exp', 'iat', 'role', 'key', 'tcStatus']:
            val = decoded['claims'].get(field, decoded.get(field, '-'))
            lbl = self._jwtClaimLabels.get(field)
            if lbl:
                lbl.setText(str(val) if val else '-')

        # Populate warnings table
        self._jwtWarningsModel.setRowCount(0)
        for w in decoded['warnings']:
            sev = 'INFO'
            if w.startswith('CRITICAL'): sev = 'CRITICAL'
            elif w.startswith('HIGH'):   sev = 'HIGH'
            elif w.startswith('MEDIUM'): sev = 'MEDIUM'
            elif w.startswith('LOW'):    sev = 'LOW'
            self._jwtWarningsModel.addRow([sev, w])

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
    
        f = self._selected_finding
        if not f:
            self._updateStatus("No finding selected.")
            return
        try:
            req = self._helpers.bytesToString(f.request_response.getRequest())
            m = re.search(
                r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', req)
            if m:
                self._jwtInput.setText(m.group(0))
                self._decodeJWT()
                self._tabs.setSelectedIndex(3)  # switch to JWT tab
                self._updateStatus("JWT sent to analyzer.")
            else:
                self._updateStatus("No JWT found in this request.")
        except Exception as ex:
            self._updateStatus("JWT extract error: " + str(ex))

    # -- Add finding --

    def _addFinding(self, finding):
        with self._lock:
            for f in self._findings:
                if f.url == finding.url and f.finding_type == finding.finding_type:
                    return
            self._findings.append(finding)

        def update():
            self._tableModel.addRow([
                str(finding.num), finding.timestamp,
                finding.severity, finding.confidence,
                finding.category, finding.finding_type,
                finding.method, finding.url, finding.evidence
            ])
            self._updateStats()
            self._updateStatus("[{}][{}] {} - {}".format(
                finding.severity, finding.confidence,
                finding.finding_type, finding.url[:60]))
            if self._cbHighlight.isSelected() and finding.request_response:
                try:
                    c = {'CRITICAL':'red','HIGH':'orange',
                         'MEDIUM':'yellow','LOW':'cyan'}.get(finding.severity,'gray')
                    finding.request_response.setHighlight(c)
                    finding.request_response.setComment("[TH] " + finding.finding_type)
                except Exception:
                    pass
        SwingUtilities.invokeLater(update)

    def _recordKeyFlow(self, keyEp, consumerEp, method, status):
        def update():
            self._keyFlowModel.addRow([keyEp, 'RSA/Asymmetric', consumerEp,
                                       method, status, datetime.now().strftime('%H:%M:%S')])
        SwingUtilities.invokeLater(update)

    # -- IScannerCheck (passive only, no active requests) --

    def doPassiveScan(self, baseRequestResponse):  return None
    def doActiveScan(self, baseRequestResponse, insertionPoint): return None
    def consolidateDuplicateIssues(self, existingIssue, newIssue): return -1

    # -- Filter --

    def _applyFilter(self):
        sev    = str(self._sevFilter.getSelectedItem())
        cat    = str(self._catFilter.getSelectedItem())
        conf   = str(self._confFilter.getSelectedItem())
        search = self._searchField.getText().strip().lower()

        self._tableModel.setRowCount(0)
        with self._lock:
            findings_copy = list(self._findings)

        for f in findings_copy:
            if sev  != 'ALL' and f.severity   != sev:  continue
            if cat  != 'ALL' and f.category   != cat:  continue
            if conf != 'ALL' and f.confidence != conf: continue
            if search:
                if search not in (f.url + f.finding_type + f.evidence + f.category).lower():
                    continue
            self._tableModel.addRow([
                str(f.num), f.timestamp, f.severity, f.confidence,
                f.category, f.finding_type, f.method, f.url, f.evidence
            ])

    # -- Detail view --

    def _findingForRow(self, model_row):
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
        if not finding: return
        self._selected_finding = finding

        self._detailLabels["Type"].setText(finding.finding_type)
        sl = self._detailLabels["Severity"]
        sl.setText(finding.severity)
        sl.setForeground(SEV_COLORS.get(finding.severity, Color.BLACK))
        cl = self._detailLabels["Confidence"]
        cl.setText(finding.confidence)
        cl.setForeground(CONF_COLORS.get(finding.confidence, Color.BLACK))
        reasons = " | ".join(finding.confidence_reasons) if finding.confidence_reasons else "-"
        self._detailLabels["Score"].setText(
            "{}/100  ->  {}".format(finding.confidence_score, reasons[:110]))
        self._detailLabels["Category"].setText(finding.category)
        self._detailLabels["URL"].setText(finding.url[:140])
        self._detailLabels["Method"].setText(finding.method)
        self._detailLabels["Time"].setText(finding.timestamp)
        self._detailLabels["Pattern matched"].setText(finding.finding_type)
        self._detailLabels["Evidence"].setText(finding.evidence[:140])

        try:
            req = self._helpers.bytesToString(finding.request_response.getRequest())
            self._requestArea.setText(req[:8000] if req else "(no request)")
            self._requestArea.setCaretPosition(0)
        except Exception:
            self._requestArea.setText("(unavailable)")
        try:
            res = finding.request_response.getResponse()
            self._responseArea.setText(
                self._helpers.bytesToString(res)[:10000] if res else "(no response)")
            self._responseArea.setCaretPosition(0)
        except Exception:
            self._responseArea.setText("(unavailable)")

    def _showContextMenu(self, e, finding):
        if not finding: return
        menu = JPopupMenu()
        items = [
            ("Send to Repeater",   lambda ev: self._sendToRepeater()),
            ("Send to Intruder",   lambda ev: self._sendToIntruder()),
            ("Show in Proxy",      lambda ev: self._highlightInProxy()),
            ("Send JWT to Analyzer", lambda ev: self._sendJWTFromDetail()),
            ("Copy URL",           lambda ev: self._copyToClipboard(finding.url)),
            ("Copy Evidence",      lambda ev: self._copyToClipboard(finding.evidence)),
        ]
        for label, action in items:
            mi = JMenuItem(label)
            mi.addActionListener(action)
            menu.add(mi)
        menu.show(e.getComponent(), e.getX(), e.getY())

    def _sendToRepeater(self):
        f = self._selected_finding
        if not f: return
        try:
            rr = f.request_response
            ri = self._helpers.analyzeRequest(rr)
            h  = ri.getUrl().getHost()
            pt = ri.getUrl().getPort()
            if pt == -1: pt = 443 if ri.getUrl().getProtocol() == 'https' else 80
            self._callbacks.sendToRepeater(h, pt,
                ri.getUrl().getProtocol().lower() == 'https', rr.getRequest(), "TokenHound")
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
            if pt == -1: pt = 443 if ri.getUrl().getProtocol() == 'https' else 80
            self._callbacks.sendToIntruder(h, pt,
                ri.getUrl().getProtocol().lower() == 'https', rr.getRequest())
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

    # -- CSV export --

    def _exportCSV(self):
        try:
            fc = JFileChooser()
            fc.setSelectedFile(File("cryptoscanner_findings.csv"))
            if fc.showSaveDialog(self._mainPanel) != JFileChooser.APPROVE_OPTION:
                return
            path = fc.getSelectedFile().getAbsolutePath()
            with self._lock:
                findings_copy = list(self._findings)
            bw = BufferedWriter(FileWriter(path))
            bw.write("Num,Time,Severity,Confidence,Score,Category,Type,Method,URL,Evidence,Reasons\r\n")
            for f in findings_copy:
                def esc(s): return '"' + str(s).replace('"', '""') + '"'
                bw.write(",".join([
                    str(f.num), f.timestamp,
                    esc(f.severity), esc(f.confidence), str(f.confidence_score),
                    esc(f.category), esc(f.finding_type), esc(f.method),
                    esc(f.url), esc(f.evidence),
                    esc(" | ".join(f.confidence_reasons))
                ]) + "\r\n")
            bw.close()
            self._updateStatus("Exported {} results -> {}".format(len(findings_copy), path))
        except Exception as ex:
            self._updateStatus("Export error: " + str(ex))

    # -- Misc --

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
        self._updateStatus("Scanning " + ("PAUSED" if self._paused else "RESUMED"))

    def _updateStats(self):
        def update():
            with self._lock:
                counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'INFO':0}
                for f in self._findings:
                    counts[f.severity] = counts.get(f.severity, 0) + 1
                total = len(self._findings)
            if hasattr(self, '_lblCritical'):
                self._lblCritical.setText("CRITICAL: " + str(counts['CRITICAL']))
                self._lblHigh.setText    ("HIGH: "     + str(counts['HIGH']))
                self._lblMedium.setText  ("MEDIUM: "   + str(counts['MEDIUM']))
                self._lblLow.setText     ("LOW: "      + str(counts['LOW']))
                self._lblTotal.setText   ("Total: "    + str(total))
        SwingUtilities.invokeLater(update)

    def _updateStatus(self, msg):
        def update():
            if self._statusLabel:
                self._statusLabel.setText("[{}]  {}".format(
                    datetime.now().strftime('%H:%M:%S'), msg))
        SwingUtilities.invokeLater(update)

    def _hostOf(self, url):
        try:
            return url.split('/')[2]
        except Exception:
            return url


# --- Cell renderers ---

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
        comp.setForeground(CONF_COLORS.get(str(value), Color.BLACK))
        comp.setFont(Font("Dialog", Font.BOLD, 11))
        return comp