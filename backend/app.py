from flask import Flask, request, jsonify
from flask_cors import CORS
import csv
import io
import re
import os
import json
import urllib.request
from collections import Counter
from google import genai

app = Flask(__name__)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB upload limit


@app.errorhandler(413)
def too_big(e):
    return jsonify({"error": "File too large. Free hosting limit is 20 MB. Try a smaller capture."}), 413


# ============================================
# API CONFIGURATION 
# ============================================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    client = None

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "SOC Log Analyzer API is running!"})


# ============================================
# ENDPOINT 1: Analyze uploaded file
# ============================================
@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    filename = file.filename.lower()

    try:
        raw = file.read()
        results = {
            "filename": file.filename,
            "total_lines": 0,
            "findings": [],
            "summary": {}
        }

        if filename.endswith(('.pcap', '.cap', '.pcapng')):
            results = analyze_pcap(raw, results)
        else:
            content = raw.decode('utf-8', errors='ignore')
            results["total_lines"] = len(content.strip().split('\n'))
            if filename.endswith('.csv'):
                results = analyze_csv(content, results)
            elif filename.endswith('.json'):
                results = analyze_json(content, results)
            elif filename.endswith(('.log', '.txt', '.tsv')):
                results = analyze_log(content, results)
            else:
                add_finding(results, "INFO", "Unknown file type",
                            "File type not fully supported.", "")

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================
# ENDPOINT 2: Generate AI Report 
# ============================================

@app.route('/generate-report', methods=['POST'])
def generate_report():
    if not GEMINI_API_KEY:
        return jsonify({"error": "Gemini API key not configured on server"}), 500

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    findings_text = data.get("findings", "")
    incident_name = data.get("incident_name", "Security Incident")
    severity = data.get("severity", "Medium")
    additional_notes = data.get("additional_notes", "")
    screenshots_text = data.get("screenshots", "")

    screenshots_block = ""
    if screenshots_text:
        screenshots_block = f"\nEVIDENCE SCREENSHOTS PROVIDED BY THE ANALYST:\n{screenshots_text}\n"

    prompt = f"""You are a senior defensive SOC analyst writing an official Incident Response report for internal defensive analysis.

Incident Name: {incident_name}
Severity: {severity}

INVESTIGATION FINDINGS:
{findings_text}

ADDITIONAL ANALYST NOTES:
{additional_notes}
{screenshots_block}

Write a complete, professional Incident Response report with EXACTLY these sections:

INCIDENT RESPONSE REPORT: {incident_name}

1. HEADER & METADATA
(Incident ID, Severity, Status, Analyst, Date)

2. EXECUTIVE SUMMARY

3. MITRE ATT&CK KILL CHAIN MAPPING
(Write one line per technique, like: Initial Access: T1566 (Phishing) - Evidence: ...)

4. INCIDENT TIMELINE

5. TECHNICAL ANALYSIS

6. FORENSIC EVIDENCE & SCREENSHOTS

7. CONTAINMENT, ERADICATION & RECOVERY

8. POST-INCIDENT RECOMMENDATIONS

FORMATTING RULES:
- Write in clean, readable plain text.
- Do NOT use markdown headers (# or ##), bolding (**), or markdown tables.
- Use UPPERCASE for section titles and put a line of dashes (----) under each title.
- Reference the actual IPs, ports, hashes, and log events from the findings.
- Do NOT invent information that is not in the findings.
- Map observed events to real MITRE ATT&CK technique IDs (e.g., T1566, T1078, T1021, T1110).
"""

    # Use primary and fallback models supported by the current SDK
    models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash"]
    last_error = None

    for model_name in models_to_try:
        try:
            # Initialize client per request or use the global instance
            genai_client = genai.Client(api_key=GEMINI_API_KEY)
            
            response = genai_client.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            
            if response and response.text:
                print(f"SUCCESS with model: {model_name}")
                return jsonify({"report": response.text})
            else:
                last_error = f"Model {model_name} returned empty text (possibly blocked by safety filters)."
                print(last_error)
                
        except Exception as e:
            last_error = str(e)
            print(f"Model {model_name} failed: {e}")
            continue

    # Return detailed error message if all attempts fail
    return jsonify({
        "error": "Failed to generate report with Gemini API.",
        "details": last_error
    }), 500


# ============================================
# ENHANCED ANALYSIS ENGINE
# ============================================

SUSPICIOUS_PORTS = {
    '21': 'FTP', '23': 'Telnet', '135': 'RPC', '139': 'NetBIOS', '445': 'SMB',
    '3389': 'RDP', '5900': 'VNC', '4444': 'Metasploit', '5555': 'Backdoor',
    '6666': 'IRC backdoor', '8888': 'Alt HTTP', '9999': 'Backdoor', '1337': 'Elite',
    '31337': 'Back Orifice', '4443': 'Alt HTTPS', '1234': 'Backdoor', '666': 'Backdoor', '9001': 'Tor'
}

LOTL_PATTERNS = [
    ('powershell -enc', 'T1059.001 - Encoded PowerShell'),
    ('-encodedcommand', 'T1059.001 - Encoded PowerShell'),
    ('-nop -w hidden', 'T1059.001 - Hidden PowerShell'),
    ('downloadstring', 'T1059.001 - PowerShell DownloadString'),
    ('invoke-webrequest', 'T1105 - PowerShell web download'),
    ('iex(', 'T1059.001 - Invoke-Expression'),
    ('certutil -urlcache', 'T1105 - Certutil download'),
    ('certutil -decode', 'T1140 - Certutil decode'),
    ('wmic process call create', 'T1047 - WMI execution'),
    ('bitsadmin /transfer', 'T1197 - BITS transfer'),
    ('rundll32', 'T1218.011 - Rundll32'),
    ('regsvr32', 'T1218.010 - Regsvr32'),
    ('mshta', 'T1218.005 - Mshta'),
    ('vssadmin delete shadows', 'T1490 - Inhibit System Recovery'),
    ('net user /add', 'T1136 - Create Account'),
    ('whoami /priv', 'T1033 - Privilege discovery'),
    ('nltest', 'T1482 - Domain Trust Discovery'),
]

OFFICE_PARENTS = ['winword', 'excel', 'outlook', 'powerpnt']
SHELL_CHILDREN = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', 'rundll32']


def add_finding(results, severity, title, description, mitre):
    results["findings"].append({
        "severity": severity, "title": title,
        "description": description, "mitre": mitre
    })


def get_col(columns, keywords):
    for col in columns:
        low = col.lower()
        for k in keywords:
            if k in low:
                return col
    return None


def is_private_ip(ip):
    return (ip.startswith('10.') or ip.startswith('192.168.') or
            ip.startswith('127.') or
            any(ip.startswith(f'172.{i}.') for i in range(16, 32)))


def lookup_country(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode())
            return data.get('country')
    except Exception:
        return None


def check_hash_virustotal(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        req = urllib.request.Request(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 0
            return (malicious, total)
    except Exception:
        return None


def detect_lotl(results, text):
    low = text.lower()
    found = [(p, m) for p, m in LOTL_PATTERNS if p in low]
    if found:
        names = ', '.join(p for p, _ in found[:6])
        add_finding(results, "HIGH", "Living-off-the-Land (LotL) Activity",
                    f"Abused legitimate tools detected: {names}.", found[0][1])


def detect_parent_child(results, rows):
    if not rows:
        return
    cols = rows[0].keys()
    parent_col = get_col(cols, ['parent'])
    child_col = get_col(cols, ['image', 'process', 'program', 'child'])
    if not parent_col or not child_col:
        return
    hits = []
    for row in rows:
        p = str(row.get(parent_col, '')).lower()
        c = str(row.get(child_col, '')).lower()
        if any(o in p for o in OFFICE_PARENTS) and any(s in c for s in SHELL_CHILDREN):
            hits.append(f"{row.get(parent_col)} → {row.get(child_col)}")
    if hits:
        add_finding(results, "HIGH", "Suspicious Parent-Child Process",
                    f"Office app spawned a shell (possible macro malware): {', '.join(hits[:5])}",
                    "T1204.002 - Malicious File")


def detect_ports(results, rows, text):
    found = set()
    if rows:
        port_cols = [c for c in rows[0].keys() if 'port' in c.lower()]
        for col in port_cols:
            for row in rows:
                val = str(row.get(col, '')).strip()
                if val in SUSPICIOUS_PORTS:
                    found.add(f"{val} ({SUSPICIOUS_PORTS[val]})")
    else:
        for port, name in SUSPICIOUS_PORTS.items():
            if re.search(rf'[:\s]{port}\b', text):
                found.add(f"{port} ({name})")
    if found:
        add_finding(results, "MEDIUM", "Suspicious Port Usage",
                    f"Connections on unusual ports: {', '.join(sorted(found))}.", "T1571 - Non-Standard Port")


def detect_dns(results, text):
    low = text.lower()
    suspicious = set(re.findall(r'\b([a-z0-9\-\.]+\.(?:ru|cn|xyz|top|tk|ml|ga|cf|gq))\b', low))
    for m in re.findall(r'\b([a-z0-9\-]{30,}\.[a-z]{2,})\b', low):
        suspicious.add(m + ' (possible DNS tunneling)')
    if suspicious:
        add_finding(results, "MEDIUM", "Suspicious Domains / DNS",
                    f"Flagged: {', '.join(sorted(suspicious)[:6])}. High-risk TLDs or long subdomains.",
                    "T1071.004 - DNS C2")


def detect_large_transfer(results, rows):
    if not rows:
        return
    byte_col = get_col(rows[0].keys(), ['byte', 'size', 'sent', 'out'])
    if not byte_col:
        return
    big = []
    for row in rows:
        try:
            val = int(re.sub(r'\D', '', str(row.get(byte_col, '0'))) or 0)
            if val > 100_000_000:
                big.append(f"{row.get('src_ip', '?')} → {row.get('dst_ip', '?')} ({val / 1e6:.0f}MB)")
        except Exception:
            pass
    if big:
        add_finding(results, "HIGH", "Large Outbound Data Transfer",
                    f"Possible exfiltration: {', '.join(big[:5])}", "T1048 - Exfiltration")


def detect_external_geo(results, text):
    ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))
    external = [ip for ip in ips if not is_private_ip(ip)]
    if not external:
        return
    threats = []
    for ip in external[:3]:
        country = lookup_country(ip)
        if country:
            threats.append(f"{ip} ({country})")
    if threats:
        add_finding(results, "MEDIUM", "External Connections (Geo Check)",
                    f"External IPs contacted: {', '.join(threats)}. Verify these locations are expected.",
                    "T1583 - Acquire Infrastructure")


def detect_hashes(results, text):
    hashes = {}
    for m in re.findall(r'\b[a-fA-F0-9]{32}\b', text):
        hashes[m] = 'MD5'
    for m in re.findall(r'\b[a-fA-F0-9]{40}\b', text):
        hashes[m] = 'SHA1'
    for m in re.findall(r'\b[a-fA-F0-9]{64}\b', text):
        hashes[m] = 'SHA256'

    if not hashes:
        return

    results["summary"]["hashes"] = [
        {"hash": h, "type": t} for h, t in list(hashes.items())[:10]
    ]
    sample = ', '.join(list(hashes.keys())[:2])
    add_finding(results, "MEDIUM", "File Hashes Detected (IOCs)",
                f"Found {len(hashes)} file hash(es) e.g. {sample}. "
                f"Check these against VirusTotal / threat intel.",
                "T1059 - Malicious file hashes present")

    if VIRUSTOTAL_API_KEY:
        for h, t in list(hashes.items())[:2]:
            vt = check_hash_virustotal(h)
            if vt and vt[0] > 0:
                add_finding(results, "HIGH", f"Known-Malicious Hash ({t})",
                            f"Hash {h} flagged by {vt[0]}/{vt[1]} security engines on VirusTotal.",
                            "T1059 - Confirmed malicious file")


def detect_beaconing(results, rows):
    if not rows:
        return
    score_col = get_col(rows[0].keys(), ['score'])
    conn_col = get_col(rows[0].keys(), ['connections', 'count'])
    src_col = get_col(rows[0].keys(), ['src', 'source'])
    dst_col = get_col(rows[0].keys(), ['dst', 'destination', 'dest'])
    hits = []
    for row in rows:
        try:
            score = float(row.get(score_col, 0)) if score_col else 0
            conns = int(row.get(conn_col, 0)) if conn_col else 0
        except Exception:
            continue
        if score >= 0.8 or conns >= 100:
            s = row.get(src_col, '?') if src_col else '?'
            d = row.get(dst_col, '?') if dst_col else '?'
            hits.append(f"{s} → {d}")
    if hits:
        add_finding(results, "HIGH", "Beaconing / C2 Pattern (RITA)",
                    f"Regular callback pattern: {', '.join(hits[:5])}. Consistent with C2 beaconing.",
                    "T1071.001 - Web C2")


# ============================================
# JSON ANALYZER (Suricata)
# ============================================
def analyze_json(content, results):
    rows = []
    try:
        for line in content.strip().split('\n'):
            line = line.strip().rstrip(',')
            if line in ('', '[', ']'):
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
    except Exception:
        rows = []
    if not rows:
        try:
            data = json.loads(content)
            if isinstance(data, list):
                rows = [d for d in data if isinstance(d, dict)]
        except Exception:
            rows = []

    if not rows:
        add_finding(results, "INFO", "Unreadable JSON", "Could not parse JSON objects.", "")
        return results

    results["summary"]["total_rows"] = len(rows)

    alerts = [r for r in rows if r.get('event_type') == 'alert']
    if alerts:
        sigs = set()
        for a in alerts:
            al = a.get('alert')
            if isinstance(al, dict) and al.get('signature'):
                sigs.add(al['signature'])
        add_finding(results, "HIGH", "IDS Alerts Present (Suricata)",
                    f"{len(alerts)} alerts. Signatures: {', '.join(list(sigs)[:3])}.", "T1059 - IDS alerts")

    src_ips = Counter(str(r.get('src_ip', '')) for r in rows if r.get('src_ip'))
    if src_ips:
        top_ip, top_count = src_ips.most_common(1)[0]
        results["summary"]["top_src_ip"] = {"ip": top_ip, "count": top_count}
        if top_count > len(rows) * 0.5:
            add_finding(results, "HIGH", "Dominant Source IP",
                        f"IP {top_ip} appears {top_count}/{len(rows)} events.", "T1595 - Active Scanning")

    detect_parent_child(results, rows)
    detect_ports(results, rows, content)
    detect_large_transfer(results, rows)
    detect_beaconing(results, rows)
    detect_lotl(results, content)
    detect_dns(results, content)
    detect_hashes(results, content)
    detect_external_geo(results, content)

    if not results["findings"]:
        add_finding(results, "LOW", "No Immediate Threats Detected", "No obvious suspicious patterns.", "")
    return results


# ============================================
# PCAP ANALYZER
# ============================================
def analyze_pcap(raw, results):
    try:
        import dpkt, socket
    except ImportError:
        add_finding(results, "INFO", "PCAP support not installed",
                    "dpkt library missing on server.", "")
        return results

    try:
        try:
            pcap = dpkt.pcap.Reader(io.BytesIO(raw))
        except Exception:
            pcap = dpkt.pcapng.Reader(io.BytesIO(raw))
    except Exception:
        add_finding(results, "INFO", "Unreadable PCAP", "Could not parse the capture.", "")
        return results

    ip_counter = Counter()
    ports = set()
    dns_names = []
    total = 0
    MAX = 50000

    for ts, buf in pcap:
        total += 1
        if total > MAX:
            break
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            src = socket.inet_ntoa(ip.src)
            ip_counter[src] += 1
            trans = ip.data
            if isinstance(trans, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                ports.add(trans.dport)
                if trans.dport == 53 or trans.sport == 53:
                    try:
                        dns = dpkt.dns.DNS(trans.data)
                        for q in dns.qd:
                            dns_names.append(q.name.decode('errors', 'ignore'))
                    except Exception:
                        pass
        except Exception:
            continue

    results["summary"]["total_packets"] = total

    if ip_counter:
        top_ip, top_count = ip_counter.most_common(1)[0]
        results["summary"]["top_src_ip"] = {"ip": top_ip, "count": top_count}
        if total and top_count > total * 0.4:
            add_finding(results, "HIGH", "Dominant Talker",
                        f"IP {top_ip} sent {top_count}/{total} packets.", "T1595 - Active Scanning")

    susp = {str(p) for p in ports if str(p) in SUSPICIOUS_PORTS}
    if susp:
        add_finding(results, "MEDIUM", "Suspicious Ports",
                    f"Ports seen: {', '.join(sorted(susp))}.", "T1571 - Non-Standard Port")

    if dns_names:
        detect_dns(results, ' '.join(dns_names))

    ext = [ip for ip in ip_counter if not is_private_ip(ip)]
    if ext:
        threats = []
        for ip in ext[:3]:
            c = lookup_country(ip)
            if c:
                threats.append(f"{ip} ({c})")
        if threats:
            add_finding(results, "MEDIUM", "External Connections (Geo Check)",
                        f"External IPs: {', '.join(threats)}.", "T1583 - Acquire Infrastructure")

    if not results["findings"]:
        add_finding(results, "LOW", "No Immediate Threats Detected",
                    "No obvious suspicious patterns in this capture.", "")
    return results


# ============================================
# CSV ANALYZER (Splunk / RITA)
# ============================================
def analyze_csv(content, results):
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)

    if not rows:
        add_finding(results, "INFO", "Empty CSV", "The CSV file has no data rows.", "")
        return results

    results["summary"]["total_rows"] = len(rows)
    results["summary"]["columns"] = list(rows[0].keys())

    ip_columns = [c for c in rows[0].keys() if 'ip' in c.lower() or 'src' in c.lower() or 'dst' in c.lower()]
    for col in ip_columns:
        ip_counts = Counter(row.get(col, '') for row in rows if row.get(col, ''))
        if ip_counts:
            top_ip, top_count = ip_counts.most_common(1)[0]
            results["summary"][f"top_{col}"] = {"ip": top_ip, "count": top_count}
            if top_count > len(rows) * 0.5:
                add_finding(results, "HIGH", f"Dominant IP in {col}",
                            f"IP {top_ip} appears {top_count}/{len(rows)} events ({round(top_count / len(rows) * 100)}%).",
                            "T1595 - Active Scanning")

    failed = sum(1 for row in rows if any('fail' in str(v).lower() or '4625' in str(v) for v in row.values()))
    if failed > 10:
        add_finding(results, "HIGH", "Multiple Failed Logins",
                    f"Found {failed} failed login events. Possible brute force.", "T1110 - Brute Force")

    detect_lotl(results, content)
    detect_parent_child(results, rows)
    detect_ports(results, rows, content)
    detect_dns(results, content)
    detect_large_transfer(results, rows)
    detect_external_geo(results, content)
    detect_hashes(results, content)
    detect_beaconing(results, rows)

    if not results["findings"]:
        add_finding(results, "LOW", "No Immediate Threats Detected",
                    "Basic analysis found no obvious suspicious patterns.", "")
    return results


# ============================================
# LOG ANALYZER (Zeek / Linux)
# ============================================
def analyze_log(content, results):
    lines = content.strip().split('\n')
    results["summary"]["total_lines"] = len(lines)

    all_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
    if all_ips:
        top_ips = Counter(all_ips).most_common(5)
        results["summary"]["top_ips"] = [{"ip": i, "count": c} for i, c in top_ips]
        if top_ips and top_ips[0][1] > len(lines) * 0.3:
            add_finding(results, "HIGH", "Dominant IP Address",
                        f"IP {top_ips[0][0]} appears {top_ips[0][1]} times.", "T1595 - Active Scanning")

    failed = [l for l in lines if 'fail' in l.lower() or 'invalid' in l.lower()]
    if len(failed) > 10:
        add_finding(results, "HIGH", "Multiple Failed Logins",
                    f"Found {len(failed)} failed login events.", "T1110 - Brute Force")

    for kw in ['malware', 'exploit', 'injection', 'backdoor', 'trojan', 'ransomware']:
        matches = [l for l in lines if kw in l.lower()]
        if matches:
            add_finding(results, "HIGH", f"Suspicious Keyword: {kw}",
                        f"Found {len(matches)} lines containing '{kw}'.", "T1059 - Command Interpreter")

    detect_lotl(results, content)
    detect_ports(results, None, content)
    detect_dns(results, content)
    detect_external_geo(results, content)
    detect_hashes(results, content)

    if not results["findings"]:
        add_finding(results, "LOW", "No Immediate Threats Detected",
                    "Basic analysis found no obvious suspicious patterns.", "")
    return results


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
