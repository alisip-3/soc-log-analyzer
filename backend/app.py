from flask import Flask, request, jsonify
from flask_cors import CORS
import csv
import io
import re
import os
from collections import Counter
import google.generativeai as genai

app = Flask(__name__)
CORS(app)

# Configure Gemini AI
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-1.5-flash")
else:
    model = None


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
        content = file.read().decode('utf-8', errors='ignore')
        lines = content.strip().split('\n')

        results = {
            "filename": file.filename,
            "total_lines": len(lines),
            "findings": [],
            "summary": {}
        }

        if filename.endswith('.csv'):
            results = analyze_csv(content, results)
        elif filename.endswith('.log') or filename.endswith('.txt'):
            results = analyze_log(content, results)
        else:
            results["findings"].append({
                "severity": "INFO",
                "title": "Unknown file type",
                "description": f"File type not fully supported. Showing basic stats.",
                "mitre": ""
            })
            results["summary"] = {"total_lines": len(lines)}

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================
# ENDPOINT 2: Generate AI Report
# ============================================
@app.route('/generate-report', methods=['POST'])
def generate_report():
    if not model:
        return jsonify({"error": "Gemini API key not configured"}), 500

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
        screenshots_block = f"""
EVIDENCE SCREENSHOTS PROVIDED BY THE ANALYST:
{screenshots_text}
"""

    prompt = f"""You are a senior SOC analyst writing a professional Incident Response report.

Incident Name: {incident_name}
Severity: {severity}

INVESTIGATION FINDINGS:
{findings_text}

ADDITIONAL ANALYST NOTES:
{additional_notes}
{screenshots_block}

Write a complete, professional Incident Response report with EXACTLY these sections:

# Incident Response Report: {incident_name}

## 1. Header & Metadata
- Incident ID: IR-001
- Severity: {severity}
- Status: Under Investigation
- Analyst: SOC Team

## 2. Executive Summary
[High-level overview for management. What happened, business impact, current status.]

## 3. MITRE ATT&CK Kill Chain Mapping
| Kill Chain Phase | MITRE Technique | Evidence |
|---|---|---|
| Initial Access | [ID - Name] | [What we found] |
[Only include phases with evidence. Otherwise write "Not observed."]

## 4. Incident Timeline
[Chronological sequence of events based on the findings.]

## 5. Technical Analysis
[Detailed breakdown: entry vector, adversary actions, IOCs (IPs, domains, hashes, accounts).]

## 6. Forensic Evidence & Screenshots
[List all evidence and what it revealed. Reference the provided screenshots by number, e.g. "(see Screenshot #1)". If screenshots were listed, mention each one and what it supports.]

## 7. Containment, Eradication & Recovery
[Recommended actions: isolation, removal, verification, restoration.]

## 8. Post-Incident Recommendations
[Immediate fixes, long-term improvements, lessons learned.]

RULES:
- Be specific. Reference actual data from the findings.
- Do NOT invent information not in the findings.
- Use real MITRE ATT&CK technique IDs (e.g., T1566, T1078, T1021).
- Write in markdown format.
"""

    try:
        response = model.generate_content(prompt)
        return jsonify({"report": response.text})
    except Exception as e:
        return jsonify({"error": f"AI generation failed: {str(e)}"}), 500
        

# ============================================
# Helper: Analyze CSV files
# ============================================
def analyze_csv(content, results):
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)

    if not rows:
        results["findings"].append({
            "severity": "INFO",
            "title": "Empty CSV",
            "description": "The CSV file has no data rows.",
            "mitre": ""
        })
        return results

    results["summary"]["total_rows"] = len(rows)
    results["summary"]["columns"] = list(rows[0].keys())

    # Find IP columns
    ip_columns = [col for col in rows[0].keys() if 'ip' in col.lower() or 'src' in col.lower() or 'dst' in col.lower()]

    for col in ip_columns:
        ip_counts = Counter(row.get(col, '') for row in rows if row.get(col, ''))
        if ip_counts:
            top_ip, top_count = ip_counts.most_common(1)[0]
            results["summary"][f"top_{col}"] = {"ip": top_ip, "count": top_count}

            if top_count > len(rows) * 0.5:
                results["findings"].append({
                    "severity": "HIGH",
                    "title": f"Dominant IP in {col}",
                    "description": f"IP {top_ip} appears {top_count} times out of {len(rows)} events ({round(top_count/len(rows)*100)}%).",
                    "mitre": "T1595 - Active Scanning"
                })

    # Check for failed logins
    failed_count = sum(1 for row in rows if any('fail' in str(v).lower() or '4625' in str(v) for v in row.values()))
    if failed_count > 10:
        results["findings"].append({
            "severity": "HIGH",
            "title": "Multiple Failed Logins Detected",
            "description": f"Found {failed_count} failed login events. Possible brute force attack.",
            "mitre": "T1110 - Brute Force"
        })

    # Check for unusual ports
    port_columns = [col for col in rows[0].keys() if 'port' in col.lower()]
    for col in port_columns:
        ports = set(row.get(col, '') for row in rows if row.get(col, ''))
        suspicious_ports = ports.intersection({'4444', '5555', '6666', '8888', '9999', '31337'})
        if suspicious_ports:
            results["findings"].append({
                "severity": "MEDIUM",
                "title": "Suspicious Port Usage",
                "description": f"Connections on unusual ports: {', '.join(suspicious_ports)}.",
                "mitre": "T1571 - Non-Standard Port"
            })

    if not results["findings"]:
        results["findings"].append({
            "severity": "LOW",
            "title": "No Immediate Threats Detected",
            "description": "Basic analysis did not find obvious suspicious patterns.",
            "mitre": ""
        })

    return results


# ============================================
# Helper: Analyze log files
# ============================================
def analyze_log(content, results):
    lines = content.strip().split('\n')
    results["summary"]["total_lines"] = len(lines)

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    all_ips = re.findall(ip_pattern, content)
    if all_ips:
        ip_counts = Counter(all_ips)
        top_ips = ip_counts.most_common(5)
        results["summary"]["top_ips"] = [{"ip": ip, "count": count} for ip, count in top_ips]

        if top_ips and top_ips[0][1] > len(lines) * 0.3:
            results["findings"].append({
                "severity": "HIGH",
                "title": "Dominant IP Address",
                "description": f"IP {top_ips[0][0]} appears {top_ips[0][1]} times.",
                "mitre": "T1595 - Active Scanning"
            })

    failed_lines = [l for l in lines if 'fail' in l.lower() or 'invalid' in l.lower()]
    if len(failed_lines) > 10:
        results["findings"].append({
            "severity": "HIGH",
            "title": "Multiple Failed Logins",
            "description": f"Found {len(failed_lines)} failed login events.",
            "mitre": "T1110 - Brute Force"
        })

    suspicious_keywords = ['malware', 'exploit', 'injection', 'backdoor', 'trojan', 'ransomware']
    for keyword in suspicious_keywords:
        matches = [l for l in lines if keyword in l.lower()]
        if matches:
            results["findings"].append({
                "severity": "HIGH",
                "title": f"Suspicious Keyword: {keyword}",
                "description": f"Found {len(matches)} lines containing '{keyword}'.",
                "mitre": "T1059 - Command and Scripting Interpreter"
            })

    if not results["findings"]:
        results["findings"].append({
            "severity": "LOW",
            "title": "No Immediate Threats Detected",
            "description": "Basic analysis did not find obvious suspicious patterns.",
            "mitre": ""
        })

    return results


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
