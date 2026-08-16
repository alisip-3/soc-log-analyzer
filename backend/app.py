from flask import Flask, request, jsonify
from flask_cors import CORS
import csv
import io
import re
from collections import Counter

app = Flask(__name__)
CORS(app)  # This allows GitHub Pages to talk to Render


@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "SOC Log Analyzer API is running!"})


@app.route('/analyze', methods=['POST'])
def analyze_file():
    # Check if a file was uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400

    filename = file.filename.lower()

    try:
        # Read the file content
        content = file.read().decode('utf-8', errors='ignore')
        lines = content.strip().split('\n')

        results = {
            "filename": file.filename,
            "total_lines": len(lines),
            "findings": [],
            "summary": {}
        }

        # Detect file type and analyze
        if filename.endswith('.csv'):
            results = analyze_csv(content, results)
        elif filename.endswith('.log') or filename.endswith('.txt'):
            results = analyze_log(content, results)
        else:
            results["findings"].append({
                "severity": "INFO",
                "title": "Unknown file type",
                "description": f"File type '{filename.split('.')[-1]}' is not fully supported yet. Showing basic stats.",
                "mitre": ""
            })
            results["summary"] = {"total_lines": len(lines)}

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def analyze_csv(content, results):
    """Analyze CSV files (like Splunk exports)"""
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

    # Count source IPs
    for col in ip_columns:
        ip_counts = Counter(row.get(col, '') for row in rows if row.get(col, ''))
        if ip_counts:
            top_ip, top_count = ip_counts.most_common(1)[0]
            results["summary"][f"top_{col}"] = {"ip": top_ip, "count": top_count}

            # Flag if one IP appears too many times
            if top_count > len(rows) * 0.5:
                results["findings"].append({
                    "severity": "HIGH",
                    "title": f"Dominant IP in {col}",
                    "description": f"IP {top_ip} appears {top_count} times out of {len(rows)} events ({round(top_count/len(rows)*100)}%). This could indicate a focused attack.",
                    "mitre": "T1595 - Active Scanning"
                })

    # Check for failed logins
    failed_count = sum(1 for row in rows if any('fail' in str(v).lower() or '4625' in str(v) for v in row.values()))
    if failed_count > 10:
        results["findings"].append({
            "severity": "HIGH",
            "title": "Multiple Failed Logins Detected",
            "description": f"Found {failed_count} failed login events. This could indicate a brute force attack.",
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
                "description": f"Connections on unusual ports detected: {', '.join(suspicious_ports)}. These ports are commonly used by malware.",
                "mitre": "T1571 - Non-Standard Port"
            })

    if not results["findings"]:
        results["findings"].append({
            "severity": "LOW",
            "title": "No Immediate Threats Detected",
            "description": "Basic analysis did not find obvious suspicious patterns. Manual review recommended.",
            "mitre": ""
        })

    return results


def analyze_log(content, results):
    """Analyze plain text log files"""
    lines = content.strip().split('\n')
    results["summary"]["total_lines"] = len(lines)

    # Find IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    all_ips = re.findall(ip_pattern, content)
    if all_ips:
        ip_counts = Counter(all_ips)
        top_ips = ip_counts.most_common(5)
        results["summary"]["top_ips"] = [{"ip": ip, "count": count} for ip, count in top_ips]

        # Flag dominant IP
        if top_ips and top_ips[0][1] > len(lines) * 0.3:
            results["findings"].append({
                "severity": "HIGH",
                "title": "Dominant IP Address",
                "description": f"IP {top_ips[0][0]} appears {top_ips[0][1]} times. This IP should be investigated.",
                "mitre": "T1595 - Active Scanning"
            })

    # Check for failed logins
    failed_lines = [l for l in lines if 'fail' in l.lower() or 'invalid' in l.lower()]
    if len(failed_lines) > 10:
        results["findings"].append({
            "severity": "HIGH",
            "title": "Multiple Failed Logins",
            "description": f"Found {len(failed_lines)} lines indicating failed logins. Possible brute force attack.",
            "mitre": "T1110 - Brute Force"
        })

    # Check for suspicious keywords
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
