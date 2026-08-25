# 🛡️ SOC Log Analyzer

**Turn raw logs into professional Incident Response reports — automatically.**

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Backend-Flask-green?style=flat-square)
![AI](https://img.shields.io/badge/AI-Google%20Gemini-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Live-brightgreen?style=flat-square)

---

## 👋 Hi, I'm Alisi!

I'm a cybersecurity student trying to break into a SOC Analyst role. I built this project because I wanted to show **real working code**, not just certificates.

When I was studying, I kept reading about how analysts spend hours parsing logs and writing reports. I thought: *"What if a tool could do the heavy lifting, but still give the analyst full control?"*

This is my answer. 🚀

---

## 🌐 Try It Live

👉 **[https://alisip-3.github.io/soc-log-analyzer/](https://alisip-3.github.io/soc-log-analyzer/)**

No install needed. Just open it, upload a file, and watch it work.

---

## 🖼️ See It In Action

I tested it on a **real AgentTesla malware infection** (PCAP from Malware-Traffic-Analysis.net) to prove it works on actual attacks.

### 1️⃣ Home Screen
![Home](docs/screenshots/01-home.png)

### 2️⃣ Upload a PCAP File
![Upload](docs/screenshots/02-pcap-upload.png)

### 3️⃣ Automatic Threat Detection
![Findings](docs/screenshots/03-pcap-findings.png)
*It found suspicious ports, external C2 connections, and malware indicators.*

### 4️⃣ AI Writes the Report
![Report](docs/screenshots/04-pcap-report.png)
*Gemini AI writes a full incident response report with MITRE ATT&CK mapping.*

### 5️⃣ Evidence Gallery
![Gallery](docs/screenshots/05-pcap-gallery.png)
*Screenshots get attached to the report as evidence.*

---

## ✨ What It Does

**Two ways to use it:**

| Mode | What it does |
| :--- | :--- |
| 📁 **Upload & Analyze** | Drop a log file (PCAP, CSV, JSON, TXT) → instant threat detection |
| ✍️ **Write Findings** | Already investigated? Type your findings → generate a report |

**Automatic detection:**
- 🔴 Brute force attacks (failed logins)
- 🔴 Living-off-the-Land (PowerShell, certutil)
- 🟡 Suspicious ports (Metasploit, RDP, Telnet)
- 🟡 C2 beaconing patterns
- 🟡 Malware hashes → **checks VirusTotal**
- 🌐 External connections to suspicious countries

**AI report includes:**
- Executive summary for management
- MITRE ATT&CK kill chain mapping
- Technical analysis with IOCs
- Containment & recovery steps
- Evidence screenshots attached

---

## 🛠️ Tech Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | HTML, CSS, JavaScript (GitHub Pages) |
| **Backend** | Python + Flask (Render) |
| **AI** | Google Gemini API |
| **Threat Intel** | VirusTotal API |
| **Log Parsing** | Custom Python + `dpkt` for PCAP |

---

## 📂 Test Files (Try These!)

**`sample_logs/`** — 5 realistic files I created, each triggers different detectors:
- `splunk_export.csv` — Splunk logs with embedded attack
- `suricata_eve.json` — IDS alerts
- `zeek_conn.log` — network connections
- `rita_beacons.csv` — C2 beaconing
- `linux_auth.log` — SSH brute force

**`demo/`** — my full worked example:
- The real AgentTesla PCAP I analyzed
- The AI-generated PDF report
- Screenshots of the process

---

## 🤔 What I Learned

- Parsing real log formats (CSV, JSON, PCAP)
- Real threat detection patterns, not just theory
- Integrating external APIs (Gemini, VirusTotal)
- Deploying a full-stack app to production
- Debugging real production issues (timeouts, CORS, API limits)

---

<div align="center">

**Built by Alisi Pinhasov** · Powered by Python + Google Gemini AI

*P.S. — AI reports take ~60s on free hosting. Threat detection is instant though!* ⚡

</div>
