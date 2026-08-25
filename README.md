# 🛡️ SOC Log Analyzer
**Turn raw logs into professional Incident Response reports — automatically.**

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Backend-Flask-green?style=flat-square)
![AI](https://img.shields.io/badge/AI-Google%20Gemini-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Live-brightgreen?style=flat-square)

SOC analysts spend hours parsing logs and formatting documentation. I built this full-stack tool to automate the heavy lifting, allowing analysts to focus on hunting threats while the AI handles the reporting.

🌐 **Try it live:** [https://alisip-3.github.io/soc-log-analyzer/](https://alisip-3.github.io/soc-log-analyzer/)

---

## 🖼️ Real-World Test (AgentTesla Malware)

To prove this tool works on actual threats and not just synthetic data, I ran the analyzer against a **real AgentTesla malware infection** (PCAP sourced from Malware-Traffic-Analysis.net). 

The engine successfully identified the C2 beaconing, suspicious ports, and external connections, and generated a full, professional PDF report.

👉 **[View the full test results, screenshots, and the AI-generated PDF report here](./pcap_full_test/)**

---
## ✨ Core Capabilities

🚀 **Dual-Mode Ingestion Engine**
> Don't just read logs—understand them. Instantly parse raw **PCAP, CSV, JSON, and TXT** files, or import your own manual investigation notes.

🎯 **Advanced Threat Hunting**
> Automatically flags the tactics real adversaries use: **Brute Force**, **Living-off-the-Land** (PowerShell/certutil), **C2 Beaconing**, and suspicious port activity.

🦠 **Live VirusTotal Intel**
> Extracts file hashes (MD5/SHA256) on the fly and pings the **VirusTotal API** to instantly confirm if a dropped payload is known malware.

🤖 **AI-Powered IR Reporting**
> Leveraging **Google Gemini**, the tool drafts a complete, executive-ready Incident Response report, automatically mapping findings to the **MITRE ATT&CK** framework.

📦 **Automated Evidence Packaging**
> Attach UI screenshots to your findings with one click. Export the final investigation as a crisp **Vector PDF** or a bundled **ZIP archive** ready for management.
---

## 📂 Try It Yourself

Want to test the detection engine? I've included a folder of realistic, noisy log files (Splunk exports, Suricata JSON, Zeek logs, and Linux auth logs) with hidden attacks buried inside the normal traffic. 

👉 **[Download the sample logs and test them on the live site](./sample_logs/)**

---

## 🧠 Engineering Challenges I Solved

🔍 **Unstructured Log Parsing**
> Built custom Python parsers to handle wildly different log formats — from structured CSV exports to raw binary PCAP captures — all without relying on heavy third-party libraries.

🔌 **Resilient API Integration**
> Connected to external services (Gemini AI, VirusTotal) with proper retry logic, rate-limit awareness, and graceful error handling so the app never crashes on a bad response.

🧩 **Framework-Free Frontend**
> Managed complex UI state, dynamic rendering, and file uploads entirely in vanilla JavaScript — proving you don't need React or Angular to build a polished web app.

🌐 **Production Deployment Under Constraints**
> Deployed a decoupled architecture (GitHub Pages + Render free tier) and solved real-world headaches like CORS policies, cold starts, and API timeouts on a zero-budget environment.

---

<div align="center">

**Built by Alisi Pinhasov** · Powered by Python, Flask, and Google Gemini AI

</div>
