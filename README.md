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

🤖 **Taming the AI (The Hard Part)**
> Getting Gemini to write security reports was genuinely the hardest part of this project. The API kept rejecting cybersecurity content due to safety filters, models got deprecated mid-development, and the SDK broke unexpectedly. I solved it by dropping the SDK entirely and calling Gemini's REST API directly — which finally gave me full control over the request.

🏗️ **Flask Over Docker (A Deliberate Choice)**
> I needed a backend strong enough to handle file parsing, API calls, and concurrent requests — but lightweight enough to run on free-tier hosting. Docker felt like overkill for this scope. Flask gave me the reliability I needed without the deployment complexity, and it runs rock-solid on Render.

🔗 **Frontend ↔ Backend Communication**
> Connecting a static GitHub Pages frontend to a Flask backend on Render meant dealing with CORS policies, cold starts, and API timeouts on a zero-budget environment. I solved it with proper error handling and timeout management so the app never just hangs.

---

<div align="center">

**Built by Alisi Pinhasov** · Powered by Python, Flask, and Google Gemini AI

</div>
