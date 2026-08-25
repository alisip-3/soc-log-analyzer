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

## ✨ Core Features

* **Two Workflows:** Upload raw logs (PCAP, CSV, JSON, TXT) for instant analysis, or upload your own Notepad investigation files.
* **Automated Threat Detection:** Flags brute force, LotL techniques (PowerShell/certutil), suspicious ports, and C2 beaconing.
* **Threat Intel Integration:** Automatically checks extracted file hashes against **VirusTotal** to confirm known malware.
* **AI Report Generation:** Uses Google Gemini to write a structured IR report, complete with MITRE ATT&CK kill-chain mapping.
* **Evidence Handling:** Attach screenshots to findings and export everything as a clean PDF or ZIP package.

---

## 📂 Try It Yourself

Want to test the detection engine? I've included a folder of realistic, noisy log files (Splunk exports, Suricata JSON, Zeek logs, and Linux auth logs) with hidden attacks buried inside the normal traffic. 

👉 **[Download the sample logs and test them on the live site](./sample_logs/)**

---

## 🤔 Key Engineering Takeaways

Building this project pushed me to solve real-world production challenges:
* Parsing diverse, unstructured log formats natively in Python.
* Integrating external REST APIs (Gemini, VirusTotal) with proper error handling and rate-limit management.
* Managing state and rendering dynamic UI elements in vanilla JavaScript.
* Deploying a decoupled architecture (GitHub Pages frontend + Render backend) and handling CORS and API timeouts in a free-tier environment.

---

<div align="center">

**Built by Alisi Pinhasov** · Powered by Python, Flask, and Google Gemini AI

</div>
