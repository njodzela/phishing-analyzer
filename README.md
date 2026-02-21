[phishing-analyzer-readme.md](https://github.com/user-attachments/files/25456720/phishing-analyzer-readme.md)
# 🎣 Phishing Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566-red)](https://attack.mitre.org/techniques/T1566/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-Integrated-orange)](https://virustotal.com)
[![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-Integrated-green)](https://abuseipdb.com)

**Automated phishing email analysis tool for SOC analysts.** Extract IOCs, verify authentication headers, check URLs against threat intelligence, and generate investigation reports — all in seconds.

---

## 🚀 What It Does

Drop in a suspicious `.eml` file and get an instant, comprehensive analysis:

| Feature | Description |
|---|---|
| 📧 **Header Analysis** | Extracts sender, Reply-To, subject, date, and flags mismatches |
| 🔐 **Authentication Check** | Parses SPF, DKIM, and DMARC results — highlights failures |
| 🌐 **URL Extraction** | Pulls every URL from the email body and headers |
| 🛡️ **VirusTotal Scanning** | Checks all extracted URLs against VT's malware database |
| 🚨 **AbuseIPDB Lookup** | Verifies sender IP reputation and abuse history |
| 📊 **Risk Scoring** | Assigns LOW / MEDIUM / HIGH / CRITICAL based on findings |
| 📋 **Report Generation** | Outputs formatted terminal report + HTML file for ticketing |
| 💡 **Analyst Recommendations** | Provides actionable next steps based on findings |

---

## 📸 Sample Output

```
╭──────────────────────────────────────────────────────────╮
│                 Phishing Analyzer Results                 │
╰──────────────────────────────────────────────────────────╯

Overall Risk Score: MEDIUM

Email Details
  Sender         attacker@spoofed-domain.com
  Reply-To       collector@evil-domain.com          ⚠️ MISMATCH
  Subject        Urgent: Verify Your Account Now
  Date           Fri, 14 Feb 2026 09:22:11 -0600
  Auth Results   SPF=fail, DKIM=none, DMARC=fail    🔴 FAILED
  Origin IP      185.220.101.45

Threat Intelligence
  AbuseIPDB      Confidence: 92% malicious (1,247 reports)
  
URL Analysis
  ┌─────────────────────────────────────────┬─────────────┐
  │ URL                                     │ Result      │
  ├─────────────────────────────────────────┼─────────────┤
  │ http://evil-login.com/verify            │ 🔴 12/90    │
  │ https://legitimate-cdn.com/image.png    │ 🟢 Clean    │
  └─────────────────────────────────────────┴─────────────┘

Recommendations
  ⚠️ Reply-To differs from Sender — common phishing redirect
  🔴 SPF and DMARC both failed — sender is likely spoofed
  🔴 Sender IP flagged as malicious by AbuseIPDB
  🚫 Block sender domain and extracted malicious URLs
```

---

## ⚡ Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/njodzela/phishing-analyzer.git
cd phishing-analyzer
```

### 2. Set up the environment

```bash
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

### 3. Run the analyzer

```bash
python3 phishing_analyzer.py suspicious-email.eml
```

That's it. The tool works immediately — no API keys required for basic analysis.

---

## 🔑 API Keys (Optional — Free)

For deeper threat intelligence, add these free API keys:

| Service | What It Does | Free Tier | Get Key |
|---|---|---|---|
| **VirusTotal** | Scans URLs for malware | 4 lookups/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **AbuseIPDB** | Checks IP reputation | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/register) |

### Set up API keys

**Option A: Environment variables (recommended)**
```bash
export VT_API_KEY=your_virustotal_key_here
export ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

**Option B: Add to your shell profile (permanent)**
```bash
echo 'export VT_API_KEY=your_key' >> ~/.zshrc
echo 'export ABUSEIPDB_API_KEY=your_key' >> ~/.zshrc
source ~/.zshrc
```

---

## 📁 Project Structure

```
phishing-analyzer/
├── phishing_analyzer.py    # Main analysis engine
├── requirements.txt        # Python dependencies
├── sample.eml              # Example email for testing
├── .gitignore              # Excludes venv, reports, cache
└── README.md               # This file
```

---

## 🔍 How It Works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  .eml file  │────▶│  Header Parser   │────▶│  Auth Validator  │
└─────────────┘     │  - Sender        │     │  - SPF           │
                    │  - Reply-To      │     │  - DKIM          │
                    │  - Subject       │     │  - DMARC         │
                    │  - Origin IP     │     └────────┬─────────┘
                    └──────────────────┘              │
                                                      ▼
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ HTML Report │◀────│  Risk Scorer     │◀────│  URL Extractor   │
│ + Terminal  │     │  LOW/MED/HI/CRIT │     │  + VT Scanner    │
└─────────────┘     └──────────────────┘     │  + AbuseIPDB     │
                                              └─────────────────┘
```

1. **Parse** — Reads the .eml file, extracts all headers and body content
2. **Validate** — Checks SPF, DKIM, DMARC authentication results
3. **Extract** — Pulls all URLs, IPs, and attachment info as IOCs
4. **Enrich** — (With API keys) Checks IOCs against VirusTotal and AbuseIPDB
5. **Score** — Calculates risk based on authentication failures, mismatches, and threat intel
6. **Report** — Generates formatted terminal output + HTML report for ticketing

---

## 🎯 Use Cases

- **SOC Analysts** — Rapid triage of reported phishing emails
- **Incident Response** — Quick IOC extraction during investigations
- **Security Teams** — Standardized phishing analysis workflow
- **Training** — Learn email header analysis and threat intelligence enrichment
- **MSSPs** — Scalable analysis across multiple client environments

---

## 🛡️ Detection Coverage

| Check | MITRE ATT&CK | Description |
|---|---|---|
| Sender/Reply-To mismatch | T1566.001 | Phishing redirect detection |
| SPF/DKIM/DMARC failure | T1566.001 | Email spoofing detection |
| Malicious URLs | T1566.002 | Spearphishing link detection |
| Known malicious IPs | T1071 | C2 infrastructure detection |
| Suspicious attachments | T1566.001 | Malicious attachment indicators |

---

## 🤝 Contributing

Contributions welcome! Areas to improve:

- [ ] Add support for `.msg` (Outlook) file format
- [ ] Integrate Shodan API for IP enrichment
- [ ] Add YARA rule scanning for attachments
- [ ] Build a web UI dashboard
- [ ] Add batch processing for multiple emails
- [ ] Integrate with TheHive/MISP for automated case creation

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Christian M. Njodzela**
Cybersecurity Analyst & Incident Response | 5+ Years SOC Experience

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/njodzela)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black)](https://github.com/njodzela)

---

*Built with Python. Designed for defenders. 🛡️*
