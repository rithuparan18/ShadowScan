# ShadowScan Pro: Modular Offensive Reconnaissance Framework

**ShadowScan Pro** is a high-performance, modular reconnaissance engine engineered in Python. It is designed to automate the "Reconnaissance" phase of a penetration test by mapping an organizational attack surface through a combination of passive discovery and active service enumeration.

---

## 🌟 Key Capabilities

* **Modular Architecture**: Designed as a plug-and-play framework, allowing security researchers to easily extend functionality through custom scanning or exploitation modules.
* **High-Speed Concurrency**: Utilizes a thread-safe `ThreadPoolExecutor` architecture to handle 500+ targets simultaneously, significantly reducing the reconnaissance window.
* **Intelligent Asset Discovery**: Aggregates passive data from HackerTarget and Certificate Transparency (CRT.sh) logs to identify subdomains before performing active DNS resolution.
* **Service & Banner Grabbing**: Identifies live services across high-value ports (SSH, HTTP, RDP, etc.) and captures banners to fingerprint outdated software versions for CVE cross-referencing.
* **Automated Secret Hunting**: Features an integrated JavaScript scraper that uses optimized Regex patterns to hunt for exposed AWS keys, Google API tokens, and JWTs within public-facing files.
* **Professional Reporting**: Generates thread-safe, structured JSON intelligence reports and provides a colorized CLI output powered by the `Rich` library for real-time analysis.

---

## 🏗️ Project Structure

```text
shadowscan/
├── main.py             # CLI Entry point & Argument Handler
├── modules/
│   ├── __init__.py     # Module Exporter
│   ├── scanner.py      # Core Discovery & Port Scanning Logic
│   ├── secrets.py      # JS Scraping & Secret Mining Module
|   └── bruteforce.py
```

---

## 🚀 Getting Started

### Prerequisites
* Python 3.10+
* Required libraries: `requests`, `dnspython`, `python-Wappalyzer`, `rich`

### Installation
```bash
git clone [https://github.com/yourusername/ShadowScan-Pro.git](https://github.com/yourusername/ShadowScan-Pro.git)
cd ShadowScan-Pro
pip install -r requirements.txt
```

### Usage
Run a standard scan on a target domain:
```bash
python main.py -d example.com
```

Enable Secret Finder and increase thread count for deep discovery:
```bash
python main.py -d example.com -s -t 60 -o my_report.json
```

---

## 🛠️ Roadmap
- [ ] **Ghost-C2 Integration**: Payload delivery for post-exploitation persistence.
- [ ] **Directory Brute-Forcer**: Automated path discovery for sensitive files (.env, .git).
- [ ] **Subdomain Takeover Module**: Logic to detect abandoned cloud assets.

---

## 🛡️ Disclaimer
This tool is intended for authorized security auditing and educational purposes only. Unauthorized scanning of networks is illegal. The author assumes no liability for misuse of this software.
