# VulnAudit: Network Port Scanner & Service Auditor

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Category](https://img.shields.io/badge/Domain-Cybersecurity%20%7C%20Reconnaissance-red.svg)]()

A modular, high-performance **Network Port Scanner and Service Auditor** built in Python with concurrent multithreading, active/passive banner grabbing, regex service version fingerprinting, and automated vulnerability baseline auditing. Designed specifically for authorized security assessments, defensive audits, and educational penetration testing lab environments.

---

## ⚠️ Mandatory Legal & Ethical Disclaimer

```
========================================================================================
[!] LEGAL NOTICE:
    This software is designed and provided STRICTLY for authorized security auditing,
    defensive vulnerability assessments, and penetration testing in controlled,
    isolated laboratory environments or against assets with explicit written consent.

    Port scanning and service enumeration against targets without prior authorization
    is illegal under the Computer Fraud and Abuse Act (CFAA - 18 U.S.C. § 1030) and
    international cybercrime statutes.

    The author accepts NO responsibility or liability for unauthorized usage, misuse,
    or damages resulting from this tool. Scan responsibly and ethically.
========================================================================================
```

---

## 📑 Table of Contents

- [Features](#-features)
- [Architecture & Directory Structure](#-architecture--directory-structure)
- [Installation](#-installation)
- [How to Run the Port Scanner (Step-by-Step Guide)](#-how-to-run-the-port-scanner-step-by-step-guide)
- [Command-Line Reference](#-command-line-reference)
- [Usage Examples](#-usage-examples)
- [Security Auditing Capabilities](#-security-auditing-capabilities)
- [Report Exports (JSON & CSV)](#-report-exports-json--csv)
- [Safe Lab Testing Guide](#-safe-lab-testing-guide)

---

## ✨ Features

- **High-Performance Threading**: Utilizes `concurrent.futures.ThreadPoolExecutor` for concurrent scanning with configurable worker counts (1–500) and microsecond-level connection timeouts.
- **Accurate Socket State Classification**: Distinguishes between `OPEN` (successful 3-way handshake), `CLOSED` (`RST` / `ECONNREFUSED`), and `FILTERED` (firewall drops / `ETIMEDOUT`).
- **Flexible Port Range Parsing**: Accepts single ports (`80`), continuous ranges (`1-1024`), comma-separated lists (`21,22,80,443`), mixed specifications (`21-25,80,443,8000-8080`), and curated aliases (`common`, `top20`, `top100`, `all`).
- **Service Banner Grabbing**:
  - **Passive Listening**: Captures initial greeting banners for protocols that speak first (SSH, FTP, SMTP, POP3, IMAP).
  - **Active Probing**: Sends targeted HTTP/1.1 probes, TLS/SSL handshakes, and Redis commands (`INFO`).
- **Regex Version Fingerprinting**: Extracts exact product and version strings across OpenSSH, Dropbear, Apache, Nginx, Microsoft IIS, vsftpd, ProFTPD, MySQL, Redis, and more.
- **Automated Security Auditor**:
  - Flags unencrypted/cleartext authentication protocols (Telnet, FTP, HTTP, POP3, IMAP, rlogin).
  - Active, safe lab checks for **Anonymous FTP Login** and **Unauthenticated Redis Databases**.
  - Audits HTTP headers for information disclosure (`Server`, `X-Powered-By`).
  - Identifies notorious vulnerable software versions (e.g., vsftpd 2.3.4 backdoor, Apache 2.4.49 path traversal, legacy OpenSSH).
- **Executive Reporting**: Generates formatted terminal reports with colorized risk badges and exports comprehensive audit reports in **JSON** and **CSV** formats to `outputs/`.

---

## 🏛 Architecture & Directory Structure

The project employs a clean, decoupled modular architecture:

```
port_scanner/
│
├── core/
│   ├── __init__.py           # Package exports for core engine
│   ├── scanner.py            # Multithreaded TCP connect scanner & latency tracker
│   ├── banner.py             # Active/passive banner grabber & regex version parser
│   └── auditor.py            # Vulnerability & security misconfiguration auditor
│
├── utils/
│   ├── __init__.py           # Package exports for utilities
│   ├── validator.py          # IP resolution, hostname validation & port range parsing
│   └── reporter.py           # JSON and CSV report generators with risk metrics
│
├── outputs/                  # Auto-generated directory for scan reports
│   └── .gitkeep
│
├── main.py                   # Production CLI entrypoint with formatted color output
├── requirements.txt          # Minimal Python dependencies
└── README.md                 # Complete documentation
```

### Module Responsibilities

1. **`core/scanner.py` (`PortScanner`)**:
   - Manages connection lifecycle via `socket.socket(socket.AF_INET, socket.SOCK_STREAM)`.
   - Records Round Trip Time (RTT) latency per open port.
   - Handles `KeyboardInterrupt` with immediate thread pool cancellation.
2. **`core/banner.py` (`BannerGrabber`)**:
   - Initiates passive socket reads followed by active probes (e.g. `GET / HTTP/1.1`, TLS wrapping).
   - Runs pre-compiled regular expressions to extract products and semantic version numbers.
3. **`core/auditor.py` (`ServiceAuditor`)**:
   - Compares identified services and versions against security baselines.
   - Assigns severity rankings (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
   - Generates actionable remediation recommendations and evidentiary proof.
4. **`utils/validator.py`**:
   - Cleanses user input (strips `http://`, port suffixes, trailing paths).
   - Validates IPv4/IPv6 addresses and resolves domain names through DNS.
   - Expands port strings and aliases into sorted unique integer sets.
5. **`utils/reporter.py`**:
   - Structures findings into standard JSON and SIEM-friendly CSV records.

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- Windows, Linux, or macOS

### 1. Clone or Navigate to the Repository
```bash
cd port_scanner
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

*(Note: The tool relies primarily on Python standard library modules (`socket`, `ssl`, `concurrent.futures`, `ipaddress`, `argparse`). `colorama` enables rich cross-platform terminal colors).*

---

## 📖 How to Run the Port Scanner (Step-by-Step Guide)

Follow this guide to get up and running quickly on Windows, Linux, or macOS:

### 1. Open Terminal & Navigate to the Project Folder
Open **PowerShell**, **Command Prompt**, or your terminal and change directory:
```powershell
cd C:\Users\hunte\Desktop\port_scanner
```

### 2. View the Built-in Command Reference & Help
Type `help` to display the colorized command guide, all flags, and syntax:
```powershell
python main.py help
```
*(You can also run `python main.py -h` or `python main.py --help`)*

### 3. Verify System Operations with Unit Tests (Recommended)
Run the 21 automated unit and integration tests to ensure sockets, banner grabbing, and security auditing operate flawlessly:
```powershell
python -m unittest test_scanner.py
```

### 4. Hands-on Test with Local Mock Services
Test the entire discovery and auditing pipeline locally without touching an external network:

1. **Terminal 1** — Start the mock vulnerable target:
   ```powershell
   python lab_target_demo.py
   ```
   *(Hosts a mock FTP server with vsftpd 2.3.4 & anonymous login on port 2121, HTTP on 8080 with Apache 2.4.49, and Redis on 6379).*

2. **Terminal 2** — Run the auditor against the mock target:
   ```powershell
   python main.py -t 127.0.0.1 -p 2121,8080,6379 -f both
   ```

### 5. Running Scans on Authorized Lab Targets

#### A. Basic Localhost Scan (Ports 1–1024)
Scans default ports 1 through 1024 on `127.0.0.1`:
```powershell
python main.py -t 127.0.0.1
```

#### B. High-Speed Attack-Surface Scan (Top 100 Ports with 100 Threads)
Scans the top 100 most commonly attacked ports concurrently:
```powershell
python main.py -t 192.168.1.50 -p top100 -T 100
```

#### C. Custom Port List with Dual JSON & CSV Export
Audits specific critical services and exports reports to both JSON and CSV:
```powershell
python main.py -t 192.168.1.20 -p 21,22,80,443,3306,8080 -f both
```

#### D. Custom Report Destination File
Saves the report directly to a specified path:
```powershell
python main.py -t lab.internal -p common -o outputs/lab_audit.json
```

#### E. Pure Port Discovery (Skip Vulnerability Auditor)
Runs port discovery and latency checks only, skipping security checks:
```powershell
python main.py -t 10.0.0.1 -p 1-65535 -T 200 --no-audit
```

#### F. Verbose Mode
Prints real-time status of closed and filtered ports alongside open ports:
```powershell
python main.py -t 127.0.0.1 -p 80,443,3389 -v
```

### 6. Locating and Viewing Exported Reports
All reports are saved in the `outputs/` folder:
- **JSON Reports (`outputs/audit_<target>_<timestamp>.json`)**: Complete scan metadata, duration, open ports, banners, and structured vulnerability findings.
- **CSV Reports (`outputs/audit_<target>_<timestamp>.csv`)**: Formatted for Microsoft Excel, Google Sheets, or SIEM log pipelines.

---

## 💻 Command-Line Reference

```
usage: python main.py help
       python main.py -t TARGET [-p PORTS] [-T THREADS] [--timeout TIMEOUT]
                               [--no-audit] [-o OUTPUT] [-f {json,csv,both}] [-v]

Production-Grade Network Port Scanner & Service Auditor for Authorized Lab Environments.

options:
  -h, --help, help      show full colorized command reference guide and exit
  -t TARGET, --target TARGET
                        Target IP address or hostname to audit (e.g., '192.168.1.50' or 'lab.local')
  -p PORTS, --ports PORTS
                        Port specification: ranges ('1-1024'), comma list ('21,22,80,443'),
                        mixed ('21-25,80,8080'), or aliases ('common', 'top100', 'all').
                        Default: '1-1024'.
  -T THREADS, --threads THREADS
                        Number of concurrent scanning worker threads (1-500). Default: 50.
  --timeout TIMEOUT     Socket connection timeout in seconds. Default: 1.0.
  --no-audit            Disable deep vulnerability checks and service posture auditing.
  -o OUTPUT, --output OUTPUT
                        Custom file path for export (e.g., 'outputs/scan.json' or 'audit.csv').
  -f {json,csv,both}, --format {json,csv,both}
                        Output report format ('json', 'csv', 'both'). Default: 'json'.
  -v, --verbose         Enable verbose output (displays closed/filtered ports and debug traces).
```

---

## 🔍 Usage Examples

### 1. Basic Scan on Localhost (Ports 1–1024)
```bash
python main.py -t 127.0.0.1
```

### 2. Fast Common Ports Audit with 100 Threads
```bash
python main.py -t 192.168.1.10 -p common -T 100
```

### 3. Comprehensive Audit with Both JSON & CSV Exports
```bash
python main.py -t 192.168.1.20 -p 1-1024 -T 100 -f both
```

### 4. Custom Port Range with Aggressive Timeout
```bash
python main.py -t lab.internal -p 21,22,80,443,3306,8080,8443 --timeout 0.5 -T 20
```

### 5. Custom Output File Path
```bash
python main.py -t 10.0.0.5 -p top100 -o outputs/client_lab_audit.json
```

### 6. Quick Scan Only (Bypass Vulnerability Auditor)
```bash
python main.py -t 192.168.1.1 -p 1-65535 -T 250 --no-audit
```

---

## 🛡️ Security Auditing Capabilities

| Category | Checks Performed | Severity |
| :--- | :--- | :--- |
| **Cleartext Protocols** | Detects plain HTTP, Telnet (port 23), FTP (port 21), POP3 (110), IMAP (143), rlogin (513) | `HIGH` / `MEDIUM` / `LOW` |
| **Anonymous FTP Access** | Connects to port 21, probes `USER anonymous` and checks for `230 Login successful` | `HIGH` |
| **Unprotected Databases** | Redis (6379) unauthenticated `PING` evaluation, MySQL/Postgres direct exposure | `CRITICAL` / `MEDIUM` |
| **Risky Services** | Windows SMB (445/139), Remote Desktop (3389), Docker Plain API (2375) | `CRITICAL` / `HIGH` |
| **HTTP Hygiene** | `Server` / `X-Powered-By` information disclosure headers | `LOW` / `INFO` |
| **Vulnerable Versions** | vsftpd 2.3.4 (Backdoor CVE-2011-2523), Apache 2.4.49 (Path Traversal), EOL software | `CRITICAL` / `HIGH` |

---

## 📊 Report Exports (JSON & CSV)

Reports are automatically saved in the `outputs/` directory.

### Sample JSON Report Structure:
```json
{
    "scan_metadata": {
        "tool": "Network Port Scanner & Service Auditor",
        "version": "1.0.0",
        "target_ip": "192.168.1.50",
        "target_host": "metasploitable.lab",
        "scan_timestamp_utc": "2026-10-27T15:30:00.123456+00:00",
        "scan_duration_seconds": 2.41,
        "total_ports_scanned": 100,
        "open_ports_discovered": 3,
        "total_findings_count": 4,
        "risk_summary": {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 0,
            "INFO": 0
        }
    },
    "open_ports": [
        {
            "port": 21,
            "status": "OPEN",
            "service": "ftp",
            "latency_ms": 1.45,
            "product": "vsftpd",
            "version": "2.3.4",
            "banner": "220 (vsFTPd 2.3.4)",
            "metadata": {}
        }
    ],
    "audit_findings": [
        {
            "severity": "CRITICAL",
            "port": 21,
            "protocol": "TCP",
            "service": "FTP",
            "title": "Vulnerable vsftpd 2.3.4 Backdoor Signature",
            "description": "vsftpd version 2.3.4 was distributed with a malicious backdoor (CVE-2011-2523)...",
            "recommendation": "Immediately remove vsftpd 2.3.4 and install a secure, verified release.",
            "evidence": "Banner signature match: 220 (vsFTPd 2.3.4)"
        }
    ]
}
```

---

## 🧪 Safe Lab Testing Guide

To test the auditor locally without external network targets:

### Option A: Quick Python Mock Server (Included Demo)
Run a simple HTTP server in one terminal:
```bash
python -m http.server 8000
```
Then audit it in another terminal:
```bash
python main.py -t 127.0.0.1 -p 8000
```

### Option B: Docker Vulnerable Testbed (Metasploitable / DVWA)
In your isolated lab VM:
```bash
# Example: Running an isolated lab target in Docker
docker run -d -p 80:80 -p 21:21 vulnerables/web-dvwa
python main.py -t 127.0.0.1 -p 21,80 -f both
```
