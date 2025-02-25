# API-Digger v2

![API-Digger Logo](https://img.shields.io/badge/API--Digger-v2-blue)
![Python](https://img.shields.io/badge/Python-3.7+-brightgreen)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

API-Digger is an automated Swagger UI vulnerability scanner that identifies exposed and potentially vulnerable API documentation endpoints.
![image](https://github.com/user-attachments/assets/5bb01a62-2bcc-470f-b6e1-8e1d3aab040a)

## 🚀 Features

- **Endpoint Discovery**: Automatically scans subdomains to identify potential Swagger UI endpoints
- **Version Detection**: Uses headless browser automation to detect Swagger UI versions
- **Vulnerability Assessment**: Identifies known vulnerabilities in detected Swagger UI versions
- **Detailed Reporting**: Generates comprehensive reports of vulnerable endpoints
- **Concurrent Processing**: Multi-threaded architecture for faster scanning

## 📋 Prerequisites

- Python 3.7+
- Feroxbuster (for directory enumeration)
- Chrome/Chromium (for headless browser automation)

## 🔧 Installation

1. Clone the repository
```bash
git clone https://github.com/Somchandra17/API-Digger.git
cd API-Digger
```

2. Install required Python packages
```bash
pip install -r requirements.txt
```

3. Install Feroxbuster (if not already installed)
```bash
# On systems with cargo (Rust package manager)
cargo install feroxbuster

# On Debian/Ubuntu
apt-get install feroxbuster

# On macOS with Homebrew 🏳️‍🌈
brew install feroxbuster
```

## 🔍 Usage

```bash
python3 api-digger.py
```

The script will prompt you for:
- Path to a file containing subdomains to scan
- Custom wordlist option (default: uses raft-medium-directories.txt from SecLists)
- Number of concurrent threads (default: 20)
- Output file name for the scan results

### Example Session

```
[?] Enter the name of the subdomains file: subdomains.txt
[?] Do you want to use a custom wordlist for directory enumeration? (y/n): n
[*] Using default wordlist: https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-medium-directories.txt
[?] Enter maximum number of concurrent threads (default: 20): 
[?] Enter the output file name: scan_results.txt
```

## 📊 Vulnerability Table

API-Digger checks for the following known Swagger UI vulnerabilities:

| Severity | Vulnerability | Vulnerable Versions |
|----------|---------------|---------------------|
| Medium   | Server-side Request Forgery (SSRF) | <4.1.3 |
| Medium   | Insecure Defaults | <3.26.1 |
| Medium   | Relative Path Overwrite (RPO) | <3.23.11 |
| Medium   | Cross-site Scripting (XSS) | >=2.0.3 <2.0.24, >=3.0.0 <3.0.13, <2.2.1, <3.20.9, <3.4.2, <2.2.3 |
| Medium   | Reverse Tabnabbing | <3.18.0 |
| Critical | Cross-site Scripting (XSS) | <2.1.0 |
| High     | Cross-site Scripting (XSS) | <2.2.1 |

## 📝 Output

The tool generates a detailed report containing:
- Scan summary with statistics
- List of all potential Swagger UI endpoints
- Details of vulnerable endpoints with version information
- List of endpoints that encountered errors during scanning

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is designed for security professionals to identify vulnerable Swagger UI instances in their own environments. Always obtain proper authorization before scanning any systems you don't own.
