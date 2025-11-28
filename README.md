# ExposureScopeX - Continuous Attack Surface & Exposure Monitoring Framework

ExposureScopeX is a modular, CLI-based offensive security framework designed to automate the phases of a penetration test, from enumeration to reporting.

## Features

- **Enumeration**: Subdomain discovery (Subfinder, Assetfinder, crt.sh), deduplication.
- **Port Scanning**: Nmap integration with multiple scan speeds (light, medium, aggressive).
- **Vulnerability Scanning**: Nuclei and Nikto automation.
- **Web App Testing**: SQLMap, Dirsearch, and basic XSS checks.
- **Exploitation**: Hydra SSH bruteforce and Metasploit hooks (Use with caution!).
- **OSINT**: Shodan, VirusTotal, and Git leak detection.
- **Cloud Security**: Misconfiguration checks for AWS, Azure, GCP.
- **Reporting**: Automated Markdown and PDF report generation.
- **Integrations**: Slack, Microsoft Teams, and SIEM (Splunk/Syslog) support.

## Installation

### Prerequisites
- Linux (Kali, ParrotOS, Ubuntu recommended)
- `curl`, `jq`, `pandoc` (for PDF reports)
- PDF Engine: `weasyprint` (recommended) or `wkhtmltopdf` (deprecated) or `pdflatex`.
- External tools: `nmap`, `nuclei`, `subfinder`, `assetfinder`, `sqlmap`, `hydra`, `dirsearch`, `subjack`, `whatweb`, `wapiti`, `dalfox`, `arjun`, `httpx`, `waybackurls`, `feroxbuster`, `katana`.
  - The script will attempt to auto-install missing tools on Debian-based systems.

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/lucky1410/ExposureScopeX.git
   cd ExposureScopeX
   ```
2. Make scripts executable:
   ```bash
   chmod +x exposurescopex.sh modules/*.sh
   ```
3. (Optional) Configure API keys in `config/exposurescopex.conf`:
   ```bash
   nano config/exposurescopex.conf
   # Add SHODAN_API_KEY, SLACK_WEBHOOK_URL, etc.
   ```

## Usage

### Basic Scan
Run a full scan on a single domain:
```bash
./exposurescopex.sh -d example.com -e -s -r
```

### Batch Mode
Scan a list of targets from a file:
```bash
./exposurescopex.sh -f targets.txt --auto --slack
```

### Options
| Flag | Description |
|------|-------------|
| `-d, --domain` | Target single domain |
| `-f, --file` | File with list of targets |
| `-e, --enum` | Run enumeration |
| `-s, --scan` | Run vulnerability scanning |
| `-x, --exploit` | Enable exploitation (CAUTION) |
| `-c, --cloud` | Run cloud misconfig scanning |
| `-m, --mode` | Scan speed: `light`, `medium`, `aggressive` |
| `-r, --report` | Generate MD & PDF report |
| `--slack` | Send results to Slack |
| `--auto` | Non-interactive mode |

## Docker Usage
Build and run using Docker:
```bash
docker build -t pentestx .
docker run -it pentestx -d example.com -e -s
```

## Disclaimer
This tool is for educational and authorized testing purposes only. The author is not responsible for any misuse.
