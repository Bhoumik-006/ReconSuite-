# ReconSuite v2.0 — Full-Spectrum Reconnaissance Toolkit

![Version](https://img.shields.io/badge/version-2.0.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)

**ReconSuite v2.0** is a full-spectrum Python reconnaissance tool combining CLI and web dashboard interfaces. It performs WHOIS lookups, DNS enumeration, subdomain discovery (brute-force + passive via crt.sh), TCP port scanning (top 1000), HTTP security headers audit, tech stack fingerprinting, SSL/TLS certificate analysis, email harvesting, Shodan intelligence, web crawling, screenshot capture, and CVE correlation — all in one integrated package.

```
⚠️ LEGAL DISCLAIMER: This tool is intended for authorised security assessment purposes only.
Unauthorised use against targets you do not own or have explicit written permission to test
is illegal. The authors assume no liability for misuse or damage caused by this tool.
```

---

## Features

### Core Modules
| Module | Description |
|--------|-------------|
| **WHOIS** | Domain registration information, registrar, dates, name servers |
| **DNS** | A, AAAA, MX, NS, TXT, SOA, CNAME record enumeration |
| **Subdomains** | Brute-force (150+ wordlist) + passive via crt.sh Certificate Transparency |
| **Port Scan** | Full top 1000 TCP ports via socket with ThreadPoolExecutor parallelism |
| **HTTP Headers** | Security headers audit with scoring (HSTS, CSP, XFO, CORS, etc.) |
| **Tech Fingerprint** | 20+ technology signatures (React, Vue, nginx, WordPress, etc.) |
| **SSL/TLS** | Certificate analysis: issuer, expiry, SAN, cipher, protocol |
| **Email Harvest** | Extracts emails from WHOIS, web pages, Google, and Bing |
| **Shodan** | Full Shodan API (with key) or Shodan InternetDB (no key) |
| **Web Crawl** | 90+ common paths: admin panels, config files, .env, API endpoints |
| **Screenshots** | Playwright headless Chromium screenshots of discovered subdomains |
| **CVE Correlation** | Maps detected software to NVD/CVE database via CPE matching |

### New in v2.0
- ✅ **Shodan API** integration with API key (fallback to free InternetDB)
- ✅ **theHarvester-style** email/subdomain harvesting from Google, Bing, crt.sh
- ✅ **Playwright screenshots** of discovered subdomains
- ✅ **CVE correlation** — matches software versions against NVD database
- ✅ **PDF report export** — professional pentest-style reports via ReportLab
- ✅ **Docker support** — one-command deployment with Docker Compose
- ✅ **Scheduled scans** — APScheduler cron jobs with diff alerting
- ✅ **Multi-target** — scan from a `targets.txt` file
- ✅ **Proxy/Tor** — route all traffic through HTTP proxy or SOCKS5
- ✅ **Persistent dashboard** — SQLite backend, scan history survives restarts

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone and run
git clone <repo> reconsuite
cd reconsuite
docker-compose up -d --build

# Open dashboard
open http://localhost:5000

# Run CLI inside container
docker exec -it reconsuite-v2 python recon_cli.py example.com
```

### Option 2: Local Installation

```bash
# Clone
git clone <repo> reconsuite
cd reconsuite

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium

# Start the web dashboard
python app.py

# Or use the CLI directly
python recon_cli.py example.com
```

---

## CLI Usage

### Basic Scan
```bash
python recon_cli.py example.com
```

### Selective Modules
```bash
# Only certain modules
python recon_cli.py example.com --only ports,headers,ssl

# Skip specific modules
python recon_cli.py example.com --skip emails,shodan
```

### Output Formats
```bash
python recon_cli.py example.com --output json,md,pdf
```

### Multi-Target Scanning
```bash
# Create targets.txt
echo "example.com" > targets.txt
echo "testsite.org" >> targets.txt

# Scan all targets
python recon_cli.py --targets targets.txt
```

### Proxy / Tor
```bash
# HTTP proxy
python recon_cli.py example.com --proxy http://127.0.0.1:8080

# SOCKS5 proxy
python recon_cli.py example.com --proxy socks5://127.0.0.1:9050

# Tor (assumes Tor running on 127.0.0.1:9050)
python recon_cli.py example.com --tor
```

### Advanced Flags
```bash
# Full scan with screenshots and CVE correlation
python recon_cli.py example.com --screenshots --cve --output json,md,pdf

# Custom thread count
python recon_cli.py example.com --threads 100
```

### Shodan API Key
```bash
# Set environment variable (or use Shodan InternetDB for free)
export SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
python recon_cli.py example.com
```

---

## Web Dashboard

The Flask dashboard is served on `http://localhost:5000` and provides:

### Tabs
| Tab | Description |
|-----|-------------|
| **Scan** | Start scans with options (CVE, screenshots, proxy) |
| **Results** | Browse scan history, view detailed results |
| **History** | Change tracking — new subdomains/ports between scans |
| **Reports** | Download generated JSON, Markdown, PDF reports |
| **Schedules** | Cron-based scheduled scans with diff alerting |
| **Export** | Export reports by target and format |

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Application status |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/targets` | List all scanned targets |
| POST | `/api/scan` | Start a new scan |
| GET | `/api/scan/<id>` | Get scan status/results |
| GET | `/api/scans` | List all scans (optional `?target=` filter) |
| GET | `/api/results/<target>` | Latest results for a target |
| GET | `/api/history` | Change history/diffs (optional `?target=` filter) |
| DELETE | `/api/scan/<id>` | Delete a scan |
| GET | `/api/reports` | List generated reports |
| GET | `/api/reports/<file>` | Download a report |
| GET | `/api/schedules` | List scheduled scans |
| POST | `/api/schedules` | Create a schedule |
| PUT | `/api/schedules/<id>` | Update a schedule |
| DELETE | `/api/schedules/<id>` | Delete a schedule |
| POST | `/api/proxy` | Configure proxy settings |

---

## Directory Structure

```
├── recon_cli.py              # CLI tool with all scanning modules
├── app.py                    # Flask web dashboard with SQLite
├── templates/
│   └── dashboard.html        # Dark-theme single-page dashboard
├── requirements.txt          # Python dependencies
├── Dockerfile                # Docker build file
├── docker-compose.yml        # Docker Compose configuration
├── README.md                 # This file
├── reports/                  # Generated report files (JSON, MD, PDF)
├── screenshots/              # Playwright screenshots
├── scans/                    # SQLite database (persistent)
└── static/                   # Static assets (optional)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  ReconSuite v2.0                     │
├──────────────┬──────────────────────────────────────┤
│   CLI Mode   │          Web Dashboard               │
│  recon_cli.py│          app.py (Flask)              │
│              │                                      │
│  ┌────────┐  │  ┌────────┐  ┌──────────────────┐   │
│  │argparse│  │  │ Flask  │  │   SQLite (persist)│   │
│  │colorama│  │  │ REST   │  │   scan_history    │   │
│  └────────┘  │  │ API    │  │   scheduled_scans │   │
│              │  └────────┘  │   scan_results    │   │
│  ┌─────────────────────┐   └──────────────────┘   │
│  │   Full-Spectrum     │  ┌──────────────────┐   │
│  │   Scan Engine       │  │   APScheduler    │   │
│  │   (ThreadPool)      │  │   Cron Jobs      │   │
│  └─────────────────────┘  │   Diff Alerting  │   │
│              │            └──────────────────┘   │
│              └────────────────────────────────────│
│              │            │                       │
│         ┌────┴────────────┴────┐                  │
│         │    Report Export     │                  │
│         │  JSON / Markdown /   │                  │
│         │  PDF (ReportLab)     │                  │
│         └─────────────────────┘                  │
└─────────────────────────────────────────────────────┘
```

### Module Architecture

Each scanning module is a self-contained function in `recon_cli.py`, making them individually importable by the Flask dashboard:

```
whois_lookup()       → WHOIS information
dns_enum()           → DNS records
subdomain_enum()     → Subdomains (brute + crt.sh)
port_scan()          → TCP port scanning
check_http_headers() → Security headers audit
fingerprint_tech()   → Technology detection
ssl_analysis()       → SSL/TLS certificate
email_harvest()      → Email discovery
shodan_query()       → Shodan + InternetDB
web_crawl()          → Path discovery
screenshot_subdomain() → Playwright screenshots
cve_correlation()    → CVE matching
full_scan()          → Orchestrator (parallel)
generate_pdf_report() → ReportLab PDF
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHODAN_API_KEY` | — | Shodan API key (falls back to free InternetDB) |
| `FLASK_SECRET` | `reconsuite-v2-...` | Flask session secret key |
| `PORT` | `5000` | Web dashboard port |
| `FLASK_DEBUG` | `0` | Enable Flask debug mode |

### Proxy Configuration

Proxy can be set via:
1. **CLI flag**: `--proxy socks5://127.0.0.1:9050`
2. **CLI flag**: `--tor` (auto-configures SOCKS5 on 127.0.0.1:9050)
3. **Dashboard**: Scan options → Proxy field

### Scheduled Scans (Cron)

The dashboard supports standard cron expressions. Examples:

| Expression | Schedule |
|------------|----------|
| `0 */6 * * *` | Every 6 hours |
| `0 0 * * *` | Daily at midnight |
| `0 9,17 * * 1-5` | Weekdays at 9 AM and 5 PM |
| `30 2 * * 0` | Weekly on Sunday at 2:30 AM |

---

## Reports

Reports are automatically saved to the `reports/` directory in three formats:

### JSON
Full structured data — ideal for programmatic consumption or integration with other tools.

### Markdown
Human-readable with severity badges and recommendations — suitable for quick sharing or embedding in wikis.

### PDF
Professional pentest-style report with:
- Executive summary with severity breakdown
- Detailed findings with severity ratings
- Remediation recommendations
- Raw data appendix
- Legal disclaimer

---

## Examples

### Basic Reconnaissance
```bash
$ python recon_cli.py example.com

[*] Modules enabled: whois, dns, subdomains, ports, headers, fingerprint, ssl, emails, shodan, crawl
[*] Output formats: json, md
[*] Running all modules in parallel...
[+] Scan completed in 45.2s
[+] [WHOIS] Registrar: Example Registrar Inc
[+] [Subdomains] 12 found (5 brute, 9 passive)
[+] [Ports] 6 open
[+] [Headers] Score: 48/100
[+] [Emails] 3 found
[+] [Crawl] 8 interesting paths
[+] Report saved: reports/example_com_20240101_120000.json
[+] Report saved: reports/example_com_20240101_120000.md
```

### Full Recon with Screenshots and CVE Correlation
```bash
$ python recon_cli.py example.com --screenshots --cve --output json,md,pdf
```

### Multi-Target with Tor
```bash
$ cat targets.txt
example.com
example.org
example.net

$ python recon_cli.py --targets targets.txt --tor --cve --output pdf
```

---

## Requirements

- **Python 3.11+**
- **Docker** (optional, for containerised deployment)
- **Dependencies** listed in `requirements.txt`

### System Dependencies (non-Docker)

For Playwright screenshots:
```bash
playwright install chromium
playwright install-deps chromium
```

For SOCKS5/Tor support:
```bash
pip install pysocks
```

---

## Security & Ethics

- **Only use on targets you own or have explicit written permission to test.**
- All reports include a legal disclaimer.
- The tool performs passive and active reconnaissance — ensure your testing is authorised.
- CVE queries hit NVD's public API — respect rate limits (403 responses mean slow down).
- Screenshots use headless Chromium — ensure you have the rights to access target URLs.

---

## License

MIT License. See `LICENSE` for details.

---

*Built with ❤️ for the security community.*
