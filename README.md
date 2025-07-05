# 🎯 ParamHunter Pro v6.9 - Stalker Edition

> **Advanced Parameter Discovery & Web Application Security Scanner**  
> *Comprehensive web security assessment tool with built-in crawler, fuzzer and external scanner integration*

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-offensive-red.svg)](https://github.com/m2hcs/paramhunter-pro)

## 🚀 Features

### 🕷️ **Smart Web Crawler**
- Asynchronous high-performance crawling up to configurable depth
- Form parameter extraction and endpoint discovery
- Intelligent URL normalization and filtering
- Domain-aware crawling with built-in rate limiting

### 🔍 **Built-in Security Fuzzer**
- **SQL Injection Detection**
  - Time-based blind SQLi detection
  - Error-based SQLi with database-specific patterns
  - Support for MySQL, PostgreSQL, MSSQL, SQLite
- **Cross-Site Scripting (XSS)**
  - Reflected XSS detection
  - Multiple payload variants and encoding techniques
- **Custom Payloads & Thresholds**
  - Configurable delay thresholds for time-based attacks
  - Extensible payload framework

### 🛠️ **External Tool Integration**
Seamlessly integrate with industry-standard security tools:
- **subfinder** - Subdomain enumeration
- **wafw00f** - Web Application Firewall detection
- **wappalyzer** - Technology stack identification
- **ffuf** - Fast web fuzzer for directory/file discovery
- **nuclei** - Vulnerability scanner with community templates
- **wapiti** - Web application vulnerability scanner
- **sqlmap** - Advanced SQL injection exploitation
- **arjun** - Parameter discovery tool

### 🎨 **Rich Terminal Interface**
- Real-time vulnerability discovery table
- Live progress tracking with multiple task monitoring
- Colorized output and severity indicators
- Interactive terminal experience via Rich library

### 📊 **Comprehensive Reporting**
- JSON reports with scan metadata and configuration
- Vulnerability severity classification (Critical/High/Medium/Low/Info)
- Timestamped findings with evidence and payload details
- Structured output for integration with other tools

## ⚙️ Installation

### Quick Setup
```bash
git clone https://github.com/yourusername/paramhunter-pro.git
cd paramhunter-pro
pip install -r requirements.txt
```

### Dependencies
```bash
pip install aiohttp beautifulsoup4 rich
```

### External Tools (Optional)
For full functionality, install external security tools:
```bash
# Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python tools
pip3 install wafw00f wapiti3 arjun

# System packages
sudo apt-get install sqlmap

# Node.js tools
npm install -g wappalyzer-cli
```

## 🎯 Usage

### Basic Scan
```bash
python3 crawllerv2.py -u https://example.com
```

### Comprehensive Security Assessment
```bash
python3 crawllerv2.py \
  --url https://target.com \
  --crawl-depth 3 \
  --timeout 20 \
  --tests sqli,xss \
  --run-nuclei \
  --run-subfinder \
  --run-wappalyzer \
  --proxy http://127.0.0.1:8080
```

### Advanced Configuration
```bash
python3 crawllerv2.py \
  --url https://app.example.com \
  --cookies "sessionid=abc123; csrftoken=xyz789" \
  --set-header "Authorization: Bearer token123; X-API-Key: secret" \
  --tests sqli,xss \
  --run-nuclei \
  --run-sqlmap \
  --run-arjun \
  --wordlist /path/to/custom/wordlist.txt
```

## 📖 Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | **Target URL (required)** | - |
| `--timeout` | Request timeout in seconds | 15 |
| `--crawl-depth` | Maximum crawler depth | 2 |
| `--cookies` | Cookie header string | - |
| `--set-header` | Custom headers (semicolon-separated) | - |
| `--proxy` | HTTP/HTTPS proxy URL | - |
| `--tests` | Internal fuzzer tests: `sqli`, `xss` | - |
| `--wordlist` | Custom wordlist for ffuf | SecLists default |

### External Tool Flags
| Flag | Tool | Purpose |
|------|------|---------|
| `--run-subfinder` | subfinder | Subdomain enumeration |
| `--run-wafw00f` | wafw00f | WAF detection |
| `--run-wappalyzer` | wappalyzer | Technology identification |
| `--run-ffuf` | ffuf | Directory/file fuzzing |
| `--run-nuclei` | nuclei | Vulnerability scanning |
| `--run-wapiti` | wapiti | Web app vulnerability assessment |
| `--run-sqlmap` | sqlmap | SQL injection exploitation |
| `--run-arjun` | arjun | Parameter discovery |

## 📁 Output

### Terminal Interface
- **Live Vulnerability Table**: Real-time discovery updates
- **Progress Tracking**: Multi-task progress with time elapsed
- **Severity Color Coding**: Visual risk assessment

### JSON Reports
Reports are automatically generated as `report_<domain>_<timestamp>.json`:

```json
{
  "scan_info": {
    "target": "https://example.com",
    "start_time": "Sat Jul  5 11:30:45 2025",
    "duration_seconds": 127
  },
  "config": {
    "url": "https://example.com",
    "timeout": "15",
    "tests": "sqli,xss"
  },
  "findings": [
    {
      "source": "ParamHunter",
      "vuln_type": "SQLi Time-Based",
      "url": "https://example.com/search",
      "severity": "High",
      "evidence": "Time: 6.2s base: 1.1s payload: 5s (mysql)",
      "parameter": "q",
      "payload": "' OR SLEEP(5)--",
      "timestamp": "11:31:22"
    }
  ]
}
```

## 🔧 Configuration

### Custom Headers
```bash
--set-header "Authorization: Bearer token123; X-Custom-Header: value"
```

### Authentication
```bash
--cookies "sessionid=abc123; auth_token=xyz789"
```

### Proxy Support
```bash
--proxy http://127.0.0.1:8080  # HTTP proxy
--proxy socks5://127.0.0.1:1080  # SOCKS5 proxy
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup
```bash
git clone https://github.com/yourusername/paramhunter-pro.git
cd paramhunter-pro
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Feature Requests & Bug Reports
- 🐛 [Report bugs](https://github.com/m2hcz/ParamHunter-Pro/issues)
- 💡 [Request features](https://github.com/m2hcz/ParamHunter-Pro/issues)
- 📖 [Documentation improvements](https://github.com/m2hcz/ParamHunter-Pro/pulls)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🎖️ Acknowledgments

- [Rich](https://github.com/Textualize/rich) - Beautiful terminal formatting
- [aiohttp](https://github.com/aio-libs/aiohttp) - Async HTTP client/server
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- Security community for vulnerability research and responsible disclosure

## 👨‍💻 Author

**m2hcs** - Senior Offensive Security Engineer
- 🐦 Twitter: [@inf0secc](https://twitter.com/inf0secc)
- 📧 Email: m2hczs@proton.me
- 🌐 GitHub: [@m2hcs](https://github.com/m2hcz)

---

<div align="center">
  <i>"The best defense is understanding the offense" 🔐</i>
  <br><br>
  <i>💡 Open to collaborations, security research discussions, and conference talks 💡</i>
</div>

---

⭐ **Star this repository if you find it useful!** ⭐
