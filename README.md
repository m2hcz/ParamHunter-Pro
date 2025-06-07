# ParamHunter Pro v6.1

An advanced, asynchronous, single-file Offensive Security Framework. It combines deep, parameter-focused fuzzing with the orchestration of industry-standard security tools like Nuclei, Nikto, and more.

<p align="center">
  <a href="#"><img src="https://img.shields.io/github/stars/YourUsername/ParamHunter-Pro?style=social" alt="Stars"></a>
  <a href="#"><img src="https://img.shields.io/github/issues/YourUsername/ParamHunter-Pro" alt="Issues"></a>
  <a href="#"><img src="https://img.shields.io/github/license/YourUsername/ParamHunter-Pro" alt="License"></a>
</p>

---

## Disclaimer

This tool is for educational purposes and authorized security testing **only**. The use of this tool against systems without explicit prior permission is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Key Features

* **Asynchronous Engine:** Built with `asyncio` and `aiohttp` for high-speed, non-blocking network I/O, allowing for massive concurrency.
* **Real-Time Dashboard UI:** Utilizes the `rich` library to provide a live, in-terminal dashboard with progress bars, spinners, and a table of vulnerabilities found in real-time.
* **Multi-Tool Orchestration:** Acts as a control plane, intelligently running a suite of external security tools as part of its workflow.
* **Deep Internal Fuzzer:** The original ParamHunter logic for surgical fuzzing of discovered parameters, testing for complex vulnerabilities like Time-Based SQLi.
* **Intelligent Crawling:** Discovers endpoints by parsing HTML (`a`, `form`, `script`, etc.) with configurable depth.
* **Unified Reporting:** All findings, from both the internal fuzzer and all external tools, are collected, normalized, and saved into a single, detailed JSON report.
* **Advanced Session Control:** Full support for custom HTTP Headers, Cookies, and Proxies.

## Tools Orchestrated

ParamHunter Pro integrates and manages the following industry-standard tools:

1.  **Subfinder:** For comprehensive subdomain enumeration to define the attack surface.
2.  **Nikto:** For web server scanning to identify outdated software and configuration issues.
3.  **Nuclei:** For fast, template-based scanning to find known vulnerabilities and CVEs.
4.  **Wapiti:** For black-box web application vulnerability scanning (XSS, SQLi, LFI, etc.).
5.  *(Support for Wafw00f, Wappalyzer, and others can be added following the same pattern)*

## Prerequisites

Before running, you **MUST** have the following installed on your system:

1.  **Python 3.8+** and **Pip**.
2.  **External Tools:** The following tools must be installed and accessible in your system's `PATH`:
    * [Subfinder](https://github.com/projectdiscovery/subfinder)
    * [Nuclei](https://github.com/projectdiscovery/nuclei)
    * [Nikto](https://github.com/sullo/nikto)
    * [Wapiti](https://wapiti.sourceforge.io/)
3.  **Python Libraries:** The required libraries can be installed via `pip`.

## Usage Examples

* **Basic scan using only the internal crawler and fuzzer on a single target:**
    ```sh
    python3 paramhunter_pro.py -u [http://testphp.vulnweb.com](http://testphp.vulnweb.com) --tests sqli
    ```

* **Full orchestration scan on a domain, running all integrated tools:**
    ```sh
    python3 paramhunter_pro.py -u [https://example.com](https://example.com) --run-subfinder --run-nuclei --run-nikto --run-wapiti
    ```

* **A deep, configured scan using a proxy and custom cookies:**
    ```sh
    python3 paramhunter_pro.py -u [https://bugbounty.target.com](https://bugbounty.target.com) --crawl-depth 3 --proxy [http://127.0.0.1:8080](http://127.0.0.1:8080) --cookies "session=xyz; logged_in=true" --run-nuclei
    ```

## Command-Line Options

```
usage: paramhunter_pro.py [-h] -u URL [-t THREADS] [--timeout TIMEOUT] [--crawl-depth CRAWL_DEPTH] [--cookies COOKIES] [--headers HEADERS]
                          [--proxy PROXY] [--tests TESTS] [--run-subfinder] [--run-nuclei] [--run-nikto] [--run-wapiti]

ParamHunter Pro v6.1 - Offensive Security Automation Framework

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Main target URL (e.g., [http://example.com](http://example.com))
  -t THREADS, --threads THREADS
                        Concurrency limit for some operations.
  --timeout TIMEOUT     Request timeout (seconds)
  --crawl-depth CRAWL_DEPTH
                        Maximum crawling depth
  --cookies COOKIES     Cookies ("sessionid=abc;user=def")
  --headers HEADERS     Custom headers ("X-API-Key:val;Auth:token")
  --proxy PROXY         Proxy (e.g., [http://127.0.0.1:8080](http://127.0.0.1:8080))
  --tests TESTS         Internal fuzzer tests (sqli,xss)
  --run-subfinder       Execute Subfinder for subdomain enumeration.
  --run-nuclei          Execute Nuclei for template-based scanning.
  --run-nikto           Execute Nikto for web server scanning.
  --run-wapiti          Execute Wapiti for black-box app scanning.
```

## Workflow

When executed, the orchestrator follows a logical attack sequence:

1.  **Scope Definition:** If `--run-subfinder` is enabled, it first enumerates all subdomains of the target domain to define the full scope.
2.  **External Scanning:** It then launches Nikto, Nuclei, and Wapiti concurrently against the defined targets.
3.  **Internal Crawling:** While external tools run, the internal crawler maps the main target application, discovering endpoints and parameters.
4.  **Deep Fuzzing:** The internal fuzzer tests the discovered endpoints with advanced payloads for the specified vulnerability classes.
5.  **Unified Reporting:** All findings from every source are collected, normalized, and saved into a single timestamped JSON file for analysis.
