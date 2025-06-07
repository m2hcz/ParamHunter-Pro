#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# --- ParamHunter Pro v6.0 (Ultimate Orchestrator) ---
#      A fully asynchronous, feature-rich, single-file Offensive Security Framework.
#      Integrates internal fuzzing with a suite of external tools like Nuclei, Nikto, and more.

from __future__ import annotations
import argparse
import asyncio
import json
import re
import time
import os
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import random
import string

import aiohttp
from bs4 import BeautifulSoup

# Rich for beautiful, real-time terminal UI
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns

# --- PAYLOADS & CONFIGURATION ---
PAYLOADS_DATA = {
    "sqli": {
        "error_based": ["'", "\"", "`", "' OR '1'='1"],
        "time_based": {
            "mysql": ("AND SLEEP({delay})-- ", 5),
            "postgres": ("AND pg_sleep({delay})-- ", 5),
            "mssql": ("WAITFOR DELAY '0:0:{delay}'-- ", 5)
        }
    },
    "xss": {
        "payloads": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "'\"/><svg onload=alert(1)>"]
    }
} # put yours payloads here...

# --- DATA STRUCTURES ---
@dataclass(frozen=True)
class Vulnerability:
    source: str
    vuln_type: str
    url: str
    severity: str
    evidence: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    timestamp: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))

@dataclass
class Endpoint:
    url: str
    method: str
    params: Dict[str, str] = field(default_factory=dict)
    def __hash__(self): return hash((self.url, self.method, tuple(sorted(self.params.items()))))
    def __eq__(self, other):
        if not isinstance(other, Endpoint): return NotImplemented
        return self.url == other.url and self.method == other.method and self.params == other.params

# --- CORE MODULES ---
class PayloadManager:
    def __init__(self, payload_data: Dict): self._payloads = payload_data
    def get_payloads(self, vuln_type: str) -> List[Any]: return self._payloads.get(vuln_type, {}).get("payloads", [])
    def get_payload_map(self, vuln_type: str) -> Dict[str, Any]: return self._payloads.get(vuln_type, {})

class SessionManager:
    def __init__(self, headers: Dict, cookies: str, proxy: Optional[str], timeout: int):
        self._headers = headers or {}
        if "User-Agent" not in self._headers: self._headers["User-Agent"] = "ParamHunterPro/6.0"
        self._cookies_str = cookies
        self._proxy = proxy
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> aiohttp.ClientSession:
        self.session = aiohttp.ClientSession(headers=self._headers, timeout=self._timeout, connector=aiohttp.TCPConnector(ssl=False))
        if self._cookies_str: self.session.cookie_jar.update_cookies({k.strip(): v.strip() for k, v in (p.split('=', 1) for p in self._cookies_str.split(';') if '=' in p)})
        return self.session

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session: await self.session.close()

class ExternalToolManager:
    def __init__(self, console: Console, output_dir="scan_results"):
        self.console = console
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir): os.makedirs(self.output_dir)

    async def _run_command(self, tool_name: str, command: str) -> bool:
        self.console.log(f":rocket: [bold cyan]Starting {tool_name}...[/] [dim]{command}[/dim]")
        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _, stderr = await process.communicate()
        if process.returncode != 0:
            self.console.log(f":cross_mark: [bold red]Error running {tool_name}.[/] Stderr: {stderr.decode(errors='ignore')[:200]}")
            return False
        self.console.log(f":check_mark_button: [bold green]{tool_name} finished.[/]")
        return True

    async def run_subfinder(self, domain: str) -> List[str]:
        output_file = os.path.join(self.output_dir, f"subfinder_{domain}.txt")
        command = f"subfinder -d {domain} -o {output_file} -silent"
        if not await self._run_command("Subfinder", command): return []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f: return [line.strip() for line in f if line.strip()]
        return []

    async def run_nuclei(self, target: str) -> List[Vulnerability]:
        output_file = os.path.join(self.output_dir, f"nuclei_{urlparse(target).netloc}.json")
        command = f"nuclei -u {target} -json -o {output_file} -silent -disable-update-check"
        if not await self._run_command("Nuclei", command): return []
        vulns = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        res = json.loads(line)
                        vulns.append(Vulnerability(source="Nuclei", vuln_type=res.get('info', {}).get('name', 'N/A'), url=res.get('matched-at', target), severity=res.get('info', {}).get('severity', 'info').capitalize(), evidence=f"Template: {res.get('template-id')}"))
                    except json.JSONDecodeError: continue
        return vulns

    async def run_nikto(self, target: str) -> List[Vulnerability]:
        output_file = os.path.join(self.output_dir, f"nikto_{urlparse(target).netloc}.json")
        command = f"nikto -h {target} -o {output_file} -Format json"
        if not await self._run_command("Nikto", command): return []
        vulns = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    data = json.load(f)
                    for item in data.get('vulnerabilities', []):
                        vulns.append(Vulnerability(source="Nikto", vuln_type=f"Nikto-{item.get('id')}", url=item.get('url'), severity="Info", evidence=item.get('msg').replace('\n', ' ')))
                except json.JSONDecodeError: pass
        return vulns
    
    async def run_wapiti(self, target: str) -> List[Vulnerability]:
        wapiti_out = os.path.join(self.output_dir, f"wapiti_{urlparse(target).netloc}")
        report_file = os.path.join(wapiti_out, "report.json")
        command = f"wapiti -u {target} -o {wapiti_out} -f json --scope url -m http_headers,xss,sql,crlf"
        if not await self._run_command("Wapiti", command): return []
        vulns = []
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                try:
                    data = json.load(f)
                    for classification, found_vulns in data.get('vulnerabilities', {}).items():
                        for v in found_vulns:
                            vulns.append(Vulnerability(source="Wapiti", vuln_type=classification, url=target, severity=v.get('level', 'Info'), evidence=v.get('info', 'N/A'), parameter=v.get('parameter')))
                except json.JSONDecodeError: pass
        return vulns

class Crawler:
    def __init__(self, session: aiohttp.ClientSession, base_url: str, max_depth: int):
        self.session, self.base_url, self.target_domain, self.max_depth = session, base_url, urlparse(base_url).netloc, max_depth
        self.queue, self.crawled_urls, self.discovered_endpoints = asyncio.Queue(), set(), set()

    async def run(self, progress: Progress) -> Set[Endpoint]:
        task = progress.add_task("[cyan]Crawling", total=None)
        await self.queue.put((self.base_url, 0))
        workers = [asyncio.create_task(self._worker(progress, task)) for _ in range(15)]
        await self.queue.join()
        for w in workers: w.cancel()
        progress.update(task, description=f"[green]Crawled {len(self.crawled_urls)} URLs", total=len(self.crawled_urls), completed=len(self.crawled_urls))
        return self.discovered_endpoints

    async def _worker(self, progress: Progress, task_id: int):
        while True:
            try:
                url, depth = await self.queue.get()
                norm_url = self._normalize_url(url)

                if not norm_url or urlparse(norm_url).netloc != self.target_domain or norm_url in self.crawled_urls or depth > self.max_depth:
                # self.queue.task_done()  <--- REMOVIDO
                    continue

                self.crawled_urls.add(norm_url)
            except asyncio.CancelledError:
                break 
            except Exception:
                pass
            finally:
                if self.queue.qsize() > 0 or not self.queue.empty():
                    self.queue.task_done()
    def _normalize_url(self, url: str) -> Optional[str]:
        try:
            full_url = urljoin(self.base_url, url.strip())
            if urlparse(full_url).scheme not in {"http", "https"} or any(urlparse(full_url).path.lower().endswith(ext) for ext in {'.css','.js','.png','.jpg','.svg'}): return None
            return urlparse(full_url)._replace(query="", fragment="").geturl()
        except ValueError: return None

    async def _parse_and_discover(self, content: str, base_url: str, depth: int):
        soup = BeautifulSoup(content, 'html.parser')
        for tag in soup.find_all(['a', 'link', 'iframe', 'script'], href=True, src=True):
            if link := tag.get('href') or tag.get('src'): await self.queue.put((link, depth + 1))
        for form in soup.find_all('form'):
            if urlparse(form_url := urljoin(base_url, form.get('action', ''))).netloc == self.target_domain:
                params = {inp.get('name'): inp.get('value', '') for inp in form.find_all(['input', 'textarea']) if inp.get('name')}
                self.discovered_endpoints.add(Endpoint(url=self._normalize_url(form_url), method=form.get('method', 'get').upper(), params=params))

class Fuzzer:
    def __init__(self, session: aiohttp.ClientSession, endpoints: Set[Endpoint], tests: List[str], payload_manager: PayloadManager):
        self.session, self.endpoints, self.tests, self.payloads = session, list(endpoints), tests, payload_manager

    async def run(self, progress: Progress):
        fuzz_task = progress.add_task("[magenta]Fuzzing Interno", total=len(self.endpoints) if self.endpoints else 1)
        if not self.endpoints: progress.update(fuzz_task, completed=1); return
        tasks = [self._fuzz_endpoint(endpoint, progress, fuzz_task) for endpoint in self.endpoints]
        for future in asyncio.as_completed(tasks):
            try:
                async for vuln in await future: yield vuln
            except Exception: pass

    async def _fuzz_endpoint(self, endpoint: Endpoint, progress: Progress, task_id: int):
        if "sqli" in self.tests:
            async for vuln in self._check_sqli(endpoint): yield vuln
        progress.update(task_id, advance=1)

    async def _make_request(self, method, url, **kwargs):
        try:
            start_time = time.monotonic()
            async with self.session.request(method, url, **kwargs) as response: return response, time.monotonic() - start_time
        except Exception: return None, 0

    async def _check_sqli(self, endpoint: Endpoint):
        for param in endpoint.params:
            for _, (payload_str, delay) in self.payloads.get_payload_map("sqli").get("time_based", {}).items():
                fuzzed_params = endpoint.params.copy(); fuzzed_params[param] = endpoint.params[param] + payload_str.format(delay=delay)
                kwargs_base = {'params' if endpoint.method=="GET" else 'data': endpoint.params}
                kwargs_fuzz = {'params' if endpoint.method=="GET" else 'data': fuzzed_params}
                _, baseline_duration = await self._make_request(endpoint.method, endpoint.url, **kwargs_base)
                _, duration = await self._make_request(endpoint.method, endpoint.url, **kwargs_fuzz)
                if duration > (baseline_duration + delay * 0.8) and baseline_duration > 0:
                    yield Vulnerability(source="ParamHunter", vuln_type="SQLI_TIME_BASED", url=endpoint.url, method=endpoint.method, parameter=param, payload=payload_str, evidence=f"Response took {duration:.2f}s (baseline: {baseline_duration:.2f}s)", severity="High")

class Reporter:
    def __init__(self, console: Console):
        self.console, self.findings = console, []
    def add_findings(self, vulns: List[Vulnerability]): self.findings.extend(vulns)
    def generate_json_report(self, target: str, args: argparse.Namespace, start_time: float):
        self.console.log(":memo: [bold blue]Generating final report...[/]")
        report = {
            "scan_info": {"target": target, "start_time": time.ctime(start_time), "duration_seconds": round(time.time() - start_time)},
            "config": vars(args),
            "findings": sorted([v.__dict__ for v in self.findings], key=lambda x: ({"High":0,"Medium":1,"Low":2,"Info":3}.get(x.get('severity'),4), x.get('vuln_type')))
        }
        filename = f"report_{urlparse(target).netloc}_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f: json.dump(report, f, indent=4)
        self.console.log(f":file_folder: [bold green]Report saved to {filename}[/]")

class ScanController:
    def __init__(self, args: argparse.Namespace):
        self.args, self.console, self.reporter, self.start_time = args, Console(), Reporter(Console()), time.time()

    def _setup_ui(self) -> Tuple[Live, Table, Progress]:
        vuln_table = Table(title="Vulnerabilities Found", expand=True, border_style="red")
        vuln_table.add_column("Time", style="dim"); vuln_table.add_column("Source", style="cyan"); vuln_table.add_column("Type", style="yellow"); vuln_table.add_column("Severity"); vuln_table.add_column("URL", style="magenta")
        progress = Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeElapsedColumn())
        live = Live(Panel(Columns([Panel(vuln_table, title="[bold green]Findings[/]"), Panel(progress, title="[bold blue]Progress[/]")])), console=self.console, screen=False, auto_refresh=True, vertical_overflow="visible")
        return live, vuln_table, progress

    async def run(self):
        self.console.print(Panel(Text("ParamHunter Pro v6.0 - Ultimate Orchestrator", justify="center"), title="[bold yellow]INITIALIZING SCAN[/]", border_style="yellow"))
        live, vuln_table, progress = self._setup_ui()
        with live:
            headers = {k:v for k,v in (h.split(':', 1) for h in self.args.headers.split(';'))} if self.args.headers else {}
            async with SessionManager(headers, self.args.cookies, self.args.proxy, self.args.timeout) as session:
                tool_manager, reporter = ExternalToolManager(self.console), Reporter(self.console)
                
                # FASE 1: ESCOPO
                targets = {self.args.url}
                if self.args.run_subfinder:
                    subs = await tool_manager.run_subfinder(urlparse(self.args.url).netloc)
                    targets.update([f"https://{s}" for s in subs if s])
                live.update(Panel(f"Scope defined: [bold green]{len(targets)}[/] total targets."))

                # FASE 2: SCANNERS EXTERNOS EM TODOS OS ALVOS
                external_tasks = []
                for target in targets:
                    if self.args.run_nuclei: external_tasks.append(tool_manager.run_nuclei(target))
                    if self.args.run_nikto: external_tasks.append(tool_manager.run_nikto(target))
                    if self.args.run_wapiti: external_tasks.append(tool_manager.run_wapiti(target))
                
                if external_tasks:
                    for future in asyncio.as_completed(external_tasks):
                        for vuln in await future:
                            sev_color = "red" if vuln.severity == "High" else "yellow" if vuln.severity == "Medium" else "white"
                            vuln_table.add_row(vuln.timestamp, vuln.source, vuln.vuln_type, f"[{sev_color}]{vuln.severity}[/]", vuln.url)
                            reporter.add_findings([vuln])

                # FASE 3: CRAWLING & FUZZING INTERNO (NO ALVO PRINCIPAL)
                crawler = Crawler(session, self.args.url, self.args.crawl_depth)
                endpoints = await crawler.run(progress)
                if endpoints:
                    fuzzer = Fuzzer(session, endpoints, self.args.tests.split(',') if self.args.tests else [], PayloadManager(PAYLOADS_DATA))
                    async for vuln in fuzzer.run(progress):
                        vuln_table.add_row(vuln.timestamp, vuln.source, vuln.vuln_type, f"[bold red]{vuln.severity}[/]", vuln.url)
                        reporter.add_findings([vuln])

        # FASE 4: RELATÓRIO FINAL
        self.console.print(Panel(Text("Scan Finished!", justify="center"), title="[bold green]COMPLETE[/]", border_style="green"))
        reporter.generate_json_report(self.args.url, self.args, self.start_time)

def main():
    parser = argparse.ArgumentParser(description="ParamHunter Pro v6.0 - Offensive Security Automation Framework")
    parser.add_argument('-u', '--url', required=True, help='Main target URL (e.g., http://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=25, help='Concurrency limit (not directly used, for config only)')
    parser.add_argument('--timeout', type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument('--crawl-depth', type=int, default=1, help="Maximum crawling depth")
    parser.add_argument('--cookies', help='Cookies ("sessionid=abc;user=def")')
    parser.add_argument('--headers', help='Custom headers ("X-API-Key:val;Auth:token")')
    parser.add_argument('--proxy', help='Proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--tests', help='Internal fuzzer tests (sqli,xss)')
    parser.add_argument('--run-subfinder', action='store_true', help='Execute Subfinder for subdomain enumeration.')
    parser.add_argument('--run-nuclei', action='store_true', help='Execute Nuclei for template-based scanning.')
    parser.add_argument('--run-nikto', action='store_true', help='Execute Nikto for web server scanning.')
    parser.add_argument('--run-wapiti', action='store_true', help='Execute Wapiti for black-box app scanning.')
    args = parser.parse_args()

    try:
        asyncio.run(ScanController(args).run())
    except KeyboardInterrupt:
        Console().print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
    except Exception as e:
        Console().print(f"\n[bold red]A fatal error occurred: {e}[/]")

if __name__ == "__main__":
    main()
