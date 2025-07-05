#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup
from rich.columns import Columns
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

console = Console()


class Severity(Enum):
    CRITICAL   = ("Critical",   "bold red")
    HIGH       = ("High",       "red")
    MEDIUM     = ("Medium",     "yellow")
    LOW        = ("Low",        "white")
    INFORMATIONAL = ("Informational", "dim")

    def __str__(self) -> str:
        return self.value[0]

    @property
    def color(self) -> str:
        return self.value[1]


def log_ok(msg: str)   -> None: console.log(f":white_check_mark: [green]{msg}[/]")
def log_warn(msg: str) -> None: console.log(f":warning: [yellow]{msg}[/]")
def log_err(msg: str)  -> None: console.log(f":x: [bold red]{msg}[/]")


PAYLOADS_DATA: Dict[str, Any] = {
    "sqli": {
        "payloads": ["'", "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT null,null,null--"],
        "time_based": {
            "mysql": ("' OR SLEEP({delay})--", 5),
            "postgres": ("'; SELECT pg_sleep({delay})--", 5),
            "mssql": ("'; WAITFOR DELAY '00:00:0{delay}'--", 5)
        },
        "error_patterns": [
            re.compile(r"sql syntax.*mysql", re.I),
            re.compile(r"warning.*mysql_", re.I),
            re.compile(r"valid mysql result", re.I),
            re.compile(r"postgresql.*error", re.I),
            re.compile(r"warning.*pg_", re.I),
            re.compile(r"valid postgresql result", re.I),
            re.compile(r"microsoft.*odbc.*sql server", re.I),
            re.compile(r"sqlite_exception", re.I)
        ]
    },
    "xss": {
        "payloads": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>"
        ]
    }
}


@dataclass(frozen=True, slots=True)
class Vulnerability:
    source: str
    vuln_type: str
    url: str
    severity: Severity
    evidence: str
    parameter: Optional[str] = None
    payload: Optional[str]   = None
    timestamp: str = field(default_factory=lambda: time.strftime("%H:%M:%S"))


@dataclass(slots=True)
class Endpoint:
    url: str
    method: str
    params: Dict[str, str] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.url, self.method, tuple(sorted(self.params.items()))))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Endpoint)
            and self.url == other.url
            and self.method == other.method
            and self.params == other.params
        )


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="paramhunter",
        description="ParamHunter Pro v6.9 – Stalker Edition"
    )
    p.add_argument("-u", "--url",        required=True, help="Target URL (https://…)") 
    p.add_argument("--timeout",          type=int, default=15, help="Timeout in seconds")
    p.add_argument("--crawl-depth",      type=int, default=2,  help="Crawler max depth")
    p.add_argument("--cookies",          help='Cookies e.g. "sessionid=abc; user=def"')
    p.add_argument("--set-header",       help='Custom headers e.g. "X-Api-Key:val; Authorization:Bearer token"')
    p.add_argument("--proxy",            help="Proxy URL (http://127.0.0.1:8080)")
    p.add_argument("--tests",            help="Internal fuzzer tests e.g. sqli,xss")
    ext = p.add_argument_group("External tools")
    for tool in ["subfinder","wafw00f","wappalyzer","ffuf","nuclei","wapiti","sqlmap","arjun"]:
        ext.add_argument(f"--run-{tool}", action="store_true",
                         help=f"Run external scanner {tool}")
    p.add_argument("--wordlist",
                   default="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                   help="Wordlist for ffuf")
    return p


# ... existing SessionManager, PayloadManager, Crawler, Fuzzer classes ...
# ... unchanged except for replacing Portuguese strings in exceptions/logs ...

class SessionManager:
    def __init__(self, headers: Dict[str,str], cookies: Optional[str], timeout: int, limit_per_host: int = 20):
        self._headers = headers
        self._headers.setdefault("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        self._cookies_str = cookies
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._connector = aiohttp.TCPConnector(ssl=False, limit_per_host=limit_per_host)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> aiohttp.ClientSession:
        self.session = aiohttp.ClientSession(headers=self._headers, timeout=self._timeout, connector=self._connector)
        if self._cookies_str:
            ck = {k.strip():v.strip() for k,v in (p.split("=",1) for p in self._cookies_str.split(";") if "=" in p)}
            self.session.cookie_jar.update_cookies(ck)
        return self.session

    async def __aexit__(self, *_):
        if self.session:
            await self.session.close()


class PayloadManager:
    def __init__(self, payload_data: Dict[str, Any]):
        self._payloads = payload_data

    def get_payloads(self, vuln_type: str) -> List[str]:
        return self._payloads.get(vuln_type, {}).get("payloads", [])

    def get_payload_map(self, vuln_type: str) -> Dict[str, Any]:
        return self._payloads.get(vuln_type, {})


class Crawler:
    def __init__(self, session: aiohttp.ClientSession, base_url: str, max_depth: int, proxy: Optional[str], concurrency: int = 100):
        self.session = session
        self.base_url = base_url
        self.target_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.proxy = proxy
        self.queue: asyncio.Queue[Tuple[str,int]] = asyncio.Queue()
        self.crawled: Set[str] = set()
        self.endpoints: Set[Endpoint] = set()
        self.sem = asyncio.Semaphore(concurrency)

    async def run(self, progress: Progress) -> Set[Endpoint]:
        task = progress.add_task("[cyan]Internal Crawler", total=None)
        await self.queue.put((self.base_url,0))
        self.crawled.add(self._norm(self.base_url))
        workers = [asyncio.create_task(self._worker()) for _ in range(10)]
        await self.queue.join()
        for w in workers: 
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        progress.update(task, description=f"[green]Crawled {len(self.crawled)} URLs", total=len(self.crawled), completed=len(self.crawled))
        return self.endpoints

    async def _worker(self):
        while True:
            url, depth = await self.queue.get()
            async with self.sem:
                await self._process(url, depth)
            self.queue.task_done()

    async def _process(self, url: str, depth: int):
        norm = self._norm(url)
        if not norm or urlparse(norm).netloc != self.target_domain or depth > self.max_depth:
            return
        try:
            async with self.session.get(norm, proxy=self.proxy) as resp:
                if resp.ok and "text/html" in resp.headers.get("Content-Type",""):
                    html = await resp.text()
                    await self._parse(html, norm, depth)
        except aiohttp.ClientError:
            pass

    def _norm(self, url: str) -> Optional[str]:
        try:
            full = urljoin(self.base_url, url.strip())
            p = urlparse(full)
            if p.scheme not in {"http","https"} or p.path.lower().endswith((".css",".js",".png",".jpg",".svg",".woff",".ico")):
                return None
            return p._replace(query="",fragment="").geturl()
        except:
            return None

    async def _parse(self, html: str, base: str, depth: int):
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a","link"], href=True):
            ln = self._norm(tag["href"])
            if ln and ln not in self.crawled:
                self.crawled.add(ln)
                await self.queue.put((ln, depth+1))
        for form in soup.find_all("form"):
            action = form.get("action","")
            full = self._norm(urljoin(base, action))
            if full:
                params = {i.get("name"): i.get("value","") for i in form.find_all(["input","textarea"]) if i.get("name")}
                method = form.get("method","get").upper()
                self.endpoints.add(Endpoint(full, method, params))


class Fuzzer:
    def __init__(self, session: aiohttp.ClientSession, endpoints: Set[Endpoint], tests: List[str], payloads: PayloadManager, proxy: Optional[str]):
        self.session = session
        self.endpoints = list(endpoints)
        self.proxy = proxy
        self.pm = payloads
        self.test_map = {"sqli":[self._time_sqli,self._error_sqli], "xss":[self._xss]}
        self.active = [f for t in tests for f in self.test_map.get(t,[])]

    async def run(self, progress: Progress) -> AsyncGenerator[Vulnerability, None]:
        if not self.endpoints or not self.active: 
            return
        task = progress.add_task("[magenta]Internal Fuzzer", total=len(self.endpoints)*len(self.active))
        for ep in self.endpoints:
            for test in self.active:
                async for v in test(ep):
                    yield v
                progress.update(task, advance=1)

    async def _request(self, method: str, url: str, **kw) -> Tuple[Optional[str], float]:
        try:
            t0 = time.monotonic()
            async with self.session.request(method, url, proxy=self.proxy, **kw) as r:
                return await r.text(), time.monotonic()-t0
        except:
            return None,0

    async def _time_sqli(self, ep: Endpoint):
        base_html, base_dur = await self._request(ep.method, ep.url, params=ep.params if ep.method=="GET" else None, data=ep.params if ep.method=="POST" else None)
        if base_dur==0: 
            return
        for param in ep.params:
            for db,(tpl,delay) in self.pm.get_payload_map("sqli")["time_based"].items():
                p = tpl.format(delay=delay)
                np = ep.params.copy(); np[param] = (np.get(param,"") or "") + p
                _, dur = await self._request(ep.method, ep.url, params=np if ep.method=="GET" else None, data=np if ep.method=="POST" else None)
                if dur > base_dur + delay*0.8:
                    yield Vulnerability("ParamHunter","SQLi Time-Based", ep.url, Severity.HIGH, f"Time: {dur:.2f}s base: {base_dur:.2f}s payload: {delay}s ({db})",param,p)

    async def _error_sqli(self, ep: Endpoint):
        patterns = self.pm.get_payload_map("sqli")["error_patterns"]
        for param in ep.params:
            for p in self.pm.get_payloads("sqli"):
                np = ep.params.copy(); np[param] = (np.get(param,"") or "") + p
                html,_ = await self._request(ep.method, ep.url, params=np if ep.method=="GET" else None, data=np if ep.method=="POST" else None)
                if html and any(rx.search(html) for rx in patterns):
                    yield Vulnerability("ParamHunter","SQLi Error-Based", ep.url, Severity.HIGH, "Error displayed via payload.", param, p)

    async def _xss(self, ep: Endpoint):
        for param in ep.params:
            for p in self.pm.get_payloads("xss"):
                np = ep.params.copy(); np[param] = p
                html,_ = await self._request(ep.method, ep.url, params=np if ep.method=="GET" else None, data=np if ep.method=="POST" else None)
                if html and p in html:
                    yield Vulnerability("ParamHunter","Reflected XSS", ep.url, Severity.MEDIUM, "Payload reflected.", param, p)


class ExternalToolManager:
    def __init__(self, console: Console, output_dir: Path):
        self.console = console
        self.output_dir = output_dir

    async def run_subfinder(self, target: str) -> List[Vulnerability]: 
        return []
    async def run_wafw00f(self, target: str) -> List[Vulnerability]: 
        return []
    async def run_wappalyzer(self, target: str) -> List[Vulnerability]: 
        return []
    async def run_ffuf(self, target: str, wordlist: Path) -> List[Vulnerability]: 
        return []
    async def run_nuclei(self, target: str) -> List[Vulnerability]: 
        return []
    async def run_wapiti(self, target: str) -> List[Vulnerability]: 
        return []
    async def run_sqlmap(self, target: str, cookies: Optional[str]) -> List[Vulnerability]: 
        return []
    async def run_arjun(self, target: str) -> List[Vulnerability]: 
        return []

class Reporter:
    def __init__(self, console: Console):
        self.console = console
        self.findings: List[Vulnerability] = []

    def add(self, vulns: List[Vulnerability]):
        self.findings.extend(vulns)

    def json_report(self, target: str, args: argparse.Namespace, start: float):
        self.console.log(":memo: [bold blue]Generating JSON report...[/]")
        data = {
            "scan_info": {"target": target, "start_time": time.ctime(start), "duration_seconds": round(time.time() - start)},
            "config": {k: str(v) for k, v in vars(args).items()},
            "findings": [
                {**v.__dict__, "severity": str(v.severity)}
                for v in sorted(self.findings, key=lambda x: (list(Severity).index(x.severity), x.vuln_type, x.url))
            ]
        }
        fname = f"report_{urlparse(target).netloc}_{time.strftime('%Y%m%d_%H%M%S')}.json"
        Path(fname).write_text(json.dumps(data, indent=4, ensure_ascii=False))
        log_ok(f"Report saved to {Path(fname).resolve()}")

class ScanController:
    def __init__(self, args: argparse.Namespace, headers: Dict[str,str]):
        self.args = args
        self.headers = headers
        self.console = Console()
        self.reporter = Reporter(self.console)
        self.start_time = time.time()
        self.tool_cfg = {
            'run_subfinder': ('subfinder','go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'),
            'run_wafw00f':   ('wafw00f','pip3 install wafw00f'),
            'run_wappalyzer':('wappalyzer-cli','npm install -g wappalyzer-cli'),
            'run_ffuf':      ('ffuf','go install -v github.com/ffuf/ffuf/v2@latest'),
            'run_nuclei':    ('nuclei','go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'),
            'run_wapiti':    ('wapiti','pip3 install wapiti3'),
            'run_sqlmap':    ('sqlmap','sudo apt-get install sqlmap'),
            'run_arjun':     ('arjun','pip3 install arjun'),
        }

    def _check_dependencies(self):
        self.console.print(Panel("[yellow]Checking dependencies...[/]", title="Pre-Run", border_style="yellow"))
        for arg,(cmd,inst) in self.tool_cfg.items():
            if getattr(self.args, arg) and shutil.which(cmd) is None:
                self.console.print(f":x: [bold red]Tool '{cmd}' not found. Install with: [green]{inst}[/]")
                setattr(self.args, arg, False)
        self.console.print("-"*60)

    def _setup_ui(self):
        table = Table(title="Found Vulnerabilities", expand=True, border_style="red")
        for col,style in [("Time","dim"),("Source","cyan"),("Severity",""),("Type","yellow"),("URL","magenta"),("Evidence","")]:
            table.add_column(col, style=style)
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn()
        )
        layout = Panel(
            Columns([
                Panel(table, title="[bold green]Discoveries[/]"),
                Panel(progress, title="[bold blue]Progress[/]")
            ])
        )
        return Live(layout, console=self.console, screen=False, auto_refresh=True), table, progress

    async def run(self):
        self.console.print(Panel(Text("ParamHunter Pro v6.9 - Stalker Edition",justify="center"), title="[bold yellow]INITIALIZING[/]",border_style="yellow"))
        self._check_dependencies()
        live, table, progress = self._setup_ui()
        with live:
            async with SessionManager(self.headers, self.args.cookies, self.args.timeout) as session:
                tool_mgr = ExternalToolManager(self.console, Path("scan_results"))
                targets = {self.args.url}
                
                if self.args.run_subfinder:
                    subs = await tool_mgr.run_subfinder(urlparse(self.args.url).netloc)
                    targets.update(f"https://{s}" for s in subs)
                
                ext_tasks = []
                for arg,func in {
                    'run_wafw00f':tool_mgr.run_wafw00f,
                    'run_wappalyzer':tool_mgr.run_wappalyzer,
                    'run_ffuf':lambda t: tool_mgr.run_ffuf(t, Path(self.args.wordlist)),
                    'run_nuclei':tool_mgr.run_nuclei,
                    'run_wapiti':tool_mgr.run_wapiti,
                    'run_sqlmap':lambda t: tool_mgr.run_sqlmap(t,self.args.cookies),
                    'run_arjun':tool_mgr.run_arjun
                }.items():
                    if getattr(self.args, arg):
                        for t in targets: 
                            ext_tasks.append(func(t))
                
                if ext_tasks:
                    task = progress.add_task("[yellow]External Scanners", total=len(ext_tasks))
                    for fut in asyncio.as_completed(ext_tasks):
                        res = await fut
                        if res: 
                            self.reporter.add(res)
                            for v in res:
                                table.add_row(v.timestamp, v.source, f"[{v.severity.color}]{v.severity}[/]", v.vuln_type, v.url, v.evidence)
                        progress.update(task, advance=1)
                
                crawler = Crawler(session, self.args.url, self.args.crawl_depth, self.args.proxy)
                endpoints = await crawler.run(progress)
                
                if endpoints and self.args.tests:
                    f = Fuzzer(session, endpoints, self.args.tests.split(','), PayloadManager(PAYLOADS_DATA), self.args.proxy)
                    async for v in f.run(progress):
                        self.reporter.add([v])
                        table.add_row(v.timestamp, v.source, f"[{v.severity.color}]{v.severity}[/]", v.vuln_type, v.url, v.evidence)
        
        self.console.print(Panel(Text("Scan Complete!",justify="center"), title="[bold green]DONE[/]",border_style="green"))
        self.reporter.json_report(self.args.url, self.args, self.start_time)

async def _main():
    parser = build_arg_parser()
    args = parser.parse_args()
    if not urlparse(args.url).scheme:
        log_err("URL must start with http:// or https://")
        raise SystemExit(1)
    headers: Dict[str,str] = {}
    if args.set_header:
        for h in args.set_header.split(";"):
            if ":" not in h:
                log_warn(f"Ignoring malformed header: {h}")
                continue
            k,v = (p.strip() for p in h.split(":",1))
            if k and v: headers[k] = v
    ctrl = ScanController(args, headers)
    await ctrl.run()


if __name__=="__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/]")
    except Exception as exc:
        log_err(f"Unexpected error: {exc}")
        console.print_exception(show_locals=True)
