#!/usr/bin/env python3
"""
CerberusScan - Web Security Scanner
Usage:
    python cerberusscan.py [argument(s)] [url]
    
Arguments:
    -f, --fullscan       Perform a full scan (includes all tests)
    -sqli                Scan for SQL Injection vulnerabilities
    -crawler             Crawl the target website for links and pages
    -xss                 Scan for Cross-Site Scripting (XSS) vulnerabilities
    -dirbuster           Perform a directory brute-force attack
    -pathtraversal       Test for path traversal vulnerabilities
    -techscan            Identify technologies used by the target

Examples:
    python cerberusscan.py -f https://example.com
    python cerberusscan.py -sqli https://example.com
    python cerberusscan.py -xss -crawler https://example.com
"""

import sys
import argparse
import time
import threading
import io
import contextlib
import codecs
import os
from urllib.parse import urlparse
from datetime import datetime

import requests
import urllib3

#  disable SSL verification globally
orig_request = requests.Session.request
def patched_request(self, method, url, **kwargs):
    kwargs.setdefault('verify', False)
    kwargs.setdefault('timeout', 10)
    return orig_request(self, method, url, **kwargs)
requests.Session.request = patched_request
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Module imports
from modules.xss import scan_xss
from modules.crawler import spider
from modules.dirbuster import dirbuster_main
from modules.pathTraversal import main as pathtraversal_main
from modules.sqli import detect_login_form
from modules.techscan import main as techscan_main

# Global reporting system
REPORT = {}
SCAN_START_TIME = time.time()

# ANSI color definitions
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"

def banner():
    banner_text = r"""
 ▄▀▄▄▄▄   ▄▀▀█▄▄▄▄  ▄▀▀▄▀▀▀▄  ▄▀▀█▄▄   ▄▀▀█▄▄▄▄  ▄▀▀▄▀▀▀▄  ▄▀▀▄ ▄▀▀▄  ▄▀▀▀▀▄ 
█ █    ▌ ▐  ▄▀   ▐ █   █   █ ▐ ▄▀   █ ▐  ▄▀   ▐ █   █   █ █   █    █ █ █   ▐ 
▐ █        █▄▄▄▄▄  ▐  █▀▀█▀    █▄▄▄▀    █▄▄▄▄▄  ▐  █▀▀█▀  ▐  █    █     ▀▄   
  █        █    ▌   ▄▀    █    █   █    █    ▌   ▄▀    █    █    █   ▀▄   █  
 ▄▀▄▄▄▄▀  ▄▀▄▄▄▄   █     █    ▄▀▄▄▄▀   ▄▀▄▄▄▄   █     █      ▀▄▄▄▄▀   █▀▀▀   
█     ▐   █    ▐   ▐     ▐   █    ▐    █    ▐   ▐     ▐               ▐      
▐         ▐                  ▐         ▐
                             /\_/\____,
                  ,___/\_/\ \  ~     /
                  \     ~  \ )   XXX
                    XXX     /    /\_/\___,
                       \o-o/-o-o/   ~    /
                        ) /     \    XXX
                       _|    / \ \_/
                    ,-/   _  \_/   \
                   / (   /____,__|  )
                  (  |_ (    )  \) _|
                 _/ _)   \   \__/   (_
                (,-(,(,(,/      \,),),)
    """
    print(f"{RED}{banner_text}{RESET}")

def init_parser():
    parser = argparse.ArgumentParser(
        description="CerberusScan - Web Security Scanner",
        epilog="Example: python cerberusscan.py -f https://example.com")
    parser.add_argument('url', help="Target URL to scan")
    parser.add_argument('-f', '--fullscan', action='store_true', help="Perform a full scan (includes all tests)")
    parser.add_argument('--sqli', action='store_true', help="Only test for SQL injections")
    parser.add_argument('--crawler', action='store_true', help="Only run crawler")
    parser.add_argument('--dirbuster', action='store_true', help="Only run Directory Bruteforce")
    parser.add_argument('--xss', action='store_true', help="Only test for XSS vulnerabilities")
    parser.add_argument('--pathtraversal', action='store_true', help="Only test for Path Traversal")
    parser.add_argument('--techscan', action='store_true', help="Only perform Technology Stack analysis")
    parser.add_argument('--quiet', action='store_true', help="Reduce informational logging")
    return parser.parse_args()

def sanitize_output(text):
    if not text:
        return ""
    try:
        return str(text).encode('utf-8', errors='replace').decode('utf-8')
    except Exception:
        return str(text).encode('ascii', errors='replace').decode('ascii')

def generate_report(target_url):
    domain = urlparse(target_url).netloc
    filename = f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"CERBERUS SCAN REPORT - {domain}\n")
        f.write(f"Scan started: {datetime.fromtimestamp(SCAN_START_TIME)}\n")
        f.write("="*50 + "\n\n")
        for module, data in REPORT.items():
            f.write(f"=== {module.upper()} RESULTS ===\n")
            f.write(sanitize_output(data) + "\n\n")
    print(f"\n{GREEN}[+]{RESET} Full report saved to: {filename}")

def run_spider(target_url, quiet=False):
    if not quiet:
        print(f"\n{GREEN}[+]{RESET} Starting Spider...")
    session = requests.Session()
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning)
    spider_results = []
    def callback(url):
        spider_results.append(url)
        if not quiet:
            print(f"{YELLOW}  Found: {url}{RESET}")
    spider(session=session, url=target_url, max_depth=3,
           callback=callback, delay=0.5)
    REPORT['spider'] = "\n".join(spider_results)
    return spider_results

def run_dirbuster(target_url, quiet=False):
    if not quiet:
        print(f"\n{GREEN}[+]{RESET} Starting Directory Bruteforce...")
    thread = threading.Thread(target=dirbuster_main, args=(target_url,), daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            thread.join(timeout=0.5)
    except KeyboardInterrupt:
        print(f"\n{RED}[!]{RESET} Scan interrupted by user! Exiting dirbuster...")
        sys.exit(1)
    if not quiet:
        print(f"{GREEN}[+]{RESET} Directory Bruteforce scan completed.")
    try:
        with open("report.txt", 'r', encoding='utf-8') as f:
            content = f.read()
        REPORT['dirbuster'] = sanitize_output(content)
    except (FileNotFoundError, UnicodeDecodeError):
        REPORT['dirbuster'] = "Directory Bruteforce report file not found."

def run_techscan(target_url):
    print(f"\n{GREEN}[+]{RESET} Analyzing Technology Stack...")
    tech_info = sanitize_output(get_technologies(target_url))
    whois_info = sanitize_output(get_whois_info(target_url.split('//')[-1]))
    REPORT['techscan'] = f"Technologies:\n{tech_info}\n\nWHOIS:\n{whois_info}"

def main():
    banner()
    args = init_parser()
    target_url = args.url
    if args.fullscan or not any([args.sqli, args.crawler, args.xss, args.pathtraversal,
                                  args.dirbuster, args.techscan]):
        modules_to_run = {'sqli': True, 'crawler': True, 'xss': True,
                          'pathtraversal': True, 'dirbuster': True, 'techscan': True}
    else:
        modules_to_run = {
            'sqli': args.sqli,
            'crawler': args.crawler,
            'xss': args.xss,
            'pathtraversal': args.pathtraversal,
            'dirbuster': args.dirbuster,
            'techscan': args.techscan
        }
    try:
        spider_results = []
        if modules_to_run.get('crawler') or modules_to_run.get('sqli'):
            spider_results = run_spider(target_url, quiet=args.quiet)
        if modules_to_run.get('sqli'):
            if not args.quiet:
                print(f"\n{GREEN}[+]{RESET} Scanning discovered URLs for login forms (SQLi tests)...")
            sqli_buffer = io.StringIO()
            for url in spider_results:
                if not args.quiet:
                    print(f"{YELLOW}  Testing URL: {url}{RESET}")
                with contextlib.redirect_stdout(sqli_buffer):
                    detect_login_form(url)
            REPORT['sqli'] = sanitize_output(sqli_buffer.getvalue().strip()) or \
                             "SQLi tests executed on discovered URLs."
        if modules_to_run.get('xss'):
            if not args.quiet:
                print(f"\n{GREEN}[+]{RESET} Running XSS scan...")
            xss_buffer = io.StringIO()
            with contextlib.redirect_stdout(xss_buffer):
                scan_xss(target_url)
            REPORT['xss'] = sanitize_output(xss_buffer.getvalue().strip()) or \
                            "No XSS vulnerabilities found."
        if modules_to_run.get('pathtraversal'):
            if not args.quiet:
                print(f"\n{GREEN}[+]{RESET} Running Path Traversal scan...")
            pt_buffer = io.StringIO()
            if spider_results:
                for url in spider_results:
                    with contextlib.redirect_stdout(pt_buffer):
                        pathtraversal_main(url)
            else:
                with contextlib.redirect_stdout(pt_buffer):
                    pathtraversal_main(target_url)
            REPORT['pathtraversal'] = sanitize_output(pt_buffer.getvalue().strip()) or \
                                      "Path traversal scan did not return detailed output."
        
        if modules_to_run.get('dirbuster'):
            run_dirbuster(target_url, quiet=args.quiet)
        
        if modules_to_run.get('techscan'):
            if not args.quiet:
                print(f"\n{GREEN}[+]{RESET} Running Technology Stack analysis...")
            techscan_buffer = io.StringIO()
            with contextlib.redirect_stdout(techscan_buffer):
                techscan_main(target_url)
            REPORT['techscan'] = sanitize_output(techscan_buffer.getvalue().strip()) or \
                                 "Technology scan returned no output."
        generate_report(target_url)
    except KeyboardInterrupt:
        print(f"\n{RED}[!]{RESET} Scan interrupted by user!")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}[!]{RESET} Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()








