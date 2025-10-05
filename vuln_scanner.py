#!/usr/bin/env python3
"""
vuln_scanner.py
Non-destructive educational web-app scanner.
Usage: python vuln_scanner.py http://localhost:5000 --limit 5 --out report.json
"""

import sys
import time
import json
import argparse
from urllib.parse import urljoin, urlparse, parse_qs
import requests
from bs4 import BeautifulSoup

# ---------------------------
# CONFIG
# ---------------------------
HEADERS = {"User-Agent": "Codtech-VulnScanner/1.0 (+https://codtech.example)"}
REQUEST_TIMEOUT = 10
SLEEP_BETWEEN_REQUESTS = 0.6
MAX_PAGES = 50
VERBOSE = True

XSS_MARKER = "XSS_TEST_MARKER_12345"
SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "sqlstate",
    "mysql_fetch",
    "syntax error at or near"
]

# ---------------------------
# UTIL
# ---------------------------
def log(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def same_domain(base, url):
    try:
        return urlparse(base).netloc == urlparse(url).netloc
    except Exception:
        return False

# ---------------------------
# PARSING
# ---------------------------
def get_links(session, base_url, html):
    soup = BeautifulSoup(html, "lxml")
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("javascript:") or href.startswith("#"):
            continue
        full = urljoin(base_url, href)
        if same_domain(base_url, full):
            links.add(full.split("#")[0])
    return links

def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        f = {}
        f['action'] = urljoin(base_url, form.get('action') or "")
        f['method'] = (form.get('method') or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get('name')
            if not name:
                continue
            typ = inp.get('type', 'text')
            val = inp.get('value') or ""
            inputs.append({'name': name, 'type': typ, 'value': val})
        f['inputs'] = inputs
        forms.append(f)
    return forms

# ---------------------------
# TESTS
# ---------------------------
def check_reflected_xss(session, form, url):
    data = {}
    for i in form['inputs']:
        if i['type'] in ['text', 'search', 'email', 'textarea', 'url', 'tel', 'password']:
            data[i['name']] = XSS_MARKER
        else:
            data[i['name']] = i.get('value', '') or '1'
    try:
        if form['method'] == 'post':
            res = session.post(form['action'] or url, data=data, timeout=REQUEST_TIMEOUT)
        else:
            res = session.get(form['action'] or url, params=data, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        return {'ok': False, 'error': str(e)}
    return {'ok': True, 'reflected': (XSS_MARKER in res.text), 'status_code': res.status_code}

def check_sqli_indicators(session, target_url, params=None):
    findings = []
    base_params = params or {}
    for payload in SQLI_PAYLOADS:
        try:
            if base_params:
                # inject payload into each param individually
                for name in list(base_params.keys()):
                    test_params = base_params.copy()
                    test_params[name] = str(test_params[name]) + payload
                    r = session.get(target_url, params=test_params, timeout=REQUEST_TIMEOUT)
                    text = r.text.lower()
                    for sig in SQL_ERRORS:
                        if sig in text:
                            findings.append({'payload': payload, 'param': name, 'signature': sig, 'url': r.url, 'status': r.status_code})
            else:
                test_params = {'q_test': payload}
                r = session.get(target_url, params=test_params, timeout=REQUEST_TIMEOUT)
                text = r.text.lower()
                for sig in SQL_ERRORS:
                    if sig in text:
                        findings.append({'payload': payload, 'param': 'q_test', 'signature': sig, 'url': r.url, 'status': r.status_code})
        except Exception as e:
            findings.append({'payload': payload, 'error': str(e)})
    return findings

# ---------------------------
# SCANNER
# ---------------------------
def scan_target(start_url, max_pages=MAX_PAGES):
    session = requests.Session()
    session.headers.update(HEADERS)

    to_visit = [start_url]
    visited = set()
    results = {'target': start_url, 'pages_scanned': 0, 'forms': [], 'sqli_findings': [], 'xss_findings': []}

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        log(f"[+] Fetching: {url}")
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            log(f"    [!] Request failed: {e}")
            visited.add(url)
            time.sleep(SLEEP_BETWEEN_REQUESTS)
            continue

        visited.add(url)
        results['pages_scanned'] += 1
        html = r.text

        # links
        links = get_links(session, url, html)
        for l in links:
            if l not in visited and l not in to_visit:
                to_visit.append(l)

        # forms
        forms = extract_forms(html, url)
        for f in forms:
            f_rec = {'page': url, 'action': f['action'], 'method': f['method'], 'inputs': f['inputs']}
            xss_res = check_reflected_xss(session, f, url)
            f_rec['xss_check'] = xss_res
            if xss_res.get('ok') and xss_res.get('reflected'):
                log(f"    [!] Possible reflected XSS on form at {url} -> action {f['action']}")
                results['xss_findings'].append({'page': url, 'action': f['action'], 'method': f['method'], 'details': 'marker reflected in response'})
            sqli_res = check_sqli_indicators(session, f['action'] or url, params={i['name']: i.get('value', '') for i in f['inputs']})
            if sqli_res:
                log(f"    [!] SQLi-like signatures found on form action {f['action']}: {sqli_res}")
                results['sqli_findings'].extend([{'page': url, 'action': f['action'], 'e': e} for e in sqli_res])
            results['forms'].append(f_rec)

        # query params reflection/sqli checks
        parsed = urlparse(url)
        if parsed.query:
            params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
            if params:
                for p in params.keys():
                    test_params = params.copy()
                    test_params[p] = str(test_params[p]) + XSS_MARKER
                    try:
                        r2 = session.get(parsed._replace(query="").geturl(), params=test_params, timeout=REQUEST_TIMEOUT)
                        if XSS_MARKER in r2.text:
                            log(f"    [!] Possible reflected XSS via query param `{p}` on {url}")
                            results['xss_findings'].append({'page': url, 'param': p, 'details': 'marker reflected in response (query param)'})
                    except Exception as e:
                        log("    [!] Error testing query param reflection:", e)
                sqli_q = check_sqli_indicators(session, parsed._replace(query="").geturl(), params=params)
                if sqli_q:
                    log(f"    [!] SQLi-like signatures found in query params on {url}: {sqli_q}")
                    results['sqli_findings'].extend([{'page': url, 'param_test': p} for p in sqli_q])

        time.sleep(SLEEP_BETWEEN_REQUESTS)

    return results

# ---------------------------
# CLI
# ---------------------------
def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Simple Web App Vulnerability Scanner (educational only).")
    parser.add_argument("target", help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--limit", type=int, default=MAX_PAGES, help="Max pages to crawl")
    parser.add_argument("--nogui", action="store_true", help="Run quietly (minimal output)")
    parser.add_argument("--out", help="Save JSON report to file (default: report.json)")
    args = parser.parse_args()

    VERBOSE = not args.nogui
    limit = args.limit
    out_file = args.out or "report.json"

    if not args.target.startswith("http"):
        print("Please provide a full URL (include http:// or https://).")
        sys.exit(1)

    print("=== Codtech Vulnerability Scanner (educational use only) ===")
    print("Make sure you have explicit permission to test the target. Scanning without permission is illegal.")
    print()

    res = scan_target(args.target, max_pages=limit)

    # Always write a report file so you can inspect results (possibly empty)
    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print("Report saved to", out_file)
    except Exception as e:
        print("Failed to write report file:", e)

    # Print a short summary
    print("\n--- Scan summary ---")
    print("Target:", res.get('target'))
    print("Pages scanned:", res.get('pages_scanned'))
    print("Forms found:", len(res.get('forms', [])))
    print("Possible reflected XSS findings:", len(res.get('xss_findings', [])))
    print("Possible SQLi indicator findings:", len(res.get('sqli_findings', [])))

if __name__ == "__main__":
    main()
