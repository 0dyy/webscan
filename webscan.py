#!/usr/bin/env python3
"""
webscan - a lightweight, non-destructive web vulnerability scanner.

Checks:
  * Missing / weak security headers (CSP, HSTS, X-Frame-Options, ...)
  * Insecure cookie flags (Secure, HttpOnly, SameSite)
  * Server / framework version disclosure
  * Directory listing
  * Exposed sensitive files (.git, .env, backups, ...)
  * Reflected XSS in URL parameters and forms (marker-based, no exploitation)
  * Open redirects in redirect-style parameters

ONLY scan systems you own or have written permission to test.

Usage:
  python webscan.py http://localhost:5000 --i-have-permission
  python webscan.py https://example.com --depth 2 --max-pages 50 -o report.html --i-have-permission
"""

import argparse
import html
import json
import random
import string
import sys
import time
from collections import deque
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()  # noqa  (only matters with --insecure)

UA = "webscan/1.0 (+authorized security testing)"

SECURITY_HEADERS = {
    "Content-Security-Policy": ("Medium", "Mitigates XSS and data injection."),
    "Strict-Transport-Security": ("Medium", "Forces HTTPS; prevents SSL stripping."),
    "X-Frame-Options": ("Low", "Prevents clickjacking (or use CSP frame-ancestors)."),
    "X-Content-Type-Options": ("Low", "Should be 'nosniff' to stop MIME sniffing."),
    "Referrer-Policy": ("Low", "Limits leakage of URLs in the Referer header."),
    "Permissions-Policy": ("Info", "Restricts powerful browser features."),
}

DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".env", ".env.local", ".DS_Store",
    "backup.zip", "backup.tar.gz", "db.sql", "database.sql", "dump.sql",
    "config.php.bak", "wp-config.php.bak", ".htpasswd", "phpinfo.php",
    "server-status", ".svn/entries", "composer.lock", "package.json",
]

# signature that must appear in the body to count as a real hit (avoids soft-404s)
SENSITIVE_SIGNATURES = {
    ".git/HEAD": "ref:",
    ".git/config": "[core]",
    ".env": "=",
    ".env.local": "=",
    ".htpasswd": ":",
    "phpinfo.php": "phpinfo",
    "server-status": "Apache Server Status",
    "composer.lock": '"packages"',
    "package.json": '"name"',
    "db.sql": "CREATE TABLE",
    "database.sql": "CREATE TABLE",
    "dump.sql": "CREATE TABLE",
}

REDIRECT_PARAMS = {"url", "next", "redirect", "redirect_uri", "redirect_url", "return",
                   "returnto", "return_to", "returnurl", "goto", "dest", "destination",
                   "continue", "target", "r", "u", "link", "forward"}

REDIRECT_PAYLOAD = "https://webscan-redirect-test.example.org/"

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


class Scanner:
    def __init__(self, base_url, depth=2, max_pages=40, delay=0.2, timeout=10,
                 verify_tls=True, cookies=None, headers=None):
        self.base = base_url.rstrip("/") + "/"
        self.host = urlparse(self.base).netloc
        self.depth = depth
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.s.verify = verify_tls
        if cookies:
            self.s.headers["Cookie"] = cookies
        for h in headers or []:
            k, _, v = h.partition(":")
            self.s.headers[k.strip()] = v.strip()
        self.findings = []
        self._seen_findings = set()
        self.pages = []          # crawled URLs
        self.forms = []          # (page_url, form dict)
        self.requests_made = 0

    # ------------------------------------------------------------------ utils
    def req(self, method, url, **kw):
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        time.sleep(self.delay)
        self.requests_made += 1
        try:
            return self.s.request(method, url, **kw)
        except requests.RequestException as e:
            print(f"  [!] {method} {url} failed: {e.__class__.__name__}", file=sys.stderr)
            return None

    def add(self, severity, title, url, detail, fix, evidence=""):
        key = (title, url.split("?")[0], detail)
        if key in self._seen_findings:
            return
        self._seen_findings.add(key)
        self.findings.append(dict(severity=severity, title=title, url=url,
                                  detail=detail, fix=fix, evidence=evidence[:300]))
        print(f"  [{severity:<6}] {title} -> {url}")

    def in_scope(self, url):
        p = urlparse(url)
        return p.scheme in ("http", "https") and p.netloc == self.host

    @staticmethod
    def marker():
        return "wsx" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    # ------------------------------------------------------------------ crawl
    def crawl(self):
        print(f"[*] Crawling {self.base} (depth={self.depth}, max={self.max_pages})")
        q = deque([(self.base, 0)])
        seen = {self.base}
        while q and len(self.pages) < self.max_pages:
            url, d = q.popleft()
            r = self.req("GET", url)
            if r is None:
                continue
            self.pages.append(url)
            if "text/html" not in r.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                self.forms.append((url, self.parse_form(url, form)))
            if d >= self.depth:
                continue
            for a in soup.find_all("a", href=True):
                nxt = urljoin(url, a["href"]).split("#")[0]
                if self.in_scope(nxt) and nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, d + 1))
        print(f"[*] Crawled {len(self.pages)} page(s), found {len(self.forms)} form(s)")

    @staticmethod
    def parse_form(page_url, form):
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "get").lower()
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            fields[name] = {"type": itype, "value": inp.get("value", "")}
        return {"action": action, "method": method, "fields": fields}

    # ------------------------------------------------------------ passive checks
    def check_headers(self):
        print("[*] Checking security headers and cookies")
        r = self.req("GET", self.base)
        if r is None:
            return
        hdrs = r.headers
        for name, (sev, why) in SECURITY_HEADERS.items():
            if name == "Strict-Transport-Security" and not self.base.startswith("https"):
                continue
            if name not in hdrs:
                if name == "X-Frame-Options" and "frame-ancestors" in hdrs.get("Content-Security-Policy", ""):
                    continue
                self.add(sev, f"Missing {name} header", self.base, why,
                         f"Add the {name} response header.")
        if hdrs.get("X-Content-Type-Options", "").lower() not in ("", "nosniff"):
            self.add("Low", "Weak X-Content-Type-Options", self.base,
                     "Value is not 'nosniff'.", "Set X-Content-Type-Options: nosniff.")
        csp = hdrs.get("Content-Security-Policy", "")
        if "'unsafe-inline'" in csp and "script-src" in csp:
            self.add("Low", "CSP allows unsafe-inline scripts", self.base,
                     "'unsafe-inline' in script-src weakens XSS protection.",
                     "Use nonces or hashes instead of 'unsafe-inline'.", csp)
        for h in DISCLOSURE_HEADERS:
            if h in hdrs and any(c.isdigit() for c in hdrs[h]):
                self.add("Low", f"Version disclosure via {h}", self.base,
                         "Exact software versions help attackers find known CVEs.",
                         f"Remove or genericise the {h} header.", f"{h}: {hdrs[h]}")
        # cookies (raw headers so we can see the flags)
        raw = r.raw.headers.get_all("Set-Cookie") if hasattr(r.raw.headers, "get_all") else []
        for c in raw or []:
            name = c.split("=", 1)[0].strip()
            low = c.lower()
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if self.base.startswith("https") and "secure" not in low:
                missing.append("Secure")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                self.add("Low" if "HttpOnly" not in missing else "Medium",
                         f"Cookie '{name}' missing {', '.join(missing)}", self.base,
                         "Cookie flags protect sessions from theft via XSS / CSRF / sniffing.",
                         "Set HttpOnly, Secure and SameSite=Lax (or Strict) on session cookies.", c)

    def check_dir_listing(self):
        print("[*] Checking for directory listing")
        dirs = {self.base}
        for p in self.pages:
            path = urlparse(p).path
            if "/" in path.strip("/"):
                parent = path.rsplit("/", 1)[0] + "/"
                dirs.add(urljoin(self.base, parent))
        for common in ("uploads/", "static/", "images/", "files/", "backup/", "assets/"):
            dirs.add(urljoin(self.base, common))
        for d in dirs:
            r = self.req("GET", d)
            if r is not None and r.status_code == 200 and (
                    "Index of /" in r.text or "Directory listing for" in r.text
                    or "<title>Directory listing" in r.text):
                self.add("Medium", "Directory listing enabled", d,
                         "Visitors can browse every file in this folder.",
                         "Disable autoindex (nginx: autoindex off; Apache: Options -Indexes).")

    def check_sensitive_files(self):
        print("[*] Checking for exposed sensitive files")
        # baseline for soft-404 detection
        junk = self.req("GET", urljoin(self.base, self.marker() + ".txt"))
        junk_len = len(junk.text) if junk is not None else -1
        for path in SENSITIVE_PATHS:
            url = urljoin(self.base, path)
            r = self.req("GET", url, allow_redirects=False)
            if r is None or r.status_code != 200 or not r.content:
                continue
            if junk is not None and junk.status_code == 200 and abs(len(r.text) - junk_len) < 20:
                continue  # soft 404
            sig = SENSITIVE_SIGNATURES.get(path)
            if sig and sig not in r.text:
                continue
            sev = "High" if path.startswith((".git", ".env", ".htpasswd")) or path.endswith(
                (".sql", ".zip", ".gz", ".bak")) else "Medium"
            self.add(sev, f"Sensitive file exposed: /{path}", url,
                     "This file can leak source code, credentials or internal details.",
                     "Remove it from the web root or deny access in the server config.",
                     r.text[:120])

    # ------------------------------------------------------------- active checks
    def check_reflected_xss(self):
        print("[*] Testing parameters and forms for reflected XSS")
        # 1) URL query parameters on crawled pages
        for url in self.pages:
            p = urlparse(url)
            params = parse_qs(p.query, keep_blank_values=True)
            for name in params:
                self._xss_param(url, name, params)
        # 2) forms
        for page, form in self.forms:
            for name, meta in form["fields"].items():
                if meta["type"] in ("submit", "button", "file", "image", "hidden", "checkbox", "radio"):
                    continue
                self._xss_form(page, form, name)

    def _payload(self):
        m = self.marker()
        return m, f"{m}<x\"'>"   # if <, " or ' come back raw, encoding is missing

    def _analyse_reflection(self, body, m):
        if m not in body:
            return None
        for probe, ctx in ((f"{m}<x\"'>", "raw HTML (< \" ' unencoded)"),
                           (f"{m}<x", "HTML tag context (< unencoded)"),
                           (f"{m}<x\"", "attribute context (\" unencoded)"),
                           (f"{m}<x\"'", "script/attribute context (' unencoded)")):
            if probe in body:
                return ctx
        return "encoded"

    def _xss_param(self, url, name, params):
        m, payload = self._payload()
        p = urlparse(url)
        new = {k: v[0] if v else "" for k, v in params.items()}
        new[name] = payload
        test = urlunparse(p._replace(query=urlencode(new)))
        r = self.req("GET", test)
        if r is None:
            return
        ctx = self._analyse_reflection(r.text, m)
        if ctx and ctx != "encoded":
            self.add("High", f"Reflected XSS in parameter '{name}'", url,
                     f"Input is reflected without encoding: {ctx}.",
                     "HTML-encode output for its context and add a strict CSP.",
                     test)

    def _xss_form(self, page, form, target):
        m, payload = self._payload()
        data = {}
        for n, meta in form["fields"].items():
            if n == target:
                data[n] = payload
            elif meta["type"] == "email":
                data[n] = "test@example.com"
            elif meta["type"] == "number":
                data[n] = "1"
            else:
                data[n] = meta["value"] or "test"
        if form["method"] == "post":
            r = self.req("POST", form["action"], data=data)
        else:
            r = self.req("GET", form["action"], params=data)
        if r is None:
            return
        ctx = self._analyse_reflection(r.text, m)
        if ctx and ctx != "encoded":
            self.add("High", f"Reflected XSS in form field '{target}'", form["action"],
                     f"{form['method'].upper()} input reflected without encoding: {ctx} "
                     f"(form on {page}).",
                     "HTML-encode output for its context and add a strict CSP.",
                     json.dumps(data))

    def check_open_redirect(self):
        print("[*] Testing redirect parameters for open redirects")
        candidates = set()
        for url in self.pages:
            p = urlparse(url)
            for name in parse_qs(p.query, keep_blank_values=True):
                if name.lower() in REDIRECT_PARAMS:
                    candidates.add((url, name))
        for _, form in self.forms:
            if form["method"] == "get":
                for name in form["fields"]:
                    if name.lower() in REDIRECT_PARAMS:
                        candidates.add((form["action"], name))
        # also probe a few common endpoints
        for path in ("login", "logout", "redirect", "out", "go"):
            for name in ("next", "url", "redirect"):
                candidates.add((urljoin(self.base, path), name))

        for url, name in candidates:
            p = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(p.query, keep_blank_values=True).items()}
            params[name] = REDIRECT_PAYLOAD
            test = urlunparse(p._replace(query=urlencode(params)))
            r = self.req("GET", test, allow_redirects=False)
            if r is None:
                continue
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and \
                    urlparse(loc).netloc == urlparse(REDIRECT_PAYLOAD).netloc:
                self.add("Medium", f"Open redirect via '{name}'", url,
                         "Attackers can use your domain to send users to phishing sites.",
                         "Only allow relative paths or an allow-list of destinations.",
                         f"{test} -> {loc}")

    # ------------------------------------------------------------------ run
    def run(self, active=True):
        start = time.time()
        self.crawl()
        self.check_headers()
        self.check_dir_listing()
        self.check_sensitive_files()
        if active:
            self.check_reflected_xss()
            self.check_open_redirect()
        self.findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
        self.duration = time.time() - start
        return self.findings


# ---------------------------------------------------------------- reporting
def html_report(sc, path):
    counts = {s: sum(1 for f in sc.findings if f["severity"] == s) for s in SEVERITY_ORDER}
    colors = {"High": "#c0392b", "Medium": "#d68910", "Low": "#2e86c1", "Info": "#7f8c8d"}
    rows = []
    for i, f in enumerate(sc.findings, 1):
        rows.append(f"""
        <details class="f">
          <summary><span class="sev" style="background:{colors[f['severity']]}">{f['severity']}</span>
          <b>{html.escape(f['title'])}</b> <span class="u">{html.escape(f['url'])}</span></summary>
          <p><b>Issue:</b> {html.escape(f['detail'])}</p>
          <p><b>Fix:</b> {html.escape(f['fix'])}</p>
          {f"<pre>{html.escape(f['evidence'])}</pre>" if f['evidence'] else ""}
        </details>""")
    chips = "".join(f'<span class="chip" style="border-color:{colors[s]};color:{colors[s]}">'
                    f'{s}: {n}</span>' for s, n in counts.items())
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>webscan report - {html.escape(sc.host)}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}}
h1{{margin-bottom:.2rem}} .meta{{color:#666;font-size:.9rem}}
.chip{{display:inline-block;border:2px solid;border-radius:20px;padding:.2rem .8rem;margin:.6rem .4rem 1rem 0;font-weight:600}}
.f{{border:1px solid #ddd;border-radius:8px;padding:.6rem .9rem;margin:.5rem 0}}
.f summary{{cursor:pointer}} .sev{{color:#fff;border-radius:4px;padding:.1rem .45rem;font-size:.8rem;margin-right:.4rem}}
.u{{color:#666;font-size:.85rem;word-break:break-all}}
pre{{background:#f5f5f5;padding:.6rem;border-radius:6px;white-space:pre-wrap;word-break:break-all}}
</style></head><body>
<h1>webscan report</h1>
<div class="meta">Target: {html.escape(sc.base)} &middot; {datetime.now():%Y-%m-%d %H:%M} &middot;
{len(sc.pages)} pages, {len(sc.forms)} forms, {sc.requests_made} requests, {sc.duration:.1f}s</div>
{chips}
{''.join(rows) or '<p>No findings. 🎉</p>'}
<p class="meta">Automated results - verify each finding manually before reporting.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def main():
    ap = argparse.ArgumentParser(description="Lightweight web vulnerability scanner")
    ap.add_argument("url", help="Base URL, e.g. https://example.com")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="Confirm you own the target or are authorised to test it")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--delay", type=float, default=0.2, help="Seconds between requests")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--passive", action="store_true", help="Skip XSS / redirect probing")
    ap.add_argument("--cookie", help="Cookie header for authenticated scans")
    ap.add_argument("-H", "--header", action="append", help="Extra header 'Name: value'")
    ap.add_argument("--insecure", action="store_true", help="Don't verify TLS certificates")
    ap.add_argument("-o", "--output", default="webscan_report.html")
    ap.add_argument("--json", help="Also write findings as JSON to this path")
    a = ap.parse_args()

    if not a.i_have_permission:
        sys.exit("Refusing to scan: add --i-have-permission to confirm you own or are "
                 "authorised to test this target.")
    if not a.url.startswith(("http://", "https://")):
        a.url = "http://" + a.url

    sc = Scanner(a.url, a.depth, a.max_pages, a.delay, a.timeout,
                 verify_tls=not a.insecure, cookies=a.cookie, headers=a.header)
    sc.run(active=not a.passive)
    html_report(sc, a.output)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"target": sc.base, "findings": sc.findings}, fh, indent=2)
    print(f"\n[+] {len(sc.findings)} finding(s). Report: {a.output}")


if __name__ == "__main__":
    main()
