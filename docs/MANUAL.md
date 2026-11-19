# webscan User Manual

Author: Odo Oklo · Last updated: November 2026

## Contents
1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Overview and quick start](#3-overview-and-quick-start)
4. [Option reference](#4-option-reference)
5. [The checks explained](#5-the-checks-explained)
6. [Reports, scenarios and limits](#6-reports-scenarios-and-limits)
7. [Troubleshooting and FAQ](#7-troubleshooting-and-faq)
8. [Example workflow and roadmap](#8-example-workflow-and-roadmap)

## 1. Introduction

This manual covers **webscan**, a command-line web vulnerability scanner written in Python. It crawls a website, runs passive and active security checks and writes an HTML report of what it finds.

The manual is for students, developers and junior security analysts. You should be comfortable with a terminal and understand basic HTTP (requests, headers, cookies).

### Legal notice

Only scan websites you own or have **written permission** to test. Scanning someone else's site without permission is illegal in most countries, including under Nigeria's Cybercrimes Act 2015. webscan will not start unless you add the `--i-have-permission` flag, which is your confirmation that you are authorised.

## 2. Installation

webscan needs Python 3.9 or newer and three pip packages. It runs on Linux, macOS and Windows.

1. Check your Python version: `python3 --version` (on Windows: `python --version`).
2. Clone the repo, or unzip it, and open a terminal in the project folder.
3. Optional but recommended: create a virtual environment with `python3 -m venv venv`, then activate it with `source venv/bin/activate` (Windows: `venv\Scripts\activate`).
4. Install the dependencies: `pip install -r requirements.txt`.
5. Check that it works: `python webscan.py --help` should print the option list.

### Folder layout

| Path | What it is |
| --- | --- |
| `README.md` | Project overview |
| `docs/MANUAL.md` | This manual |
| `docs/sample_report.html` | Example report from a scan of the practice app |
| `webscan.py` | The scanner |
| `vuln_testapp.py` | A deliberately vulnerable practice site (localhost only) |
| `requirements.txt` | Python dependencies |

`flask` is only needed for the practice site.

## 3. Overview and quick start

webscan crawls a site, then runs passive and active checks and writes an HTML report. It doesn't damage anything: it sends no exploits, deletes nothing and submits only harmless test strings.

### How a scan runs

1. **Crawl.** Starting at the URL you give, it follows links on the same host up to `--depth` levels and `--max-pages` pages. It records every page and every HTML form.
2. **Header and cookie check.** It requests the home page and inspects the security headers, version headers and `Set-Cookie` flags.
3. **Directory listing check.** It requests the parent folders of crawled pages, plus common folders such as `/uploads/` and `/static/`.
4. **Sensitive file check.** It requests about 20 known-dangerous paths, such as `/.git/HEAD` and `/.env`. It first measures a random missing page, so that "soft 404" pages aren't reported as hits.
5. **Reflected XSS test (active).** Each URL parameter and form field gets a random marker followed by `<x"'>`, and the response is checked for that string unencoded.
6. **Open redirect test (active).** Parameters named like `next`, `url` or `redirect` are pointed at a test domain to see whether the server redirects there.
7. **Report.** Findings are sorted by severity and written to HTML, and to JSON if you ask.

### Quick start (practice site)

Open two terminals in the project folder.

1. Terminal 1: `python vuln_testapp.py`. The practice site starts on `http://127.0.0.1:5000`.
2. Terminal 2: `python webscan.py http://127.0.0.1:5000 --i-have-permission`
3. Open `webscan_report.html` in a browser. You should see 14 findings, including 4 High: XSS in `q`, XSS in the `name` form field, `.git/HEAD` exposed and `.env` exposed.
4. Stop the practice site with Ctrl+C.

The practice site also has a `/safe` page and a `msg` field that encode their output correctly. webscan should *not* flag those, which shows it isn't producing false positives.

## 4. Option reference

Syntax: `python webscan.py <url> [options] --i-have-permission`

| Option | Default | What it does |
| --- | --- | --- |
| `url` (required) | none | Starting URL. `http://` is added if you leave out the scheme. |
| `--i-have-permission` | off | Required. Confirms you are authorised to test the target. |
| `--depth N` | 2 | How many link levels to follow from the start page |
| `--max-pages N` | 40 | Stop crawling after this many pages |
| `--delay S` | 0.2 | Seconds to wait between requests. Raise it for fragile or shared hosts. |
| `--timeout S` | 10 | Seconds before a request is given up |
| `--passive` | off | Skip the XSS and open redirect tests (headers, files and listings only) |
| `--cookie "..."` | none | Cookie header to send, for scanning pages behind a login |
| `-H "Name: value"` | none | Extra request header. Repeatable, e.g. `-H "Authorization: Bearer xyz"`. |
| `--insecure` | off | Don't verify TLS certificates (self-signed staging servers) |
| `-o FILE` | `webscan_report.html` | Where to write the HTML report |
| `--json FILE` | none | Also write findings as JSON |

A full scan with defaults makes roughly 60–200 requests, depending on how many pages and forms the site has.

## 5. The checks explained

Every finding is a lead, not proof. Confirm each one by hand before you report it or count it as fixed.

| Finding | Severity | How to confirm by hand | How to fix |
| --- | --- | --- | --- |
| Reflected XSS in parameter / form field | High | In Burp or the browser, send `<img src=x onerror=alert(1)>` to the same field and see whether it runs | Encode output for its context (HTML, attribute, JS), and add a strict Content-Security-Policy |
| Sensitive file exposed (`.git`, `.env`, `.sql`, backups) | High | Open the URL in a browser. For `.git`, try `git-dumper` on a lab copy only. | Delete the file from the web root, or deny dotfiles in the server config |
| Open redirect | Medium | Visit the evidence URL and check you land on the test domain | Allow only relative paths or an allow-list of hosts |
| Directory listing enabled | Medium | Open the folder URL and look for an "Index of" page | nginx: `autoindex off;` Apache: `Options -Indexes` |
| Cookie missing HttpOnly | Medium | DevTools → Application → Cookies, then check the HttpOnly column | Set `HttpOnly; Secure; SameSite=Lax` on session cookies |
| Missing Content-Security-Policy / HSTS | Medium | DevTools → Network → response headers | Add the header in the server or app config |
| Cookie missing Secure / SameSite | Low | As for HttpOnly | As above |
| Missing X-Frame-Options, X-Content-Type-Options, Referrer-Policy | Low | Response headers | Add the header |
| CSP allows `unsafe-inline` | Low | Read the CSP value in the evidence | Use nonces or hashes for inline scripts |
| Version disclosure (`Server`, `X-Powered-By`) | Low | Response headers show exact versions | nginx: `server_tokens off;` PHP: `expose_php = Off`. Express: `app.disable('x-powered-by')` |
| Missing Permissions-Policy | Info | Response headers | Add a policy that disables unused features |

### How the XSS test avoids false positives

The probe is a unique marker such as `wsxk3j9a1bc` followed by `<x"'>`. If the marker comes back but the symbols are encoded (`&lt;x&quot;`), the page is safe and nothing is reported. If `<`, `"` or `'` come back raw, the report names which context is exposed. HSTS is only checked on `https://` targets, and X-Frame-Options isn't reported if the CSP already has `frame-ancestors`.

## 6. Reports, scenarios and limits

### Reading the HTML report

The header shows the target, the date, and how many pages, forms and requests the scan covered and how long it took. Coloured chips count findings by severity. Each finding is a collapsible card: click it to see **Issue**, **Fix** and **Evidence** (the exact URL, payload or header value). Fix High findings first.

### JSON output

`--json findings.json` writes `{"target": ..., "findings": [...]}`. Each finding has `severity`, `title`, `url`, `detail`, `fix` and `evidence`. Use it to compare scans before and after a fix, or to feed a CI pipeline.

### Common scenarios

- **Your own live site, first look:** `--passive` first. It only reads pages, so it's gentle on production.
- **Full test on staging:** `--depth 3 --max-pages 150 --insecure` if the certificate is self-signed.
- **Pages behind a login:** log in with your browser, copy the session cookie from DevTools and pass `--cookie "session=..."`. Avoid crawling a logout link, or the session will end mid-scan.
- **Slow or shared hosting:** `--delay 1` to stay polite and avoid rate-limit bans.
- **Retest after fixing:** run the same command with `--json after.json` and compare it with the earlier JSON.

### Limitations

- It doesn't run JavaScript, so links and forms built by React/Vue at runtime are missed. Use Burp's crawler for single-page apps.
- It doesn't test SQL injection, stored XSS, DOM XSS, CSRF, IDOR or business logic. Those still need manual testing.
- Only forms with `name` attributes are tested. Hidden, file and checkbox fields are skipped.
- It stays on the exact host you give, so `www.site.com` and `site.com` are separate scans.
- A clean report doesn't mean the site is secure. It means these specific checks passed.

## 7. Troubleshooting and FAQ

| Problem | Cause | Fix |
| --- | --- | --- |
| `Refusing to scan: add --i-have-permission` | The safety flag is missing | Add `--i-have-permission`, but only if you are authorised |
| `ModuleNotFoundError: requests` / `bs4` / `flask` | Dependencies not installed in the active Python | `pip install -r requirements.txt`, inside your venv if you use one |
| `ImportError: cannot import name 'escape' from 'flask'` | Old copy of the practice site on Flask 3 | Use the shipped `vuln_testapp.py`, which imports `escape` from `markupsafe` |
| `SSLError` / certificate verify failed | Self-signed or expired certificate | Add `--insecure` (staging only) |
| webscan crawls only 1 page | The site builds links with JavaScript, or redirects to another host such as `www.` | Scan the final host directly, or seed deeper URLs as the start URL |
| many `[!] ... failed: ConnectTimeout` | Firewall, WAF or rate limit blocking you | Raise `--delay` and `--timeout`. Check that your IP isn't banned. |
| webscan reports 0 XSS on a site you know is vulnerable | The bug is stored or DOM-based, or behind a login | Use `--cookie`, then test manually in Burp |

**Can webscan harm a site?** It's designed to be non-destructive, but active tests submit forms. On a live contact form that can send a few test emails. Use `--passive` on production and full scans on staging.

**Can I use webscan for bug bounties?** Only within each programme's scope and rules. Many programmes ban automated scanners or cap request rates, so read the policy and set `--delay` to match.

## 8. Example workflow and roadmap

### Securing a site you run, end to end

1. **Baseline:** `python webscan.py https://yoursite.com --passive --json before.json -o before.html --i-have-permission`
2. **Full scan on staging:** the same command without `--passive`, pointed at your staging copy.
3. **Fix:** work through High, then Medium findings using the fix column in section 5.
4. **Retest:** scan again with `--json after.json -o after.html` and confirm every fixed finding has gone.
5. **Document:** keep `before.html` and `after.html` as evidence. Before-and-after reports make a strong portfolio case study.

### Roadmap

- [ ] Error-based SQL injection detection (database error strings after a `'` probe)
- [ ] CSRF check that flags POST forms with no token field
- [ ] Headless-browser crawling with Playwright for JavaScript sites
- [ ] PDF export of the report with ReportLab
- [ ] GitHub Actions workflow that runs webscan on every deploy
