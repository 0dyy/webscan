# webscan

A lightweight, non-destructive web vulnerability scanner written in Python. It crawls a website, checks for common security flaws and produces a clean HTML report.

> ⚠️ **Only scan websites you own or have written permission to test.** The scanner refuses to run without the `--i-have-permission` flag.

📖 **Full manual:** [docs/MANUAL.md](docs/MANUAL.md) · 📄 **Sample report:** [docs/sample_report.html](docs/sample_report.html)

## Features

| Check | Severity |
|---|---|
| Reflected XSS: URL parameters and GET/POST forms, context-aware | High |
| Exposed `.git`, `.env`, SQL dumps and backups | High |
| Open redirects | Medium |
| Directory listing | Medium |
| Cookies missing HttpOnly / Secure / SameSite | Medium/Low |
| Missing CSP, HSTS, X-Frame-Options and other security headers | Medium/Low |
| Server and framework version disclosure | Low |

- **Safe XSS detection:** it injects a random marker plus `<x"'>` and checks whether the special characters come back unencoded. It finds the bug without running any real payload.
- **Soft-404 aware:** it measures a random missing page first, so custom error pages don't become false hits.
- **Polite by default:** a configurable delay between requests, and it stays on the target host.
- **Reports:** collapsible HTML findings with issue, fix and evidence, plus optional JSON for CI.

## Installation

```bash
git clone https://github.com/<your-username>/webscan.git
cd webscan
pip install -r requirements.txt
```

Requires Python 3.9+.

## Quick start

Try it safely against the bundled vulnerable practice app:

```bash
python vuln_testapp.py                                          # terminal 1 (127.0.0.1:5000)
python webscan.py http://127.0.0.1:5000 --i-have-permission     # terminal 2
```

Open `webscan_report.html`. You should see **14 findings**, including 4 High.

## Usage

```bash
# full scan of a site you own
python webscan.py https://yoursite.com --depth 3 --max-pages 100 \
       -o report.html --json findings.json --i-have-permission

# passive only (no input probing), gentle on production
python webscan.py https://yoursite.com --passive --i-have-permission

# authenticated scan
python webscan.py https://app.example.com --cookie "session=abc123" --i-have-permission
```

| Option | Default | Description |
|---|---|---|
| `--depth N` | 2 | Link levels to crawl |
| `--max-pages N` | 40 | Maximum pages to crawl |
| `--delay S` | 0.2 | Seconds between requests |
| `--timeout S` | 10 | Request timeout |
| `--passive` | off | Skip XSS and open redirect tests |
| `--cookie` | none | Cookie header for authenticated scans |
| `-H "Name: value"` | none | Extra header (repeatable) |
| `--insecure` | off | Skip TLS verification |
| `-o FILE` | `webscan_report.html` | HTML report path |
| `--json FILE` | none | Also write JSON findings |

## Limitations

webscan doesn't execute JavaScript and doesn't test SQL injection, stored or DOM XSS, CSRF or access-control bugs. Treat findings as leads to verify manually, and treat a clean report as "these checks passed", not "the site is secure".

## Roadmap

- [ ] Error-based SQL injection detection
- [ ] CSRF token checks
- [ ] Headless crawling (Playwright) for JavaScript-heavy sites
- [ ] PDF report export

## License

MIT. See [LICENSE](LICENSE). For authorised security testing and education only.

## Author

**Odo Oklo**, Computer and Communication Engineering, ATBU
