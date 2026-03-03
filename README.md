# Blaze v2.1 — Smart Directory Bruteforce Engine

```
    ██████╗ ██╗      █████╗ ███████╗███████╗
    ██╔══██╗██║     ██╔══██╗╚══███╔╝██╔════╝
    ██████╔╝██║     ███████║  ███╔╝ █████╗
    ██╔══██╗██║     ██╔══██║ ███╔╝  ██╔══╝
    ██████╔╝███████╗██║  ██║███████╗███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
```

**Built by assassin_marcos**

A next-generation directory bruteforce tool that outsmarts gobuster, ffuf, dirsearch, and feroxbuster. Blaze combines intelligent detection, real-time adaptation, and blazing-fast async I/O to discover hidden paths, files, and endpoints on web servers.

---

## Features

### Core Engine
- **Async I/O** — Built on `aiohttp` with full asyncio for maximum throughput
- **Adaptive Threading** — Auto-adjusts concurrency based on server response times, error rates, CPU cores, and bandwidth estimation
- **Dynamic Semaphore** — Real-time thread scaling (up and down) without restart
- **Adaptive Rate Limiting** — Automatically backs off on 429s and server errors
- **Rate Limit Fingerprinting** — Reads `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` headers to intelligently pace requests

### Intelligence
- **WAF Detection** — 22+ WAF signatures (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, ModSecurity, F5 BIG-IP, Barracuda, Wordfence, Fortinet, Citrix, etc.) with auto-stop and confidence scoring
- **Technology Fingerprinting** — 80+ probe paths, detects PHP, WordPress, Joomla, Drupal, ASP.NET, Java/JSP, Node.js, Python/Django/Flask, Ruby on Rails, Spring, Tomcat, Nginx, Apache, IIS, Magento, TYPO3, Umbraco, Moodle, SharePoint, AEM, Confluence, Jenkins, GitLab, Elasticsearch, SAP, Docker/Kubernetes, GraphQL, Swagger/OpenAPI
- **Smart Wordlist Selection** — Auto-selects from 36 wordlists based on detected technology stack (37 tech mappings)
- **Real-Time Tech Detection** — Detects new technologies from scan results as they come in
- **Subdomain-Aware Scanning** — Automatically selects additional wordlists based on subdomain patterns (e.g., `api.target.com` → api.txt + swagger.txt)
- **Response Header Leak Detection** — Flags leaked internal IPs, debug tokens, server versions, backend names, and 37+ sensitive headers with severity scoring
- **Custom Signature Packs** — Drop `.json` files in `signatures/` to extend WAF, technology, and wordlist detection

### Filtering & Detection
- **Wildcard Detection** — Calibrates against random paths to detect wildcard responses
- **Real-Time Adaptive Filter** — Learns wildcard patterns LIVE during scanning by tracking (status, size), (status, lines), (status, hash) tuples. Auto-filters when a pattern repeats N times
- **Soft-404 Detection** — Response diffing with `SequenceMatcher` + dynamic content stripping (CSRF tokens, timestamps, UUIDs, Base64)
- **Wildcard 401/403 Detection** — Detects authentication gateways and internal firewalls that block all paths
- **Smart Status Filtering** — 200/201/204/301/302/307/308 shown, 404 hidden, 403 hidden unless `--show-forbidden`, 401 shown only if not wildcard, 500 shown (reveals stack traces)

### Smart Recursion
- **Context-Aware** — Maps 40+ directory name patterns to appropriate wordlists (e.g., `/api` → api.txt, `/wp-admin` → wordpress.txt, `/backup` → backup.txt, `/umbraco` → umbraco.txt)
- **Multi-Wordlist Per Directory** — Each recursive level gets context-appropriate wordlists
- **Suspicious Directory Detection** — Flags directories like `backup`, `old`, `dev`, `staging`

### Discovery
- **HTML Link Crawling** — Extracts `href`, `src`, `action` attributes from discovered HTML pages and queues them for scanning
- **JavaScript Endpoint Extraction** — 12 regex patterns with scoring system, extracts fetch(), axios, route definitions from JS files
- **Smart Extension Probing** — Auto-probes `.bak`, `.old`, `.zip`, `.tar.gz`, `.sql` variants of discovered files, plus 25+ filename permutation patterns (`.config.php.swp`, `config_backup.php`, `config.bak.php`, `#config.php#`, etc.)
- **Directory Archive Probing** — Checks `backup.zip`, `backup.tar.gz`, etc. for discovered directories
- **Scope-Aware Crawling** — Discovers related subdomains from HTML links while staying within the target's base domain
- **Parameter Fuzzing** — 101 built-in parameter names, 9 test values, reflection detection, 30 interesting-response patterns

### Advanced Modes
- **VHOST Discovery** — Host header fuzzing against target IP with baseline comparison
- **Pattern Generation** — Supports `{FUZZ}`, `{EXT}`, `{YEAR}`, `{MONTH}`, `{DAY}`, `{DATE}`, `{NUM:start-end}` with Cartesian product expansion
- **Headless Browser** — Playwright integration for JS challenge bypass with stealth mode
- **Resume Support** — Atomic state saving, resume interrupted scans exactly where you left off

### Output
- **Clean Terminal UI** — Visually appealing output with colored status codes, live adaptive progress bar, and no clutter
- **Full URLs** — Shows complete URLs with status codes, sizes, and response times
- **Adaptive Notifications** — Real-time display of thread adjustments and filter activations
- **Export** — JSON, CSV, TXT output formats

---

## Installation

### Quick Install (pip)

```bash
pip3 install . --break-system-packages
```

Or with fast extras (uvloop):

```bash
pip3 install ".[fast]" --break-system-packages
```

### Installer Script (Cross-Platform)

Works on Linux, macOS, Windows (Git Bash / MSYS2 / WSL):

```bash
chmod +x install.sh
./install.sh
```

### Standalone Binary

```bash
python3 build.py
```

Creates a single-file executable in `dist/` — no Python required on the target machine.

### From Source

```bash
git clone https://github.com/assassin-marcos/blaze.git
cd blaze
pip3 install -e ".[all]" --break-system-packages
```

---

## Usage

### Basic Scan

```bash
blaze -u https://target.com
```

### Recursive Smart Scan

```bash
blaze -u https://target.com -r --depth 5
```

### Custom Threads & Extensions

```bash
blaze -u https://target.com -t 200 -e php,html,txt,bak
```

### With Proxy (Burp Suite)

```bash
blaze -u https://target.com --proxy http://127.0.0.1:8080
```

### Custom Wordlist

```bash
blaze -u https://target.com -w /path/to/wordlist.txt
```

### Show 403 Responses

```bash
blaze -u https://target.com --show-forbidden
```

### Resume Interrupted Scan

```bash
blaze -u https://target.com --resume
```

### VHOST Discovery

```bash
blaze -u https://10.10.10.1 --vhost --vhost-wordlist hostnames.txt
```

### Parameter Fuzzing

```bash
blaze -u https://target.com --discover-params
```

### Pattern Generation

```bash
blaze -u https://target.com -p "backup-{DATE}.{EXT}"
```

### Headless Browser (JS Challenge Bypass)

```bash
pip install playwright && playwright install
blaze -u https://target.com --headless
```

### Export Results

```bash
blaze -u https://target.com -o results.json --format json
blaze -u https://target.com -o results.csv --format csv
```

### Force Past WAF

```bash
blaze -u https://target.com --force
```

### Skip WAF Check

```bash
blaze -u https://target.com --no-waf-check
```

---

## All Options

```
Target:
  -u, --url              Target URL

Wordlists:
  -w, --wordlist         Wordlist file(s) (can specify multiple)
  --always-lists         Wordlists to always include
  --setup-lists          Interactive setup for always-run wordlists
  --list-wordlists       List all available built-in wordlists
  --merge-dicts          Merge user dictionaries into Blaze wordlists
  --source-dir           Source directory for --merge-dicts

Scan Options:
  -t, --threads          Concurrent threads (0 = auto-detect)
  --timeout              Request timeout in seconds (default: 10)
  -r, --recursive        Enable smart recursive scanning
  --depth                Max recursion depth (default: 3)
  -e, --extensions       File extensions (comma-separated)
  --delay                Delay between requests in seconds
  --smart / --no-smart   Toggle smart mode (default: on)

Smart Features:
  --show-forbidden       Show 403 Forbidden responses
  --no-js-extract        Skip JavaScript endpoint extraction
  --no-ext-probe         Skip smart backup extension probing
  --diff-threshold       Soft-404 similarity threshold (default: 0.85)
  --resume               Resume an interrupted scan
  --clear-state          Clear saved scan state

Advanced Modes:
  --vhost                Enable VHOST discovery
  --vhost-wordlist       Hostname wordlist for VHOST mode
  --discover-params      Parameter discovery on found pages
  -p, --pattern          Pattern generation
  --headless             Headless browser JS challenge bypass

Request Options:
  --user-agent           Custom User-Agent
  --random-agent         Random User-Agent per request
  -H, --header           Custom header(s)
  -c, --cookie           Cookies
  --proxy                Proxy URL
  -L, --follow-redirects Follow HTTP redirects
  --ignore-ssl           Ignore SSL errors (default: on)

Filters:
  -s, --include-status   Only show these status codes
  -x, --exclude-status   Exclude status codes (default: 404)
  --min-size / --max-size
  --min-words / --max-words

WAF Options:
  --no-waf-check         Skip WAF detection
  --force                Continue even if WAF detected

Output:
  -o, --output           Output file path
  --format               Output format (txt/json/csv)
  -q, --quiet            Quiet mode
  -v, --verbose          Verbose output
  --no-color             Disable colored output
```

---

## Wordlists

Blaze ships with **117,000+ curated entries** across 36 technology-specific wordlists — every single path is a legitimate, hand-verified web endpoint (zero garbage, zero XSS payloads, zero scraped URLs):

| Wordlist | Entries | Description |
|----------|---------|-------------|
| php.txt | 86,272 | PHP applications & frameworks |
| api.txt | 13,233 | REST / SOAP / API endpoints |
| backup.txt | 4,188 | Backup files, archives, dumps |
| drupal.txt | 2,056 | Drupal CMS |
| joomla.txt | 1,233 | Joomla CMS |
| common.txt | 916 | Universal paths, admin, config, sensitive |
| spring.txt | 611 | Spring Boot / Java EE / Struts |
| wordpress.txt | 516 | WordPress admin, plugins, themes, REST API |
| nodejs.txt | 516 | Node.js / Express / Next.js / Nuxt |
| python_web.txt | 511 | Django / Flask / FastAPI / Tornado |
| sensitive_files.txt | 471 | Credentials, keys, SSH, SSL, DB dumps |
| iis.txt | 444 | Microsoft IIS / Exchange / ADFS |
| rails.txt | 429 | Ruby on Rails / Sidekiq / Devise |
| asp.txt | 426 | ASP.NET / Blazor / SignalR / Umbraco / Sitecore |
| apache.txt | 386 | Apache HTTPD / mod_* / cgi-bin |
| cloud_devops.txt | 385 | AWS/Azure/GCP metadata, Terraform, Ansible |
| sap.txt | 361 | SAP NetWeaver / Fiori / HANA / BusinessObjects |
| laravel.txt | 322 | Laravel framework |
| sensitive.txt | 307 | Sensitive directories & hidden paths |
| sharepoint.txt | 301 | Microsoft SharePoint / _layouts / REST API |
| moodle.txt | 289 | Moodle LMS |
| aem.txt | 265 | Adobe Experience Manager / CRXDE / OSGi |
| jsp.txt | 250 | Java Server Pages |
| magento.txt | 248 | Magento / Adobe Commerce / REST & GraphQL |
| docker_kubernetes.txt | 241 | Docker Registry / K8s API / Portainer / Rancher |
| confluence.txt | 225 | Atlassian (Confluence / Jira / Bitbucket / Bamboo) |
| tomcat.txt | 224 | Apache Tomcat |
| devops.txt | 221 | DevOps / CI-CD pipelines |
| swagger.txt | 214 | Swagger / OpenAPI / Redoc / API docs |
| elasticsearch.txt | 214 | Elasticsearch / Kibana / _cat / _cluster |
| nginx.txt | 202 | Nginx-specific |
| jenkins.txt | 200 | Jenkins CI/CD / Script Console / Blue Ocean |
| gitlab.txt | 184 | GitLab / Admin / API v4 |
| umbraco.txt | 172 | Umbraco CMS / Backoffice / Delivery API |
| typo3.txt | 158 | TYPO3 CMS / Backend / Sysext |
| graphql.txt | 140 | GraphQL / GraphiQL / Playground / Voyager |

### Merging Custom Dictionaries

Place your wordlists in `wordlists/dict/` and run:

```bash
blaze --merge-dicts
```

Blaze will classify and merge entries into the appropriate technology wordlists. Unclassified entries go to `common.txt`.

### Always-Run Wordlists

Configure up to 3 wordlists that always run regardless of tech detection:

```bash
blaze --setup-lists
```

---

## How It Works

### Scan Flow

1. **Custom Signatures** — Load user signature packs from `signatures/` directory
2. **Initial Probe** — Connect to target, collect headers, cookies, response body
3. **WAF Detection** — Check for 22+ WAF signatures in headers/body/cookies + trigger paths
4. **Technology Detection** — Fingerprint server, language, framework, CMS from probe + 80 active paths
5. **Subdomain Intelligence** — Detect subdomain patterns and add context-appropriate wordlists
6. **Response Calibration** — Wildcard detection (random paths), soft-404 baseline, wildcard auth detection
7. **Wordlist Assembly** — Build wordlist from: high-priority → user lists → tech-specific → subdomain → always-run → common
8. **Main Scan** — Async scan with real-time adaptive filtering, header leak detection, rate limit fingerprinting, thread adjustment
9. **HTML Crawling** — Scope-aware link extraction from discovered HTML pages, subdomain discovery
10. **JS Extraction** — Parse JavaScript files for hidden API endpoints
11. **Smart Recursion** — Context-aware recursive scanning with per-directory wordlists
12. **Results** — Summary with grouped results, header leaks, rate limit info, and adaptive filter report

### Adaptive Threading

Blaze automatically adjusts concurrency during scanning:

- Detects CPU cores and sets initial thread count (`cores × 25`)
- Monitors response times in a sliding window (last 200 requests)
- **< 30ms avg** → increases threads by 40%
- **< 80ms avg** → increases threads by 20%
- **> 500ms avg** → decreases threads by 20%
- **> 1s avg** → decreases threads by 40%
- **> 15% error rate** → decreases threads by 30%
- Bounded by `min(cores × 2)` and `max(cores × 125)`

### Real-Time Adaptive Filter

The killer feature. During scanning, Blaze tracks every response as a `(status_code, content_length)`, `(status_code, line_count)`, and `(status_code, content_hash)` tuple. When any combo is seen more than the threshold (default 8×), it's flagged as a wildcard pattern and all future matches are auto-filtered.

This catches:
- Wildcard 403 from internal firewalls (same size every time)
- Custom error pages that return HTTP 200
- Authentication gateways returning identical 401s
- Any repetitive response pattern not caught by initial calibration

### Custom Signature Packs

Extend Blaze's detection by dropping `.json` files in the `signatures/` directory:

```json
{
    "name": "My Custom Signatures",
    "version": "1.0",
    "waf_signatures": {
        "header_patterns": {
            "X-Custom-WAF": ["CustomWAF", 0.9]
        },
        "body_patterns": {
            "Access Denied by CustomWAF": ["CustomWAF", 0.85]
        }
    },
    "tech_signatures": {
        "body_patterns": {
            "/custom-cms/": ["CustomCMS", 0.8]
        },
        "cookie_patterns": {
            "custom_session": ["CustomCMS", 0.9]
        },
        "probe_paths": [
            ["custom-admin/", "CustomCMS"]
        ]
    },
    "wordlist_map": {
        "CustomCMS": "common.txt"
    }
}
```

---

## Dependencies

- **Required:** `aiohttp >= 3.9.0`
- **Optional:** `uvloop` (faster event loop on Linux/macOS), `playwright` (headless browser)

---

## Platform Support

| Platform | Status |
|----------|--------|
| Linux x64 | Full support |
| Linux ARM64 | Full support |
| macOS x64 | Full support |
| macOS ARM64 (M1/M2/M3) | Full support |
| Windows x64 | Full support |
| FreeBSD / Unix | Should work (untested) |

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

**Built by assassin_marcos**
