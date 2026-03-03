# Blaze v2.0 — Smart Directory Bruteforce Engine

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

### Intelligence
- **WAF Detection** — 22+ WAF signatures (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, ModSecurity, F5 BIG-IP, Barracuda, Wordfence, Fortinet, Citrix, etc.) with auto-stop and confidence scoring
- **Technology Fingerprinting** — 80+ probe paths, detects PHP, WordPress, Joomla, Drupal, ASP.NET, Java/JSP, Node.js, Python/Django/Flask, Ruby on Rails, Spring, Tomcat, Nginx, Apache, IIS, Magento, TYPO3, Umbraco, Moodle, SharePoint, AEM, Confluence, Jenkins, GitLab, Elasticsearch, SAP, Docker/Kubernetes, GraphQL, Swagger/OpenAPI
- **Smart Wordlist Selection** — Auto-selects from 36 wordlists based on detected technology stack (37 tech mappings)
- **Real-Time Tech Detection** — Detects new technologies from scan results as they come in

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
- **Smart Extension Probing** — Auto-probes `.bak`, `.old`, `.zip`, `.tar.gz`, `.sql` variants of discovered files
- **Directory Archive Probing** — Checks `backup.zip`, `backup.tar.gz`, etc. for discovered directories
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
pip install .
```

Or with fast extras (uvloop):

```bash
pip install ".[fast]"
```

### Installer Script

**Linux / macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows:**
```
install.bat
```

### Standalone Binary

```bash
python build.py
```

Creates a single-file executable in `dist/` — no Python required on the target machine.

### From Source

```bash
git clone https://github.com/assassin-marcos/blaze.git
cd blaze
pip install -e ".[all]"
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

Blaze ships with **759,450+ entries** across 36 technology-specific wordlists:

| Wordlist | Entries | Description |
|----------|---------|-------------|
| common.txt | 496,426 | Universal paths, files, directories |
| asp.txt | 106,480 | ASP.NET / IIS / ASP Classic paths |
| php.txt | 86,271 | PHP applications |
| apache.txt | 14,362 | Apache HTTP Server |
| api.txt | 13,232 | REST API endpoints |
| spring.txt | 11,528 | Spring Framework / Spring Boot |
| python_web.txt | 11,148 | Django, Flask, FastAPI, Python |
| wordpress.txt | 5,625 | WordPress CMS |
| backup.txt | 4,187 | Backup files & archives |
| drupal.txt | 2,055 | Drupal CMS |
| joomla.txt | 1,232 | Joomla CMS |
| nodejs.txt | 515 | Node.js / Express / Next.js |
| sensitive_files.txt | 471 | Sensitive files (.env, keys, configs) |
| iis.txt | 443 | Microsoft IIS |
| rails.txt | 428 | Ruby on Rails |
| cloud_devops.txt | 385 | AWS, Azure, GCP, cloud paths |
| sap.txt | 361 | SAP systems |
| laravel.txt | 321 | Laravel framework |
| sharepoint.txt | 301 | Microsoft SharePoint |
| sensitive.txt | 289 | Sensitive directories & paths |
| moodle.txt | 289 | Moodle LMS |
| aem.txt | 265 | Adobe Experience Manager |
| jsp.txt | 249 | Java Server Pages |
| magento.txt | 248 | Magento eCommerce |
| docker_kubernetes.txt | 241 | Docker & Kubernetes |
| confluence.txt | 225 | Atlassian Confluence |
| tomcat.txt | 223 | Apache Tomcat |
| elasticsearch.txt | 214 | Elasticsearch / Kibana |
| devops.txt | 205 | DevOps / CI-CD tools |
| nginx.txt | 201 | Nginx-specific |
| jenkins.txt | 200 | Jenkins CI/CD |
| swagger.txt | 183 | Swagger / OpenAPI / API docs |
| gitlab.txt | 184 | GitLab |
| umbraco.txt | 172 | Umbraco CMS |
| typo3.txt | 158 | TYPO3 CMS |
| graphql.txt | 140 | GraphQL APIs |

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

1. **Initial Probe** — Connect to target, collect headers, cookies, response body
2. **WAF Detection** — Check for 22+ WAF signatures in headers/body/cookies + trigger paths
3. **Technology Detection** — Fingerprint server, language, framework, CMS from probe + 80 active paths
4. **Response Calibration** — Wildcard detection (random paths), soft-404 baseline, wildcard auth detection
5. **Wordlist Assembly** — Build wordlist from: high-priority paths → user lists → tech-specific → always-run → common
6. **Main Scan** — Async scan with real-time adaptive filtering, thread adjustment, and progress tracking
7. **HTML Crawling** — Extract and scan links from discovered HTML pages
8. **JS Extraction** — Parse JavaScript files for hidden API endpoints
9. **Smart Recursion** — Context-aware recursive scanning with per-directory wordlists
10. **Results** — Summary with grouped results, statistics, and adaptive filter report

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
