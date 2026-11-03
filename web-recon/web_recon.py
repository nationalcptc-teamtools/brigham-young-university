#!/usr/bin/env python3
"""
Web Recon - Directory, Parameter & Vulnerability Discovery

Wraps whatweb, ffuf, and arjun into a sequential discovery pipeline for web
targets. Auto-detects technology stacks, discovers directories/files,
filters static assets, discovers hidden parameters, automatically probes for
common vulnerability indicators (LFI/SQLi/CMDi via ffuf -mr), and generates
copy-paste curl commands, ffuf commands, and Burp Repeater request blocks.

Discovery only. No automated exploitation.

Pipeline (spider-first: enumerate everything easy, probe it, THEN brute force):
  Phase 0:   whatweb tech fingerprint → auto-select extension preset
  Phase 0.5: quick-win pre-checks (robots.txt, api-docs, .git, .env, ...)
  Phase 1:   katana spider → linked endpoints + on-page GET parameters
  Phase 2:   probe spidered/quick-check findings for vulns FIRST
             (dir-traversal triage + LFI/SQLi/CMDi on on-page params)
  Phase 3:   ffuf directory/file brute force (fast wordlist) → new endpoints
  Phase 4:   arjun parameter discovery on brute-forced endpoints
  Phase 5:   ffuf vulnerability probing on arjun params
  Phase 6:   report → curl/ffuf/Burp + per-dir recursive & vhost commands

License: MIT
"""

import argparse
import json
import os
import random
import re
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# =============================================================================
# Constants & Configuration
# =============================================================================

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Safety valve: cap how many endpoints arjun runs against so a large crawl
# can't stall an unattended run (arjun is ~30-60s per endpoint).
MAX_ARJUN_ENDPOINTS = 25

# arjun per-endpoint timeout. 5 min was too slow for exam pace; 90s finishes
# any responsive endpoint and caps the worst-case multi-endpoint run.
ARJUN_TIMEOUT = 90

# HTML form field harvesting (Phase 1.5): cap on endpoints fetched, and
# anti-CSRF/token fields that are pointless to probe.
MAX_FORM_ENDPOINTS = 25
SKIP_FORM_PARAMS = {
    "csrfmiddlewaretoken", "csrf_token", "csrf",
    "_token", "__requestverificationtoken", "authenticity_token",
}

# ffuf concurrency. 40 threads can SIGSEGV fragile single-container targets
# (e.g. Juice Shop) and you never want to knock a box over. 20 is a
# safer default; raise via --ffuf-flags "-t N" when the target can take it.
FFUF_THREADS = 20

# --gentle mode: reduced concurrency + rate limiting for fragile
# single-container targets. Juice Shop SIGSEGVs under default probe load
# (even -t 10); these settings keep it alive.
GENTLE_DIR_THREADS = 5
GENTLE_API_THREADS = 3
GENTLE_PROBE_THREADS = 3
GENTLE_PROBE_RATE = 15      # req/s cap for probe wordlists
GENTLE_KATANA_CONCURRENCY = 5

# Path prefixes that mark an API base worth fuzzing one level deeper (Phase 3.6).
# Self-gating: we only fuzz a base that was actually discovered, so non-API
# targets skip this phase entirely.
API_BASES = ("api", "rest", "graphql", "v1", "v2")

# API fuzzing is a deeper, secondary probe — run it gentler so the extra load
# doesn't tip a fragile target over (Juice Shop survives -t 3, crashes at -t 20).
API_FUZZ_THREADS = 8

# Static file extensions to filter before parameter discovery
# Source: reconFTW modules/web.sh line 1341
STATIC_EXTENSIONS = {
    ".eot", ".jpg", ".jpeg", ".gif", ".css", ".tif", ".tiff",
    ".png", ".ttf", ".otf", ".woff", ".woff2", ".ico", ".pdf", ".svg",
    # JS bundles: on SPAs the spider surfaces dozens of these; they are
    # static assets, not endpoints to probe/param-fuzz.
    ".js", ".mjs", ".map",
}

# Technology preset → file extensions for ffuf directory scanning
# 'all' intentionally has NO extensions: for unknown/Node.js stacks,
# scanning 30k words × 13 extensions = 390k requests over a remote
# host takes 130+ minutes and extensions like .php/.asp are useless.
# Tech-specific presets use a small, targeted extension list only.
TECH_PRESETS = {
    "php":  "php,html,txt,bak,inc,php.bak,old",
    "aspx": "aspx,asp,config,bak,ashx,asmx,svc",
    "java": "jsp,do,action,jsf,faces,xml,bak",
    "all":  None,   # no extension multiplier — dir names only
}

# whatweb output keywords → tech preset mapping
WHATWEB_TECH_MAP = {
    "php":  ["PHP", "WordPress", "Laravel", "Drupal", "Joomla", "Moodle",
             "CakePHP", "CodeIgniter", "Symfony"],
    "aspx": ["ASP.NET", "IIS", "Microsoft-HTTPAPI", "Microsoft-IIS"],
    "java": ["Java", "Tomcat", "JBoss", "Spring", "JSP", "Servlet",
             "GlassFish", "WebLogic", "WildFly", "Jenkins"],
    # Node.js/Express stacks fall through to 'all' preset — listed here
    # so they are logged when detected rather than triggering a preset.
    # (no specific extension preset needed for JS backends)
    "_nodejs_detected": ["Node.js", "Express", "Next.js", "Nuxt",
                         "FeathersJS", "NestJS"],
}

# Default SecLists wordlist paths (standard Kali install: apt install seclists)
# dir_primary is deliberately the small, curated common.txt (~4.7k). The katana
# spider (Phase 1) already harvests every linked dir/file, so the brute-force
# pass only needs to catch UNLINKED paths — common.txt does that fast. Use
# --wordlist to swap in raft-medium (~30k) when you want an exhaustive sweep.
WORDLISTS = {
    "dir_primary":  "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "dir_fallback": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    # --quick must be <= the normal list; common.txt (~4.7k) is already the
    # fast default, so quick reuses it (quick mode also trims extensions/recursion).
    "dir_quick":    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "vhost":        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    # API route fuzzing (Phase 3.6). objects.txt lists REST object names in
    # both cases (Products/products, Users/users, Feedbacks...), matching the
    # /api/<Model> and /rest/<object> conventions; ~3k entries, still fast.
    "api":          "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    "api_fallback": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "lfi":          "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
    "sqli":         "/usr/share/seclists/Fuzzing/Databases/SQLi/quick-SQLi.txt",
    "cmdi":         "/usr/share/seclists/Fuzzing/command-injection-commix.txt",
}

# Vulnerability probe configurations
# Each probe type defines: which wordlist to use, what regex to match in
# responses, and a human description for logging and reports.
PROBE_CONFIG = {
    "lfi": {
        "wordlist_key": "lfi",
        "match_regex": (
            "root:x:|root:/bin|\\[boot loader\\]|\\[extensions\\]"
            "|; for 16-bit|PD[A-Za-z0-9+/]="
        ),
        "description": "LFI / Path Traversal",
    },
    "sqli": {
        "wordlist_key": "sqli",
        "match_regex": (
            # MySQL / MariaDB
            "SQL syntax|mysql_fetch|mysql_num_rows|Warning.*mysql_"
            "|You have an error in your SQL"
            # PostgreSQL
            "|pg_query|pg_exec|syntax error at or near|unclosed quotation"
            "|quoted string not properly"
            # Oracle
            "|ORA-[0-9]"
            # MSSQL
            "|Microsoft SQL|ODBC"
            # SQLite (Juice Shop / Sequelize)
            "|SQLITE_ERROR|sqlite3_errmsg|SequelizeDatabaseError"
            "|near \".*\": syntax error|unrecognized token"
            # Generic
            "|sql syntax|SqlException|DatabaseException"
        ),
        "description": "SQL Injection (error-based)",
    },
    "cmdi": {
        "wordlist_key": "cmdi",
        "match_regex": (
            "uid=[0-9]+\\([a-z]|root:|www-data"
            "|COMPUTERNAME=|Windows NT|Microsoft Windows"
        ),
        "description": "Command Injection",
    },
}

# arjun output parsing patterns (adapted from reconFTW web.sh lines 1272-1285)
RE_URL = re.compile(r"https?://\S+")
RE_PARAMS_FOUND = re.compile(r"Parameters found:\s*(.*)", re.IGNORECASE)
RE_INLINE_PARAM = re.compile(r"[?&]([A-Za-z0-9_.-]+)=")

# HTML form field names: input/select/textarea/button. These are the params
# the app actually expects on POST forms — arjun can't find them when the app
# doesn't reflect parameters (e.g. CSRF-protected login forms).
RE_FORM_NAME = re.compile(
    r"<(?:input|select|textarea|button)[^>]*\bname\s*=\s*"
    r"[\"']?([A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)

# Top 20 LFI & Path Traversal payloads for quick directory-level verification
TOP_20_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd\x00",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../windows/win.ini",
    "../../../../windows/win.ini\x00",
    "....//....//....//....//windows/win.ini",
    "..%2f..%2f..%2f..%2fwindows%2fwin.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
    "c:/windows/win.ini",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../windows/system32/drivers/etc/hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\etc\\passwd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "../../../../etc/passwd%00",
    "../../../../windows/win.ini%00",
]


# =============================================================================
# Utility Functions
# =============================================================================

LOG_LOCK = threading.Lock()


def log_info(msg):
    """Print an informational message."""
    with LOG_LOCK:
        print(f"{BLUE}[*]{RESET} {msg}")


def log_success(msg):
    """Print a success message."""
    with LOG_LOCK:
        print(f"{GREEN}[+]{RESET} {msg}")


def log_warn(msg):
    """Print a warning message."""
    with LOG_LOCK:
        print(f"{YELLOW}[!]{RESET} {msg}")


def log_error(msg):
    """Print an error message."""
    with LOG_LOCK:
        print(f"{RED}[-]{RESET} {msg}")


def log_vuln(msg):
    """Print a vulnerability indicator message."""
    with LOG_LOCK:
        print(f"{RED}{BOLD}[!!!]{RESET} {RED}{msg}{RESET}")


def log_phase(phase_name):
    """Print a phase separator banner."""
    with LOG_LOCK:
        print(f"\n{MAGENTA}{BOLD}{'=' * 60}{RESET}")
        print(f"{MAGENTA}{BOLD}  {phase_name}{RESET}")
        print(f"{MAGENTA}{BOLD}{'=' * 60}{RESET}\n")


def check_tool(name):
    """Check if an external tool is installed and in PATH."""
    return shutil.which(name) is not None


def auto_detect_headless():
    """
    Return True if a Chrome/Chromium binary is available for katana headless
    crawling. False otherwise.
    """
    for name in ("chromium", "chromium-browser", "google-chrome",
                 "google-chrome-stable", "chrome"):
        if shutil.which(name):
            return True
    return False


def target_responding(url, verbose=False):
    """Quick liveness check — returns False if the target won't answer."""
    out, _, _ = run_subprocess(
        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "8", url.rstrip("/") + "/"],
        timeout=12, verbose=verbose,
    )
    return out.strip() not in ("", "000")


def check_alive_or_warn(url, phase, verbose=False):
    """
    Warn (loudly) if the target has stopped responding — e.g. it crashed under
    fuzzing load. One short retry in case it is just restarting. Returns True
    if alive. Lets the caller decide whether to skip a phase.
    """
    if target_responding(url, verbose=verbose):
        return True
    log_warn(f"Target not responding before {phase} — may have crashed under "
             f"load. Waiting 15s for a possible restart...")
    time.sleep(15)
    if target_responding(url, verbose=verbose):
        log_success("Target responding again — continuing.")
        return True
    log_error(f"Target still unresponsive — {phase} results will be incomplete "
              f"(reduce load with --no-probe or --ffuf-flags \"-t 5 -rate 20\").")
    return False


def run_phase(label, fn, default=None):
    """
    Run one pipeline phase, catching any unexpected exception so a single
    failing tool/phase can't abort the whole target — the run still reaches
    report generation with whatever was gathered. Returns fn()'s value, or
    `default` if it raised.
    """
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 - deliberately broad for resilience
        log_error(f"{label} failed ({type(e).__name__}: {e}) — continuing")
        return default


def run_subprocess(cmd, timeout=None, verbose=False):
    """
    Run a subprocess command and return (stdout, stderr, returncode).

    Captures stdout/stderr for programmatic parsing.  Use
    run_subprocess_live() instead when you want to stream output directly
    to the terminal (e.g. for long-running ffuf directory scans).
    """
    if verbose:
        log_info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        log_warn(f"Command timed out after {timeout}s: {' '.join(cmd[:3])}...")
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        log_error(f"Command not found: {cmd[0]}")
        return "", f"{cmd[0]} not found", -1


def run_subprocess_live(cmd, timeout=None, verbose=False):
    """
    Run a subprocess and stream its stdout/stderr live to the terminal.

    Used for long-running tools (e.g. ffuf directory scan) where the user
    needs real-time feedback.  Returns (returncode,) — output is not
    captured since it has already been printed.
    """
    if verbose:
        log_info(f"Running: {' '.join(cmd)}")
    import threading
    import time

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr → stdout
            text=True,
            bufsize=1,                  # line-buffered
        )

        deadline = time.monotonic() + timeout if timeout else None

        def _stream():
            for line in proc.stdout:
                if ":: Progress:" in line or line.strip().startswith(":: Progress:"):
                    continue
                with LOG_LOCK:
                    print(line, end="", flush=True)

        t = threading.Thread(target=_stream, daemon=True)
        t.start()

        while proc.poll() is None:
            if deadline and time.monotonic() > deadline:
                proc.kill()
                log_warn(
                    f"Command timed out after {timeout}s: "
                    f"{' '.join(cmd[:3])}..."
                )
                t.join(timeout=2)
                return -1
            time.sleep(0.5)

        t.join(timeout=5)
        return proc.returncode

    except FileNotFoundError:
        log_error(f"Command not found: {cmd[0]}")
        return -1


def sanitize_filename(url):
    """
    Convert a URL into a safe filename component.
    Includes host, port (if non-standard), and path slug or hash if path exists.
    """
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    port = parsed.port
    base = f"{host}_{port}" if (port and port not in (80, 443)) else host
    path = parsed.path.strip("/")
    if path:
        slug = re.sub(r"[^\w\-]", "_", path)
        if len(slug) > 30:
            import hashlib
            slug = hashlib.md5(path.encode()).hexdigest()[:8]
        return f"{base}_{slug}"
    return base


def find_wordlist(key):
    """
    Find a wordlist by key, checking primary and fallback paths.
    Returns the path string if found, None otherwise.
    """
    path = WORDLISTS.get(key, "")
    if path and os.path.isfile(path):
        return path
    # Fallback for directory wordlists
    if key == "dir_primary":
        fallback = WORDLISTS.get("dir_fallback", "")
        if fallback and os.path.isfile(fallback):
            log_warn(f"Primary wordlist not found, using fallback: {fallback}")
            return fallback
    return None


def url_sep(url):
    """Return '&' if URL already has query params, else '?'."""
    return "&" if "?" in url else "?"


# =============================================================================
# Phase 0: Technology Detection (whatweb)
# =============================================================================

def run_whatweb(url, verbose=False):
    """Run whatweb -a1 against a URL and return raw output."""
    log_info(f"Running whatweb against {url}")
    cmd = ["whatweb", "-a", "1", "--color=never", url]
    stdout, stderr, rc = run_subprocess(cmd, timeout=30, verbose=verbose)

    if rc != 0:
        log_warn(f"whatweb returned non-zero exit code: {rc}")

    return {"raw": stdout.strip()}


def detect_tech_preset(whatweb_result):
    """
    Determine the best tech preset from whatweb output.
    Scans the raw whatweb output for known technology keywords.
    Node.js/Express stacks log a detection but still use 'all' preset
    (no specific extension subset is better for JS backends).
    """
    raw = whatweb_result.get("raw", "") or ""

    for preset, keywords in WHATWEB_TECH_MAP.items():
        for keyword in keywords:
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, raw, re.IGNORECASE):
                if preset == "_nodejs_detected":
                    log_success(
                        f"Tech detected: {keyword} (Node.js stack) → "
                        "using 'all' preset (no specific JS extensions)"
                    )
                    return "all"
                log_success(f"Tech detected: {keyword} → using '{preset}' preset")
                return preset

    log_warn("Could not determine technology stack, using 'all' preset")
    return "all"


# =============================================================================
# Phase 1: Site Spidering (katana)
# =============================================================================

def parse_katana_output(stdout, url):
    """
    Parse katana stdout (one URL per line) into (endpoints, params_by_url).
    Pure function — no I/O — so it is unit-testable.

    Inline parameters found on static-asset URLs (STATIC_EXTENSIONS) are
    dropped from params_by_url — they are version cache-busters, not
    application parameters.
    """
    host = urlparse(url).hostname
    endpoints = set()
    params_by_url = {}
    for line in stdout.splitlines():
        m = RE_URL.search(line.strip())
        if not m:
            continue
        found = m.group(0)
        parsed = urlparse(found)
        # Stay in scope — ignore off-host links katana may surface.
        if host and parsed.hostname and parsed.hostname != host:
            continue
        base = found.split("?", 1)[0].split("#", 1)[0]
        endpoints.add(base)
        # Skip parameters harvested from static assets (static extension or
        # /static/ path): they are cache-busting version params, not
        # application parameters worth probing. (The endpoint itself is still
        # recorded — endpoints get static-filtered downstream where relevant.)
        if is_static_url(base):
            continue
        for pm in RE_INLINE_PARAM.finditer(found):
            params_by_url.setdefault(base, set()).add(pm.group(1))
    params_by_url = {u: sorted(p) for u, p in params_by_url.items() if p}
    return sorted(endpoints), params_by_url


def run_katana(url, depth=3, headless=False, verbose=False,
               concurrency=15):
    """
    Spider the target with katana to enumerate endpoints and on-page GET
    parameters that are already linked/reachable, BEFORE any brute forcing.

    Reliability: jsluice parses JS bundles (where SPA/API routes live), known
    files (robots/sitemap) are crawled, forms are auto-filled, and the whole
    run is retried once if the first pass returns almost nothing (katana can
    exit early on JS-heavy SPAs). headless=True renders JS via Chrome/Chromium
    and is auto-enabled by the caller when Chromium is detected (--headless to
    force, --no-headless to disable).

    Returns (endpoints, params_by_url):
      endpoints     : sorted list of unique in-scope URLs (query string stripped)
      params_by_url : {base_url: [param, ...]} for URLs that carried a query
    """
    log_info(
        f"Spidering {url} with katana (depth {depth}"
        f"{', headless' if headless else ''})"
    )
    base_cmd = [
        "katana", "-u", url,
        "-d", str(max(depth, 3)),  # -kf all needs depth>=3 to crawl known files
        "-jc",              # crawl linked JS files for endpoints
        "-jsl",             # jsluice: extract endpoints from JS (finds /rest,/api)
        "-kf", "all",       # robots.txt + sitemap.xml
        "-aff",             # auto form-fill → reach more routes
        "-retry", "2",
        "-c", str(concurrency),
        "-timeout", "15",
        "-silent",
    ]
    if headless:
        base_cmd += ["-hl", "-nos"]

    # Retry the whole crawl once if it comes back near-empty (1 = just root).
    best_eps, best_params = [], {}
    for attempt in (1, 2):
        stdout, _, rc = run_subprocess(base_cmd, timeout=420, verbose=verbose)
        eps, params = parse_katana_output(stdout, url)
        if len(eps) > len(best_eps):
            best_eps, best_params = eps, params
        if len(eps) > 1:
            break
        if attempt == 1:
            log_warn(
                f"katana returned {len(eps)} endpoint(s) (rc={rc}); retrying once..."
            )

    log_success(
        f"katana found {len(best_eps)} endpoint(s), "
        f"{sum(len(p) for p in best_params.values())} on-page param(s)"
    )
    return best_eps, best_params


def robots_disallow_urls(base_url, verbose=False):
    """
    Fetch robots.txt and return absolute URLs for its Disallow entries.
    On Juice Shop this is how /ftp surfaces; broadly useful on any target
    since Disallow lines advertise paths the owner wants hidden.
    """
    base = base_url.rstrip("/")
    stdout, _, _ = run_subprocess(
        ["curl", "-sk", "--max-time", "8", "-L", base + "/robots.txt"],
        timeout=12, verbose=verbose,
    )
    urls = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                urls.append(base + "/" + path.lstrip("/"))
    if urls:
        log_success(f"robots.txt Disallow revealed {len(urls)} path(s): "
                    + ", ".join(urls))
    return urls


# =============================================================================
# Phase 1.5: HTML Form Field Harvesting
# =============================================================================

def parse_form_fields(html):
    """
    Extract input/select/textarea/button field names from HTML.
    Pure function — no I/O — so it is unit-testable.
    Anti-CSRF/token fields (SKIP_FORM_PARAMS) are dropped.
    """
    fields = set()
    for m in RE_FORM_NAME.finditer(html):
        name = m.group(1).strip()
        if name and name.lower() not in SKIP_FORM_PARAMS:
            fields.add(name)
    return sorted(fields)


def harvest_form_params(endpoints, verbose=False):
    """
    Fetch each endpoint and harvest HTML form field names.

    arjun only discovers parameters the app reflects back; login/registration
    form fields (username/password/email) are usually NOT reflected, so this
    is the only way the pipeline sees them. The harvested fields flow into
    the normal probe pipeline, which tests them GET & POST for LFI/SQLi/CMDi.

    Returns {url: [param, ...]} for endpoints that exposed a form.
    """
    params_by_url = {}
    total = min(len(endpoints), MAX_FORM_ENDPOINTS)
    if total < len(endpoints):
        log_warn(
            f"Form harvest limited to first {MAX_FORM_ENDPOINTS} of "
            f"{len(endpoints)} endpoints"
        )
    for i, ep in enumerate(endpoints[:MAX_FORM_ENDPOINTS], 1):
        log_info(f"Form harvest [{i}/{total}]: {ep}")
        out, _, _ = run_subprocess(
            ["curl", "-sk", "-L", "--max-time", "10", ep],
            timeout=15, verbose=verbose,
        )
        fields = parse_form_fields(out)
        if fields:
            params_by_url[ep] = fields
            log_success(f"  {len(fields)} form field(s): {', '.join(fields)}")
    return params_by_url


# =============================================================================
# Phase 3: Directory Discovery (ffuf)
# =============================================================================

def build_ffuf_cmd(url, extensions, wordlist, output_file,
                   recursive=False, extra_flags=None, filter_size=None,
                   threads=None):
    """Build the ffuf command list for directory scanning."""
    base_url = url.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", base_url,
        "-w", wordlist,
        "-ac",              # auto-calibrate
        "-t", str(threads or FFUF_THREADS),
        "-timeout", "10",
        "-o", output_file,
        "-of", "json",
        "-noninteractive",
        # NOTE: no -s here — silent mode strips the [Status/Size/Words]
        # metadata from live hits. The progress ticker (:: Progress:) is
        # filtered out by run_subprocess_live instead.
    ]

    # On wildcard-200 SPAs, -ac alone is unreliable; also filter the known
    # catch-all body size so real endpoints (different size) survive.
    if filter_size is not None:
        cmd += ["-fs", str(filter_size)]

    # Only add -e if there are meaningful extensions for this tech stack.
    # 'all' preset passes None to avoid the 13x request multiplier.
    if extensions:
        cmd += ["-e", extensions]

    # Recursion is ON by default (depth 2): each discovered directory gets one
    # deeper pass so nested unlinked paths (exam favorites) aren't missed.
    # Disable with --no-recursive when time/requests are tight.
    if recursive:
        cmd += ["-recursion", "-recursion-depth", "2"]

    if extra_flags:
        cmd.extend(shlex.split(extra_flags))

    return cmd


# =============================================================================
# Phase 0.5: Quick-Win Pre-Checks
# =============================================================================

# High-value paths to probe before the long ffuf scan.
# On Juice Shop, /api-docs alone gives the full API route map.
QUICK_WIN_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
    "/api-docs",
    "/swagger.json",
    "/openapi.json",
    "/.well-known/security.txt",
    "/server-status",
    "/phpinfo.php",
    "/web.config",
    "/crossdomain.xml",
    "/security.txt",
    "/package.json",
    "/config.json",
    "/metrics",          # Prometheus metrics (info disclosure)
    "/ftp",              # exposed file share (Juice Shop & others)
    "/actuator/health",  # Spring Boot actuator
]


def _curl_get(url, verbose=False):
    """GET a URL with curl; return (status, body). status 0 on failure."""
    out, _, _ = run_subprocess(
        ["curl", "-sk", "-o", "-", "-w", "\n__STATUS__%{http_code}",
         "--max-time", "8", "-L", url],
        timeout=12, verbose=verbose,
    )
    status, body = 0, out
    if "__STATUS__" in out:
        parts = out.rsplit("__STATUS__", 1)
        body = parts[0]
        try:
            status = int(parts[1].strip())
        except ValueError:
            status = 0
    return status, body


def run_quick_checks(base_url, verbose=False):
    """
    Curl a list of high-value paths before the ffuf scan.

    SPAs (Angular/React) return 200 + the same index page for EVERY path, so a
    naive "non-404 = hit" test yields false positives. We first fetch a random
    path to learn that catch-all response (status + body length); any path that
    matches it within tolerance is flagged as catch-all and skipped, so only
    responses that genuinely differ are reported.

    Returns a list of dicts describing real (non-catch-all) hits.
    """
    hits = []
    base = base_url.rstrip("/")

    # Learn the catch-all baseline from a path that should not exist.
    rnd = "/zz" + "".join(random.choices(string.ascii_lowercase, k=14))
    base_status, base_body = _curl_get(base + rnd, verbose=verbose)
    base_len = len(base_body)
    if base_status == 200:
        log_info(
            f"Catch-all baseline: random path returns 200 ({base_len}b) — "
            f"SPA-style; filtering identical responses"
        )

    log_info(f"Checking {len(QUICK_WIN_PATHS)} high-value paths...")
    for path in QUICK_WIN_PATHS:
        target = base + path
        status, body = _curl_get(target, verbose=verbose)

        if status in (0, 404):
            log_info(f"  {path:<30} {status}")
            continue

        # Skip responses indistinguishable from the catch-all baseline.
        if (status == base_status == 200
                and abs(len(body) - base_len) <= 64):
            log_info(f"  {path:<30} {status} (catch-all — skipped)")
            continue

        # Color-code by status
        if status in (401, 403):
            sc = f"{RED}{BOLD}{status}{RESET}"
            tag = f" {RED}← AUTH PROTECTED — high priority{RESET}"
        elif status == 500:
            sc = f"{RED}{status}{RESET}"
            tag = f" {YELLOW}← server error{RESET}"
        elif status in (200, 301, 302):
            sc = f"{GREEN}{status}{RESET}"
            tag = ""
        else:
            sc = f"{YELLOW}{status}{RESET}"
            tag = ""

        snippet = body[:300].replace("\n", " ").replace("\r", "")
        log_success(f"  {path:<30} {sc}{tag}")
        if snippet:
            print(f"  {CYAN}    ↳ {snippet[:200]}{RESET}")

        hits.append({
            "path":    path,
            "url":     target,
            "status":  status,
            "snippet": snippet,
        })

    return hits


def detect_catchall_size(url, verbose=False, any_status=False):
    """
    Probe a random path under `url` to detect a wildcard/catch-all responder
    (SPAs 200 the same index for everything; API bases 500 the same error for
    everything). Returns the catch-all body size to feed ffuf as -fs, or None.
    With any_status=True, treat any repeated status as a catch-all (used for
    API bases, which answer unknown routes with a uniform non-200 error).
    """
    base = url.rstrip("/")
    rnd = "/zz" + "".join(random.choices(string.ascii_lowercase, k=14))
    out, _, _ = run_subprocess(
        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
         "--max-time", "8", "-L", base + rnd],
        timeout=12, verbose=verbose,
    )
    try:
        code, size = out.split()
        if any_status or code == "200":
            return int(size)
    except ValueError:
        pass
    return None


def find_api_bases(endpoints, base_url):
    """
    Return base URLs (e.g. http://t/api, http://t/rest) that were actually
    discovered among `endpoints`, so Phase 3.6 can fuzz one level deeper.
    Self-gating: nothing discovered → nothing fuzzed.
    """
    root = base_url.rstrip("/")
    bases = set()
    for ep in endpoints:
        seg = urlparse(ep).path.strip("/").split("/")
        if seg and seg[0] and seg[0].lower() in API_BASES:
            bases.add(root + "/" + seg[0])
    return sorted(bases)


def run_api_fuzz(api_base, output_dir, verbose=False, timeout=600,
                 threads=None):
    """
    Fuzz api_base/FUZZ with the API wordlist. Reuses build_ffuf_cmd and the
    catch-all -fs trick (an API base 500s unknown routes uniformly). Returns a
    list of ffuf hit dicts.
    """
    wl = find_wordlist("api") or find_wordlist("api_fallback")
    if not wl:
        log_warn("API wordlist not found; skipping API fuzz "
                 "(install seclists or set WORDLISTS['api']).")
        return []

    catchall = detect_catchall_size(api_base, verbose=verbose, any_status=True)
    out_file = os.path.join(
        output_dir, f"{sanitize_filename(api_base)}_apifuzz.json"
    )
    log_info(
        f"Fuzzing {api_base}/FUZZ  (wordlist={os.path.basename(wl)}"
        + (f", -fs {catchall}" if catchall else "") + ")"
    )
    cmd = build_ffuf_cmd(api_base, None, wl, out_file,
                         filter_size=catchall,
                         threads=threads or API_FUZZ_THREADS)
    run_subprocess_live(cmd, timeout=timeout, verbose=verbose)

    hits = parse_ffuf_json(out_file) if os.path.isfile(out_file) else []
    for h in hits:
        log_success(
            f"  API route: {h.get('url')} "
            f"[{h.get('status')}] {h.get('length')}b"
        )
    return hits


def run_ffuf_dirscan(url, preset, output_dir, wordlist_override=None,
                     extra_flags=None, recursive=False,
                     quick_mode=False, verbose=False, timeout=1800,
                     threads=None):
    """
    Run ffuf directory scan against a target URL.
    Returns path to the JSON output file, or None on failure.
    """
    extensions = TECH_PRESETS.get(preset)   # None for 'all' preset
    
    if quick_mode:
        log_info(f"QUICK MODE ENABLED: Forcing small wordlist and minimal extensions.")
        if extensions:
            extensions = "php,txt,bak"
        recursive = False

    # Resolve wordlist
    if wordlist_override and os.path.isfile(wordlist_override):
        wordlist = wordlist_override
    else:
        wl_key = "dir_quick" if quick_mode else "dir_primary"
        wordlist = find_wordlist(wl_key)
        if not wordlist:
            log_error("No directory wordlist found! Install: apt install seclists")
            return None

    ext_display = extensions if extensions else "(none — directory names only)"
    wl_lines    = sum(1 for _ in open(wordlist)) if os.path.isfile(wordlist) else "?"
    multiplier  = (len(extensions.split(",")) + 1) if extensions else 1
    est_reqs    = wl_lines * multiplier if isinstance(wl_lines, int) else "?"
    est_mins    = round(est_reqs / 50 / 60, 1) if isinstance(est_reqs, int) else "?"

    # Detect a wildcard/catch-all (SPA) so we can filter its size in ffuf.
    catchall_size = detect_catchall_size(url, verbose=verbose)
    if catchall_size is not None:
        log_warn(
            f"Catch-all detected: unknown paths return 200 ({catchall_size}b). "
            f"Filtering that size (-fs {catchall_size}) so real endpoints survive."
        )

    log_info(f"Wordlist  : {wordlist} ({wl_lines} entries)")
    log_info(f"Extensions: {ext_display}")
    log_info(f"Recursion : {'ON' if recursive else 'OFF (--no-recursive used)'}")
    log_info(f"Est. requests: ~{est_reqs} (running with {FFUF_THREADS} threads)")

    safe_name   = sanitize_filename(url)
    output_file = os.path.join(output_dir, f"{safe_name}_ffuf.json")

    cmd = build_ffuf_cmd(
        url, extensions, wordlist, output_file,
        recursive=recursive, extra_flags=extra_flags,
        filter_size=catchall_size,
        threads=threads,
    )
    log_info(f"Starting ffuf directory scan against {url}")
    log_info("[ffuf output streamed live — hits appear as found]")
    if verbose:
        log_info(f"Full command: {' '.join(cmd)}")

    rc = run_subprocess_live(cmd, timeout=timeout, verbose=verbose)

    if rc != 0 and not os.path.isfile(output_file):
        log_error(f"ffuf failed (rc={rc})")
        return None

    if os.path.isfile(output_file):
        log_success(f"ffuf scan complete → {output_file}")
        return output_file

    log_warn("ffuf completed but no output file was generated")
    return None


# =============================================================================
# Phase 2: Static Asset Filtering
# =============================================================================

def parse_ffuf_json(json_path):
    """Parse ffuf JSON output and return the results list."""
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
        raw_results = data.get("results", [])

        # Deduplicate by lowercase URL to kill case-variants (e.g. /ftp and /FTP)
        results = []
        seen = set()
        for r in raw_results:
            url_lower = r.get("url", "").lower()
            if url_lower not in seen:
                seen.add(url_lower)
                results.append(r)

        log_info(
            f"Parsed {len(raw_results)} results from ffuf JSON "
            f"(deduplicated to {len(results)})"
        )
        return results
    except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
        log_error(f"Failed to parse ffuf JSON: {e}")
        return []


# Path segments reserved for static bundles. jsluice/katana surface URLs like
# /static/js/.exec that carry NO static extension, so extension-only filtering
# misses them — a whole path segment named 'static' is always a bundle dir.
STATIC_PATH_SEGMENTS = ("static",)


def is_static_url(u):
    """
    True if the URL points at a static asset: a known static extension OR a
    path with a dedicated static-bundle segment (/static/...).
    """
    path = urlparse(u).path.lower().strip("/")
    if not path:
        return False
    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return True
    return any(seg in STATIC_PATH_SEGMENTS for seg in path.split("/"))


def filter_static_urls(urls):
    """Drop static-asset URLs (extension or /static/ path) from a URL list."""
    return [u for u in urls if not is_static_url(u)]


def filter_static_assets(results):
    """Remove static asset URLs from ffuf results."""
    dynamic = []
    static_count = 0

    for r in results:
        url = r.get("url", "")
        if is_static_url(url):
            static_count += 1
        else:
            dynamic.append(r)

    log_info(
        f"Filtered {static_count} static assets, "
        f"{len(dynamic)} dynamic endpoints remain"
    )
    return dynamic


def extract_dynamic_endpoints(results):
    """Extract a deduplicated list of endpoint URLs from filtered results."""
    seen = set()
    endpoints = []
    for r in results:
        status = r.get("status", 0)
        # Skip 500s for parameter discovery. They are typically Express router
        # errors reflecting the path, not real parameterized endpoints.
        if status >= 500:
            continue

        url = r.get("url", "")
        url_lower = url.lower()
        if url and url_lower not in seen:
            seen.add(url_lower)
            endpoints.append(url)
    return endpoints


# =============================================================================
# Phase 3: Parameter Discovery (arjun)
# =============================================================================

def run_arjun(endpoint, verbose=False):
    """Run arjun against a single endpoint and return discovered params."""
    log_info(f"Running arjun against {endpoint}")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="arjun_"
    ) as f:
        output_file = f.name

    # arjun invocation mirrors reconFTW: arjun -i <input> -oT <output>
    # For single URL we use -u instead of -i.
    # -m GET,POST: test both HTTP methods so JSON POST body params
    # (e.g. email/password on /rest/user/login) are discovered.
    cmd = ["arjun", "-u", endpoint, "-m", "GET,POST", "-oT", output_file]
    stdout, stderr, rc = run_subprocess(cmd, timeout=ARJUN_TIMEOUT, verbose=verbose)

    params = parse_arjun_output(output_file, stdout)

    # Cleanup temp file
    try:
        os.unlink(output_file)
    except OSError:
        pass

    return params


def parse_arjun_output(text_file, stdout_text=""):
    """
    Parse arjun plaintext output to extract discovered parameters.

    Adapted from reconFTW modules/web.sh lines 1272-1285:
      grep -aEo 'https?://[^ ]+'              → extract URLs
      grep -aE 'Parameters found:' | tr ','    → extract param lists
      grep -aEo '([?&][A-Za-z0-9_.-]+)='      → extract inline params
    """
    params = {}

    # Combine file content and stdout
    content = stdout_text or ""
    try:
        if os.path.isfile(text_file) and os.path.getsize(text_file) > 0:
            with open(text_file, "r") as f:
                content += "\n" + f.read()
    except (OSError, IOError):
        pass

    if not content.strip():
        return params

    current_url = None

    for line in content.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Extract URL from line
        url_match = RE_URL.search(line)
        if url_match:
            found_url = url_match.group(0)
            base_url = re.sub(r"[?&].*", "", found_url)
            current_url = base_url
            if current_url not in params:
                params[current_url] = set()

            # Extract inline params (e.g., ?id=1&file=test)
            for pm in RE_INLINE_PARAM.finditer(found_url):
                params[current_url].add(pm.group(1))

        # Extract from "Parameters found: param1, param2" lines
        pf_match = RE_PARAMS_FOUND.search(line)
        if pf_match and current_url:
            for p in pf_match.group(1).split(","):
                p = p.strip()
                if p:
                    params[current_url].add(p)

    return {url: sorted(p) for url, p in params.items() if p}


def discover_params(endpoints, verbose=False):
    """Run arjun on all dynamic endpoints and aggregate parameter results."""
    all_params = {}
    total = len(endpoints)

    for i, endpoint in enumerate(endpoints, 1):
        log_info(f"Parameter discovery [{i}/{total}]: {endpoint}")
        try:
            result = run_arjun(endpoint, verbose=verbose)
            all_params.update(result)
            if result:
                for url, p_list in result.items():
                    log_success(
                        f"Found {len(p_list)} param(s) on {url}: "
                        f"{', '.join(p_list)}"
                    )
            else:
                log_info(f"No parameters found on {endpoint}")
        except Exception as e:
            log_error(f"Error running arjun on {endpoint}: {e}")

    return all_params


# =============================================================================
# Phase 4.5: Vulnerability Probing (raw response logging)
# =============================================================================


def _advisory_match(payload_str, status, body_snippet, regex_pattern):
    """
    Check if a response looks interesting based on the advisory regex.
    Returns True if the pattern matches the payload or body snippet.
    This is purely informational — the user decides what is a vuln.
    """
    try:
        combined = f"{payload_str} {body_snippet}"
        return bool(re.search(regex_pattern, combined, re.IGNORECASE))
    except re.error:
        return False


def _write_probe_header(probe_file, target_url, probe_type, param,
                        wordlist, probe_url):
    """Write a section header for one probe into the probe results file."""
    config = PROBE_CONFIG[probe_type]
    wl_name = os.path.basename(wordlist)
    sep = "-" * 80
    header = (
        f"\n{sep}\n"
        f"PROBE   : {config['description']}\n"
        f"URL     : {probe_url}\n"
        f"PARAM   : {param}\n"
        f"WORDLIST: {wl_name}\n"
        f"TIME    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{sep}\n"
        f"{'STATUS':<8} {'SIZE':<8} {'WORDS':<7} {'LINES':<7} PAYLOAD\n"
        f"{'-'*8} {'-'*8} {'-'*7} {'-'*7} {'-'*40}\n"
    )
    with open(probe_file, "a") as f:
        f.write(header)


def _write_probe_row(probe_file, status, size, words, lines, payload,
                     advisory=False, body_snippet=""):
    """Append a single response row to the probe results file."""
    flag = "  <-- ⚠ REGEX ADVISORY" if advisory else ""
    row = (
        f"{status:<8} {size:<8} {words:<7} {lines:<7} "
        f"{payload}{flag}\n"
    )
    if body_snippet:
        # Clean up snippet for single-line display
        clean_snippet = body_snippet.replace('\n', ' ').replace('\r', '')
        row += f"  BODY: {clean_snippet}\n"

    with open(probe_file, "a") as f:
        f.write(row)


def _write_probe_footer(probe_file, total, advisory_count):
    """Write a summary footer after a probe section."""
    footer = (
        f"\nTotal responses (non-baseline): {total}\n"
        f"Advisory regex matches         : {advisory_count}\n"
        f"  (advisory matches are hints only — review manually)\n"
    )
    with open(probe_file, "a") as f:
        f.write(footer)

def run_ffuf_probe(url, param, probe_type, probe_file=None, verbose=False,
                   method="GET", threads=10, rate=None):
    """
    Probe a single parameter with one vuln-class wordlist using specified HTTP method (GET or POST).

    ffuf runs WITHOUT -mr so every non-baseline response is captured.
    All results (status, size, words, payload) are:
      - Printed to the terminal in a clean columnar table.
      - Appended to probe_file so the user has a full readable record.

    The advisory regex is checked per-row and flagged with ⚠ but it does
    NOT filter or decide — the user reviews the table and decides.

    threads/rate: lower both for fragile targets (--gentle mode).
    """
    config = PROBE_CONFIG.get(probe_type)
    if not config:
        return None

    wordlist = find_wordlist(config["wordlist_key"])
    if not wordlist:
        log_warn(
            f"Wordlist for {config['description']} not found: "
            f"{WORDLISTS.get(config['wordlist_key'], '?')}"
        )
        return None

    wl_name = os.path.basename(wordlist)

    if method.upper() == "POST":
        probe_url = url
        post_data = f"{param}=FUZZ"
        report_cmd = (
            f'ffuf -u "{probe_url}" -X POST -d "{post_data}" -H "Content-Type: application/x-www-form-urlencoded" '
            f"-w {wordlist} -ac -t 10 -timeout 5"
        )
    else:
        probe_url = f"{url}{url_sep(url)}{param}=FUZZ"
        post_data = None
        report_cmd = (
            f'ffuf -u "{probe_url}" -w {wordlist} '
            f"-ac -t 10 -timeout 5"
        )

    # Use a temp directory for ffuf -od to dump response bodies
    tmp_dir = tempfile.mkdtemp(prefix=f"probe_{probe_type}_")
    tmp_json = os.path.join(tmp_dir, "out.json")

    # ── ffuf command ────────────────────────────────────────────────────
    cmd = [
        "ffuf",
        "-u",    probe_url,
        "-w",    wordlist,
        "-ac",                   # auto-calibrate to drop identical baselines
        "-t",    str(threads),
        "-timeout", "5",
        "-od",   tmp_dir,        # dump bodies
        "-o",    tmp_json,
        "-of",   "json",
        "-noninteractive",
        "-s",
    ]
    if rate:
        cmd += ["-rate", str(rate)]

    if method.upper() == "POST":
        cmd.extend([
            "-X", "POST",
            "-d", post_data,
            "-H", "Content-Type: application/x-www-form-urlencoded",
        ])

    log_info(
        f"  [{config['description']}] "
        f"param={BOLD}{param}{RESET}  "
        f"wordlist={CYAN}{wl_name}{RESET}"
    )
    if verbose:
        log_info(f"  cmd: {' '.join(cmd)}")

    run_subprocess(cmd, timeout=120, verbose=False)

    # ── Parse ALL results ───────────────────────────────────────────────
    all_results    = []
    advisory_hits  = []

    try:
        if os.path.isfile(tmp_json) and os.path.getsize(tmp_json) > 0:
            with open(tmp_json, "r") as f:
                data = json.load(f)
            for r in data.get("results", []):
                snippet = ""
                resultfile = r.get("resultfile")
                if resultfile:
                    dump_path = os.path.join(tmp_dir, resultfile)
                    if os.path.isfile(dump_path):
                        with open(dump_path, "r", errors="ignore") as df:
                            snippet = df.read(300)

                row = {
                    "payload":      r.get("input", {}).get("FUZZ", ""),
                    "status":       r.get("status",  0),
                    "length":       r.get("length",  0),
                    "words":        r.get("words",   0),
                    "lines":        r.get("lines",   0),
                    "body_snippet": snippet,
                }
                all_results.append(row)
    except (json.JSONDecodeError, FileNotFoundError):
        pass

    # Cleanup temp directory
    try:
        shutil.rmtree(tmp_dir)
    except OSError:
        pass

    # ── Advisory regex check (highlight only, not filter) ───────────────
    advisory_regex = config.get("match_regex", "")
    for row in all_results:
        if advisory_regex and _advisory_match(
            row["payload"], row["status"], row["body_snippet"], advisory_regex
        ):
            row["advisory"] = True
            advisory_hits.append(row)
        else:
            row["advisory"] = False

    # ── Terminal output ─────────────────────────────────────────────────
    if all_results:
        # Column header
        print(
            f"\n  {BOLD}{'STATUS':<8} {'SIZE':<8} {'WORDS':<7} {'LINES':<7} PAYLOAD{RESET}"
        )
        print(f"  {'-'*8} {'-'*8} {'-'*7} {'-'*7} {'-'*40}")
        for row in all_results:
            flag   = f"  {YELLOW}⚠ advisory{RESET}" if row["advisory"] else ""
            color  = YELLOW if row["advisory"] else ""
            creset = RESET  if row["advisory"] else ""
            print(
                f"  {color}"
                f"{row['status']:<8} "
                f"{row['length']:<8} "
                f"{row['words']:<7} "
                f"{row['lines']:<7} "
                f"{row['payload']}"
                f"{creset}{flag}"
            )
        print()
        log_info(
            f"  {len(all_results)} response(s) captured, "
            f"{len(advisory_hits)} advisory match(es)  "
            f"→ see probe results file for full log"
        )
    else:
        log_info(f"  No non-baseline responses (all filtered by auto-calibrate)")

    # ── Write to probe results file ─────────────────────────────────────
    if probe_file:
        _write_probe_header(
            probe_file, url, probe_type, param, wordlist, probe_url
        )
        for row in all_results:
            _write_probe_row(
                probe_file,
                row["status"], row["length"], row["words"], row["lines"],
                row["payload"], advisory=row["advisory"],
                body_snippet=row["body_snippet"]
            )
        if not all_results:
            with open(probe_file, "a") as f:
                f.write("(no non-baseline responses — all calibrated out)\n")
        _write_probe_footer(probe_file, len(all_results), len(advisory_hits))

    return {
        "probe_type":   probe_type,
        "description":  config["description"],
        "param":        param,
        "wordlist":     wordlist,
        "results":      all_results,       # ALL responses, not just regex hits
        "advisory_hits": advisory_hits,    # regex-flagged subset (advisory)
        "ffuf_cmd":     report_cmd,
    }


def probe_all_params(params_by_url, probe_file, verbose=False,
                     threads=10, rate=None):
    """
    Probe all discovered parameters on all endpoints for LFI/SQLi/CMDi.

    Writes a running probe_results.txt as each check completes so the
    user can open it in a text editor and review while the scan runs.

    Args:
        params_by_url : {url: [param1, param2, ...]}
        probe_file    : absolute path to the output text file
        threads/rate  : ffuf concurrency/rate (lower for fragile targets)

    Returns:
        {url: {param: [probe_result_dicts]}}
    """
    all_results  = {}
    total_params = sum(len(p) for p in params_by_url.values())
    count        = 0

    # Write file header once
    with open(probe_file, "w") as f:
        f.write(
            "=" * 80 + "\n"
            "Web Recon — Vulnerability Probe Results\n"
            f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Targets   : {', '.join(params_by_url.keys())}\n"
            "=" * 80 + "\n"
            "\n"
            "Each section shows ALL non-baseline responses for one probe.\n"
            "STATUS  = HTTP response code\n"
            "SIZE    = response body size in bytes\n"
            "WORDS   = word count in response body\n"
            "LINES   = line count in response body\n"
            "⚠ REGEX ADVISORY = payload matched the advisory hint regex\n"
            "  (advisory matches are hints only — YOU decide what is a vuln)\n"
            "\n"
        )

    for url, param_list in params_by_url.items():
        all_results[url] = {}
        for param in param_list:
            count += 1
            log_info(
                f"Probing [{count}/{total_params}]: "
                f"{BOLD}{param}{RESET} on {url} (GET & POST)"
            )
            results = []
            for method in ("GET", "POST"):
                for probe_type in PROBE_CONFIG:
                    result = run_ffuf_probe(
                        url, param, probe_type,
                        probe_file=probe_file,
                        verbose=verbose,
                        method=method,
                        threads=threads,
                        rate=rate,
                    )
                    if result is not None:
                        results.append(result)
            all_results[url][param] = results

    return all_results


def probe_dir_traversal(endpoints, probe_file, verbose=False, threads=10):
    """
    Probe all discovered directory endpoints with top 20 LFI/Directory Traversal
    payloads directly against the URL path (both appended to path and under common params).

    Quickly rules out direct path-based directory traversal on every directory.
    """
    log_info("Running Quick Directory Traversal Triage (Top 20 payloads)")
    hits = []
    lfi_config = PROBE_CONFIG["lfi"]
    match_regex = lfi_config["match_regex"]

    with tempfile.NamedTemporaryFile("w", delete=False, suffix="_lfi20.txt") as tf:
        tf.write("\n".join(TOP_20_LFI_PAYLOADS) + "\n")
        tmp_wl = tf.name

    try:
        for ep in endpoints:
            base = ep.rstrip("/")
            # Test direct path traversal (e.g. http://target/dir/FUZZ)
            # and common LFI parameters (file, page, path, view)
            test_urls = [
                f"{base}/FUZZ",
                f"{base}/?file=FUZZ",
                f"{base}/?page=FUZZ",
                f"{base}/?path=FUZZ",
            ]
            for test_url in test_urls:
                cmd = [
                    "ffuf",
                    "-u", test_url,
                    "-w", tmp_wl,
                    "-ac",
                    "-t", str(threads),
                    "-timeout", "5",
                    "-mr", match_regex,
                    "-of", "json",
                    "-noninteractive",
                    "-s",
                ]
                tmp_json = tempfile.mktemp(suffix="_lfi.json")
                cmd.extend(["-o", tmp_json])

                stdout, stderr, rc = run_subprocess(cmd, timeout=30, verbose=verbose)
                if os.path.exists(tmp_json):
                    try:
                        with open(tmp_json, "r") as f:
                            d = json.load(f)
                        for r in d.get("results", []):
                            hit_info = {
                                "endpoint": ep,
                                "test_url": test_url,
                                "payload": r.get("input", {}).get("FUZZ", ""),
                                "status": r.get("status", 0),
                                "length": r.get("length", 0),
                            }
                            hits.append(hit_info)
                            log_vuln(
                                f"DIRECTORY TRAVERSAL HIT on {test_url} "
                                f"payload=`{hit_info['payload']}` status={hit_info['status']} size={hit_info['length']}"
                            )
                        os.remove(tmp_json)
                    except Exception:
                        pass
    finally:
        if os.path.exists(tmp_wl):
            os.remove(tmp_wl)

    return hits


# =============================================================================
# Phase 4: Report Generation
# =============================================================================

def generate_curl_probes(url, param):
    """Generate curl probe commands for a single parameter (GET and POST)."""
    sep = url_sep(url)
    lines = []

    lines.append("# LFI / Path Traversal (GET & POST)")
    lines.append(f'curl -sk "{url}{sep}{param}=../../../../etc/passwd"')
    lines.append(f'curl -sk -X POST -d "{param}=../../../../etc/passwd" "{url}"')
    lines.append(f'curl -sk "{url}{sep}{param}=....//....//....//....//etc/passwd"')
    lines.append(
        f'curl -sk "{url}{sep}{param}='
        f'php://filter/convert.base64-encode/resource=index.php"'
    )
    lines.append("")
    lines.append("# SQLi Detection (GET & POST)")
    lines.append(f"curl -sk \"{url}{sep}{param}=1'\"")
    lines.append(f'curl -sk -X POST -d "{param}=1\'" "{url}"')
    lines.append(f'curl -sk "{url}{sep}{param}=1 OR 1=1-- -"')
    lines.append(f'curl -sk -X POST -d "{param}=1 OR 1=1-- -" "{url}"')
    lines.append("")
    lines.append("# Command Injection (GET & POST)")
    lines.append(f'curl -sk "{url}{sep}{param}=;id"')
    lines.append(f'curl -sk -X POST -d "{param}=;id" "{url}"')
    lines.append(f'curl -sk "{url}{sep}{param}=|whoami"')

    return lines


def generate_ffuf_probe_commands(url, param):
    """Generate ffuf -mr probe commands with SecLists wordlist paths (GET & POST)."""
    sep = url_sep(url)
    lines = []

    for probe_type, config in PROBE_CONFIG.items():
        wl_path = WORDLISTS.get(config["wordlist_key"], "WORDLIST_NOT_FOUND")
        wl_name = os.path.basename(wl_path)
        lines.append(f"# {config['description']} fuzzing with {wl_name} (GET)")
        lines.append(
            f'ffuf -u "{url}{sep}{param}=FUZZ" '
            f"-w {wl_path} "
            f'-mr "{config["match_regex"]}" '
            f"-ac -t 10 -timeout 5"
        )
        lines.append(f"# {config['description']} fuzzing with {wl_name} (POST)")
        lines.append(
            f'ffuf -u "{url}" -X POST -d "{param}=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" '
            f"-w {wl_path} "
            f'-mr "{config["match_regex"]}" '
            f"-ac -t 10 -timeout 5"
        )
        lines.append("")

    return lines


def generate_burp_request(url, param, payload="PAYLOAD_HERE"):
    """Generate Burp Suite Repeater raw HTTP request blocks (GET & POST)."""
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    port = parsed.port
    path = parsed.path or "/"
    sep = url_sep(url)

    host_header = host
    if port and port not in (80, 443):
        host_header = f"{host}:{port}"

    get_req = (
        f"GET {path}{sep}{param}={payload} HTTP/1.1\n"
        f"Host: {host_header}\n"
        f"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\n"
        f"Accept: */*\n"
        f"Connection: close"
    )

    post_body = f"{param}={payload}"
    post_req = (
        f"POST {path} HTTP/1.1\n"
        f"Host: {host_header}\n"
        f"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\n"
        f"Content-Type: application/x-www-form-urlencoded\n"
        f"Content-Length: {len(post_body)}\n"
        f"Connection: close\n\n"
        f"{post_body}"
    )

    return f"--- GET Request ---\n{get_req}\n\n--- POST Request ---\n{post_req}"


def generate_dir_fuzz_commands(endpoint):
    """Recursive deeper-directory ffuf command for one discovered directory."""
    base = endpoint.rstrip("/")
    wl = WORDLISTS["dir_primary"]
    return [
        f"# Recursively fuzz deeper inside {base}/",
        f'ffuf -u "{base}/FUZZ" -w {wl} -ac -recursion -recursion-depth 2 '
        f"-t 40 -timeout 10",
    ]


def generate_vhost_command(target_url):
    """Host-header / virtual-host discovery command for the target host."""
    parsed = urlparse(target_url)
    host = parsed.hostname or "TARGET"
    root = target_url.rstrip("/")
    wl = WORDLISTS["vhost"]
    return [
        "# Virtual-host / Host-header fuzzing (name-based vhosts)",
        f'ffuf -u "{root}/" -H "Host: FUZZ.{host}" -w {wl} -ac -t 40 -timeout 10',
        "# If every response looks identical, filter the baseline size: add -fs <bytes>",
    ]


def _probe_indicator_lines(probe_results, title, blurb):
    """
    Render one probe-results bucket to Markdown lines.
    Returns (lines, found_any_advisory).

    Advisory hits (regex-flagged) are shown as strong indicators; plain
    differential responses (non-baseline, no regex match) are shown as
    manual-review candidates — never silently dropped.
    """
    lines = [title, "", blurb, ""]
    found = False
    for p_url, param_probes in probe_results.items():
        parsed_path = urlparse(p_url).path or "/"
        for param, probes in param_probes.items():
            lines.append(f"### {parsed_path} — `{param}` parameter")
            lines.append("")
            has_hits = False
            for probe in probes:
                hits = probe.get("results")
                if hits is None:
                    hits = [
                        {"payload": h.get("payload"), "status": h.get("status"),
                         "length": h.get("length"), "advisory": True}
                        for h in probe.get("advisory_hits", [])
                    ]
                if not hits:
                    continue
                has_hits = True
                wl_name = os.path.basename(probe.get("wordlist", ""))
                advisory = [h for h in hits if h.get("advisory")]
                if advisory:
                    found = True
                    lines.append("| Vuln Type | Payload | Status | Size | Wordlist |")
                    lines.append("|-----------|---------|--------|------|----------|")
                    for hit in advisory:
                        lines.append(
                            f"| **[!] {probe['description']}** "
                            f"| `{hit['payload']}` | {hit['status']} "
                            f"| {hit['length']} | {wl_name} |"
                        )
                else:
                    shown = hits[:5]
                    lines.append(
                        "> **Differential candidate** — "
                        f"{len(hits)} non-baseline response(s) "
                        "(no advisory regex match — review manually)."
                    )
                    lines.append("")
                    lines.append("| Payload | Status | Size |")
                    lines.append("|---------|--------|------|")
                    for hit in shown:
                        lines.append(
                            f"| `{hit['payload']}` | {hit['status']} "
                            f"| {hit['length']} |"
                        )
                    if len(hits) > len(shown):
                        lines.append(
                            f"| *... and {len(hits) - len(shown)} more* | | |"
                        )
                lines.append("")
                lines.append("Command used:")
                lines.append("```bash")
                lines.append(probe.get("ffuf_cmd", ""))
                lines.append("```")
                lines.append("")
            if not has_hits:
                lines.append("*No indicators found.*")
                lines.append("")
    lines.append("---")
    lines.append("")
    return lines, found


def write_recon_summary(target_url, scan_results, output_path):
    """
    Write the final Markdown recon summary report.
    Returns True if potential vulnerabilities were flagged.
    """
    lines = []
    has_vulns = False

    # ── Header ──────────────────────────────────────────────────────────
    lines.append(f"# Recon Summary: {target_url}")
    lines.append("")
    lines.append(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if scan_results.get("whatweb_raw"):
        lines.append(f"**Tech Detected:** {scan_results['whatweb_raw']}")
    lines.append(f"**Tech Preset:** {scan_results.get('preset', 'unknown')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Phase 0.5: Quick-Win Pre-Checks ─────────────────────────────────
    quick_hits = scan_results.get("quick_hits", [])
    if quick_hits:
        lines.append("## Phase 0.5: Quick-Win Pre-Checks")
        lines.append("")
        lines.append("| Status | URL | Snippet |")
        lines.append("|--------|-----|---------|")
        for h in quick_hits:
            status = h.get('status', '?')
            url = h.get('url', '?')
            snippet = h.get('snippet', '')[:50].replace('|', ' ') + "..."
            lines.append(f"| {status} | {url} | `{snippet}` |")
        lines.append("")
        lines.append("---")
        lines.append("")

    # ── Phase 1: Spidered Endpoints & On-Page Parameters ────────────────
    spider_endpoints = scan_results.get("spider_endpoints", [])
    spider_params = scan_results.get("spider_params_by_url", {})
    if spider_endpoints or spider_params:
        lines.append("## Phase 1: Spidered Endpoints & On-Page Parameters (katana)")
        lines.append("")
        if spider_endpoints:
            lines.append(f"**{len(spider_endpoints)} endpoint(s) crawled:**")
            lines.append("")
            for ep in spider_endpoints:
                lines.append(f"- {ep}")
            lines.append("")
        if spider_params:
            lines.append("**On-page parameters (probed separately below):**")
            lines.append("")
            for p_url, p_list in spider_params.items():
                parsed_path = urlparse(p_url).path or "/"
                lines.append(f"- `{parsed_path}` → {', '.join(f'`{p}`' for p in p_list)}")
            lines.append("")
        lines.append("---")
        lines.append("")

    # ── Phase 3: Directory Brute Force ──────────────────────────────────
    lines.append("## Phase 3: Directory Brute Force (ffuf)")
    lines.append("")

    ffuf_results = scan_results.get("ffuf_results", [])
    dynamic_endpoints = scan_results.get("dynamic_endpoints", [])
    static_filtered = scan_results.get("static_filtered_count", 0)

    if ffuf_results:
        api_roots = [r for r in ffuf_results if r.get("status") >= 500]
        regular = [r for r in ffuf_results if r.get("status") < 500]

        if api_roots:
            lines.append("### ⚠️ Potential API Roots / Error Routers (500+ Status)")
            lines.append(
                "> *These endpoints returned server errors, often indicating "
                "missing sub-paths or parameters. Probe sub-paths manually.*"
            )
            lines.append("")
            lines.append("| Status | Size | URL |")
            lines.append("|--------|------|-----|")
            for r in api_roots:
                lines.append(f"| {r.get('status', '?')} | {r.get('length', '?')} | {r.get('url', '?')} |")
            lines.append("")

        if regular:
            lines.append("### Discovered Endpoints")
            lines.append("")
            lines.append("| Status | Size | URL |")
            lines.append("|--------|------|-----|")
            for r in regular:
                lines.append(
                    f"| {r.get('status', '?')} "
                    f"| {r.get('length', '?')} "
                    f"| {r.get('url', '?')} |"
                )
            lines.append("")

        lines.append(
            f"**Total found:** {len(ffuf_results)} endpoints "
            f"({len(dynamic_endpoints)} sent to arjun, {static_filtered} static filtered)"
        )
    else:
        lines.append("*No endpoints discovered.*")

    lines.append("")
    lines.append("---")
    lines.append("")

    # ── Phase 3.6: API Route Discovery ──────────────────────────────────
    api_endpoints = scan_results.get("api_endpoints", [])
    if api_endpoints:
        lines.append("## Phase 3.6: API Route Discovery")
        lines.append("")
        lines.append(
            "> Fuzzed under the discovered API base(s) with the API wordlist."
        )
        lines.append("")
        lines.append("| Status | Size | URL |")
        lines.append("|--------|------|-----|")
        for h in api_endpoints:
            lines.append(
                f"| {h.get('status', '?')} | {h.get('length', '?')} "
                f"| {h.get('url', '?')} |"
            )
        lines.append("")
        lines.append("---")
        lines.append("")

    # ── Phase 2.5: FTP Auto-Listing ─────────────────────────────────────
    ftp_data = scan_results.get("ftp_listing")
    if ftp_data:
        lines.append(f"## Phase 2.5: FTP Auto-Listing ({ftp_data['url']})")
        lines.append("")
        lines.append("```html")
        # Keep snippet manageable
        lines.append(ftp_data['content'][:1000].strip())
        if len(ftp_data['content']) > 1000:
            lines.append("\n... (truncated)")
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    # ── Phase 3.5: Directory Traversal Quick Triage ──────────────────────
    dir_lfi_hits = scan_results.get("dir_lfi_hits", [])
    if dir_lfi_hits:
        has_vulns = True
        lines.append("## Phase 3.5: Quick Directory Traversal Triage ⚠️")
        lines.append("")
        lines.append("| Target Endpoint | Test URL / Parameter | Payload | Status | Size |")
        lines.append("|-----------------|----------------------|---------|--------|------|")
        for hit in dir_lfi_hits:
            lines.append(
                f"| {hit['endpoint']} | `{hit['test_url']}` | `{hit['payload']}` | {hit['status']} | {hit['length']} |"
            )
        lines.append("")
        lines.append("---")
        lines.append("")

    # ── Phase 3: Parameter Discovery ────────────────────────────────────
    params_by_url = scan_results.get("params_by_url", {})
    lines.append("## Phase 4: Parameter Discovery (arjun)")
    lines.append("")

    if params_by_url:
        for p_url, p_list in params_by_url.items():
            parsed_path = urlparse(p_url).path or "/"
            lines.append(f"### {parsed_path}")
            for p in p_list:
                lines.append(f"- `{p}`")
            lines.append("")
    else:
        lines.append(
            "*No parameters discovered by arjun "
            "(no dynamic endpoints from brute force).*"
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    # ── On-Page Parameter Indicators (spidered params, probed separately) ─
    spider_probe_results = scan_results.get("spider_probe_results", {})
    if spider_probe_results:
        spider_lines, spider_found = _probe_indicator_lines(
            spider_probe_results,
            "## On-Page Parameter Vulnerability Indicators ⚠️",
            "> Parameters found on the page by the katana spider, probed via "
            "`ffuf` with SecLists wordlists (separate from arjun results).",
        )
        lines.extend(spider_lines)
        has_vulns = has_vulns or spider_found

    # ── Phase 4.5: Vulnerability Indicators (arjun-discovered params) ────
    probe_results = scan_results.get("probe_results", {})
    if probe_results:
        arjun_lines, arjun_found = _probe_indicator_lines(
            probe_results,
            "## Phase 4.5: Vulnerability Indicators ⚠️",
            "> Parameters automatically probed via `ffuf -mr` "
            "using SecLists wordlists",
        )
        lines.extend(arjun_lines)
        has_vulns = has_vulns or arjun_found

    # ── Phase 4: Manual Verification Commands ───────────────────────────
    lines.append("## Phase 4: Manual Verification Commands")
    lines.append("")

    if params_by_url:
        for p_url, p_list in params_by_url.items():
            parsed_path = urlparse(p_url).path or "/"
            for param in p_list:
                # Check for vulnerability tag
                vuln_tag = ""
                diff_tag = ""
                if probe_results.get(p_url, {}).get(param):
                    for probe in probe_results[p_url][param]:
                        if probe.get("advisory_hits"):
                            vuln_tag = (
                                f" ⚠️ LIKELY VULNERABLE ({probe['description']})"
                            )
                            break
                    if not vuln_tag and any(
                        p.get("results") for p in probe_results[p_url][param]
                    ):
                        diff_tag = " 🧪 DIFFERENTIAL CANDIDATE (review manually)"

                lines.append(
                    f"### {parsed_path} — `{param}` parameter{vuln_tag}{diff_tag}"
                )
                lines.append("")

                # curl commands
                lines.append("#### curl probe commands")
                lines.append("```bash")
                for cmd_line in generate_curl_probes(p_url, param):
                    lines.append(cmd_line)
                lines.append("```")
                lines.append("")

                # ffuf commands with SecLists wordlists
                lines.append(
                    "#### ffuf probe commands (with SecLists wordlists)"
                )
                lines.append("```bash")
                for cmd_line in generate_ffuf_probe_commands(p_url, param):
                    lines.append(cmd_line)
                lines.append("```")
                lines.append("")

                # Burp Repeater request
                lines.append("#### Burp Repeater Request")
                lines.append("```http")
                lines.append(generate_burp_request(p_url, param))
                lines.append("```")
                lines.append("")
    else:
        lines.append(
            "*No parameters discovered — "
            "no verification commands to generate.*"
        )

    # ── Additional Manual Fuzzing: per-directory recursion + vhost ──────
    all_dirs = scan_results.get("all_dirs", [])
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Additional Manual Fuzzing Commands")
    lines.append("")

    # One vhost / Host-header block per target host.
    lines.append("### Virtual-host / Host-header discovery")
    lines.append("```bash")
    lines.extend(generate_vhost_command(target_url))
    lines.append("```")
    lines.append("")

    if all_dirs:
        lines.append("### Recursive deeper-directory fuzzing (per directory)")
        lines.append("")
        for ep in all_dirs:
            parsed_path = urlparse(ep).path or "/"
            lines.append(f"#### {parsed_path}")
            lines.append("```bash")
            lines.extend(generate_dir_fuzz_commands(ep))
            lines.append("```")
            lines.append("")

    # Write the report atomically
    dir_name = os.path.dirname(output_path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".recon_", suffix=".tmp")
    with open(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(tmp_path, output_path)

    log_success(f"Recon summary written to: {output_path}")
    return has_vulns


def print_cli_summary(target_url, scan_results):
    """Print a colorized CLI summary of scan results."""
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  SCAN COMPLETE: {target_url}{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}\n")

    ffuf_results  = scan_results.get("ffuf_results", [])
    dynamic       = scan_results.get("dynamic_endpoints", [])
    params        = scan_results.get("params_by_url", {})
    probe_results = scan_results.get("probe_results", {})
    probe_file    = scan_results.get("probe_file", "")

    total_params   = sum(len(p) for p in params.values())

    print(f"  {CYAN}Endpoints discovered:{RESET}    {len(ffuf_results)}")
    print(f"  {CYAN}Dynamic endpoints:{RESET}       {len(dynamic)}")
    print(f"  {CYAN}Parameters found:{RESET}        {total_params}")

    # Count advisory-flagged responses (hints, not decisions)
    advisory_count   = 0
    advisory_details = []
    for p_url, param_probes in probe_results.items():
        for param, probes in param_probes.items():
            for probe in probes:
                hits = probe.get("advisory_hits", [])
                if hits:
                    advisory_count += len(hits)
                    advisory_details.append(
                        f"    {YELLOW}⚠  {param} → {probe['description']} "
                        f"({len(hits)} advisory match(es)){RESET}"
                    )

    if advisory_count > 0:
        print(
            f"  {YELLOW}Advisory matches:{RESET}        "
            f"{YELLOW}{advisory_count}{RESET} "
            f"(review probe results file)"
        )
        for detail in advisory_details:
            print(detail)
    else:
        print(f"  {CYAN}Advisory matches:{RESET}        0")

    if probe_file and os.path.isfile(probe_file):
        print(f"\n  {GREEN}Probe results file:{RESET} {probe_file}")

    print()


# =============================================================================
# Pipeline Orchestration
# =============================================================================

def scan_target(url, args):
    """
    Execute the full recon pipeline against a single target.

    Phases:
      0.   whatweb tech detection
      0.5. quick-win pre-checks
      1.   katana spider (+ robots.txt) → endpoints & on-page params
      2.   probe spidered findings for vulns (dir-traversal + on-page params)
      3.   ffuf directory brute force → 3.5 static-asset filtering
      4.   arjun parameter discovery (spider + brute endpoints)
      5.   ffuf vulnerability probing on arjun params
      6.   report generation

    Each phase is wrapped in run_phase() so one failing tool degrades to a
    partial report instead of aborting the whole target.
    """
    scan_results = {
        "target_url": url,
        "preset": "all",
        "whatweb_raw": "",
        "spider_endpoints": [],
        "spider_params_by_url": {},
        "spider_probe_results": {},
        "ffuf_results": [],
        "dynamic_endpoints": [],
        "static_filtered_count": 0,
        "params_by_url": {},
        "probe_results": {},
        "all_dirs": [],
    }

    output_dir = args.output_dir or "./recon_output"
    os.makedirs(output_dir, exist_ok=True)
    verbose = args.verbose
    safe_name = sanitize_filename(url)

    # ── Phase 0: Tech Detection ─────────────────────────────────────────
    preset = args.tech
    if not preset:
        log_phase("Phase 0: Technology Detection (whatweb)")
        whatweb_result = run_phase(
            "whatweb", lambda: run_whatweb(url, verbose=verbose),
            default={"raw": ""},
        )
        raw_output = whatweb_result.get("raw", "")
        scan_results["whatweb_raw"] = raw_output
        # Always print raw whatweb output — useful even when the preset
        # can't be determined (X-Powered-By, cookies, etc.)
        if raw_output:
            log_success("whatweb output:")
            print(f"  {CYAN}{raw_output}{RESET}")
        else:
            log_warn("whatweb returned no output")
        preset = detect_tech_preset(whatweb_result)
    else:
        log_info(f"Using manually specified tech preset: {preset}")

    scan_results["preset"] = preset

    # ── Phase 0.5: Quick-Win Pre-Checks ────────────────────────────────
    quick_hits = []
    if not args.skip_quick_checks:
        log_phase("Phase 0.5: Quick-Win Pre-Checks")
        quick_hits = run_quick_checks(url, verbose=verbose)
        scan_results["quick_hits"] = quick_hits
        if quick_hits:
            log_success(
                f"Quick checks: {len(quick_hits)} interesting path(s) found "
                f"(non-404)"
            )
            api_docs = [h for h in quick_hits
                        if h["path"] in ("/api-docs", "/swagger.json",
                                         "/openapi.json")]
            if api_docs:
                log_vuln(
                    f"API documentation exposed at {api_docs[0]['url']} — "
                    "contains full route map! Review it before fuzzing."
                )
        else:
            log_info("No quick-win paths found (all 404)")
    else:
        log_info("Quick-win pre-checks skipped (--skip-quick-checks)")

    # ── Phase 1: Site Spidering (katana) + robots.txt ──────────────────
    spider_endpoints, spider_params = [], {}
    if not args.skip_spider:
        log_phase("Phase 1: Site Spidering (katana)")
        headless = args.headless
        if headless is None:
            headless = auto_detect_headless()
            log_info(
                f"Headless crawl: {'ON' if headless else 'OFF'} "
                f"({'Chromium detected' if headless else 'no Chromium found'})"
            )
        elif headless and not auto_detect_headless():
            log_warn(
                "--headless forced but no Chrome/Chromium found — "
                "katana may error or fall back"
            )
        spider_endpoints, spider_params = run_phase(
            "katana spider",
            lambda: run_katana(
                url, depth=args.depth, headless=headless, verbose=verbose,
                concurrency=(
                    GENTLE_KATANA_CONCURRENCY if args.gentle else 15
                ),
            ),
            default=([], {}),
        )
        # Fold in paths advertised by robots.txt Disallow (e.g. /ftp).
        robots_urls = run_phase(
            "robots.txt parse",
            lambda: robots_disallow_urls(url, verbose=verbose),
            default=[],
        )
        spider_endpoints = list(dict.fromkeys(spider_endpoints + robots_urls))
        scan_results["spider_endpoints"] = spider_endpoints
        scan_results["spider_params_by_url"] = spider_params
        for ep in spider_endpoints:
            log_info(f"  → {ep}")
    else:
        log_info("Spidering skipped (--skip-spider)")

    # ── Phase 2: Probe everything discovered so far (BEFORE brute force) ─
    # Combine spidered endpoints + quick-check hits — these are the "easy"
    # findings; triage them for vulns first so quick wins surface early.
    discovered_dirs = filter_static_urls(list(dict.fromkeys(
        spider_endpoints + [h["url"] for h in quick_hits]
    )))

    if not args.no_probe and (discovered_dirs or spider_params):
        log_phase("Phase 2: Vulnerability Probing — Spidered Findings")
        probe_threads = GENTLE_PROBE_THREADS if args.gentle else 10
        probe_rate = GENTLE_PROBE_RATE if args.gentle else None

        # Phase 1.5: harvest POST form fields (username/password/email etc.)
        # that arjun would miss, so they get probed below like any param.
        if not args.no_form_harvest and discovered_dirs:
            form_params = run_phase(
                "form harvest",
                lambda: harvest_form_params(discovered_dirs, verbose=verbose),
                default={},
            )
            for f_url, fields in form_params.items():
                merged = set(spider_params.get(f_url, [])) | set(fields)
                spider_params[f_url] = sorted(merged)

        if discovered_dirs:
            scan_results["dir_lfi_hits"] = run_phase(
                "directory-traversal triage",
                lambda: probe_dir_traversal(
                    discovered_dirs, probe_file="", verbose=verbose,
                    threads=probe_threads),
                default=[],
            )

        if spider_params:
            spider_probe_file = os.path.join(
                output_dir, f"{safe_name}_spider_probe.txt"
            )
            log_info(f"On-page param probe file: {spider_probe_file}")
            scan_results["spider_probe_results"] = run_phase(
                "on-page param probing",
                lambda: probe_all_params(
                    spider_params, probe_file=spider_probe_file,
                    verbose=verbose, threads=probe_threads, rate=probe_rate),
                default={},
            )
            scan_results["spider_probe_file"] = spider_probe_file
    elif args.no_probe:
        log_info("Vulnerability probing disabled (--no-probe)")

    # ── Phase 3: Directory Brute Force (ffuf) ───────────────────────────
    ffuf_json_path = None
    expected_json = os.path.join(output_dir, f"{safe_name}_ffuf.json")

    if args.skip_dir_scan and os.path.isfile(expected_json):
        log_info(
            f"Skipping Phase 3 (--skip-dir-scan), using existing: {expected_json}"
        )
        ffuf_json_path = expected_json
    elif not check_alive_or_warn(url, "ffuf brute force", verbose):
        log_warn("Skipping ffuf brute force — target is down.")
    else:
        log_phase("Phase 3: Directory Brute Force (ffuf)")
        dir_timeout = args.timeout * 60
        log_info(
            f"ffuf subprocess timeout: {args.timeout} min "
            f"({dir_timeout}s) — increase with --timeout if needed"
        )
        ffuf_json_path = run_phase(
            "ffuf directory brute force",
            lambda: run_ffuf_dirscan(
                url, preset, output_dir,
                wordlist_override=args.wordlist,
                extra_flags=args.ffuf_flags,
                recursive=args.recursive,
                quick_mode=args.quick,
                verbose=verbose,
                timeout=dir_timeout,
                threads=(GENTLE_DIR_THREADS if args.gentle else None),
            ),
            default=None,
        )

    # ── Phase 3.5: Static Asset Filtering ───────────────────────────────
    if ffuf_json_path:
        log_phase("Phase 3.5: Static Asset Filtering")
        all_results = parse_ffuf_json(ffuf_json_path)
        scan_results["ffuf_results"] = all_results

        dynamic_results = filter_static_assets(all_results)
        scan_results["static_filtered_count"] = (
            len(all_results) - len(dynamic_results)
        )

        dynamic_endpoints = extract_dynamic_endpoints(dynamic_results)
        scan_results["dynamic_endpoints"] = dynamic_endpoints

        if dynamic_endpoints:
            log_success(
                f"Found {len(dynamic_endpoints)} dynamic endpoints to investigate"
            )
            for ep in dynamic_endpoints:
                log_info(f"  → {ep}")
        else:
            log_warn("No dynamic endpoints found after filtering")

        # ── 401/403 callout — auth-protected endpoints ──────────────
        auth_protected = [
            r for r in all_results if r.get("status") in (401, 403)
        ]
        if auth_protected:
            print()
            log_warn(
                f"{RED}{BOLD}{len(auth_protected)} AUTH-PROTECTED ENDPOINT(S) "
                f"FOUND — high priority targets:{RESET}"
            )
            for r in auth_protected:
                print(
                    f"  {RED}{BOLD}[{r.get('status')}]{RESET} "
                    f"{r.get('url', '?')}  (size={r.get('length','?')})"
                )
            scan_results["auth_protected"] = auth_protected

    # ── Phase 3.6: API Route Fuzzing (only if an API base was discovered) ─
    # Use RAW ffuf results (not the 500-filtered dynamic set): API bases like
    # /api and /rest answer with 500 on a bare GET, so they'd otherwise be lost.
    dynamic_endpoints = scan_results.get("dynamic_endpoints", [])
    raw_ffuf_urls = [r.get("url", "") for r in scan_results.get("ffuf_results", [])]
    api_endpoints = []
    api_bases = find_api_bases(
        spider_endpoints + dynamic_endpoints + raw_ffuf_urls, url
    )
    if api_bases and args.no_api_fuzz:
        log_info(f"API base(s) {', '.join(api_bases)} found but "
                 f"API fuzzing skipped (--no-api-fuzz)")
    elif api_bases and check_alive_or_warn(url, "API fuzz", verbose):
        log_phase("Phase 3.6: API Route Fuzzing")
        log_info(f"API base(s) discovered: {', '.join(api_bases)}")
        for base in api_bases:
            api_endpoints.extend(run_phase(
                f"API fuzz {base}",
                lambda b=base: run_api_fuzz(
                    b, output_dir, verbose=verbose,
                    threads=(GENTLE_API_THREADS if args.gentle else None)),
                default=[],
            ))
        scan_results["api_endpoints"] = api_endpoints
        log_success(f"API fuzzing found {len(api_endpoints)} route(s)")

    # Combined directory set (spider + brute + API), static-filtered — used for
    # arjun, FTP auto-listing, and manual-command generation.
    all_dirs = filter_static_urls(list(dict.fromkeys(
        spider_endpoints + dynamic_endpoints + [h["url"] for h in api_endpoints]
    )))
    scan_results["all_dirs"] = all_dirs

    # ── FTP directory auto-listing (from robots/spider or brute) ────────
    for ep in all_dirs:
        if urlparse(ep).path.rstrip("/").lower().endswith("/ftp"):
            print()
            log_phase("FTP Directory Auto-Listing")
            log_info(f"Fetching contents of {ep}...")
            out, _, _ = run_subprocess(
                ["curl", "-sk", "-L", ep], timeout=10, verbose=verbose
            )
            if out:
                scan_results["ftp_listing"] = {"url": ep, "content": out}
                log_success("FTP directory listed successfully")
                print(f"  {CYAN}{out[:500].strip()}...{RESET}")
            break

    # ── Phase 4: Parameter Discovery (arjun) ────────────────────────────
    # Runs on spider-discovered AND brute-forced endpoints. On SPAs the brute
    # force finds nothing (catch-all 200s), so the spidered /rest & /api routes
    # are where params actually live. Capped so a large crawl can't stall.
    arjun_targets = all_dirs[:MAX_ARJUN_ENDPOINTS]
    if len(all_dirs) > MAX_ARJUN_ENDPOINTS:
        log_warn(
            f"arjun limited to first {MAX_ARJUN_ENDPOINTS} of {len(all_dirs)} "
            f"endpoints (raise MAX_ARJUN_ENDPOINTS to cover more)"
        )
    if arjun_targets and not check_alive_or_warn(url, "arjun", verbose):
        log_warn("Skipping arjun parameter discovery — target is down.")
    elif arjun_targets:
        log_phase("Phase 4: Parameter Discovery (arjun)")
        params_by_url = run_phase(
            "arjun",
            lambda: discover_params(arjun_targets, verbose=verbose),
            default={},
        )
        scan_results["params_by_url"] = params_by_url
        if params_by_url:
            total = sum(len(p) for p in params_by_url.values())
            log_success(f"Total parameters discovered: {total}")
        else:
            log_warn("No parameters discovered by arjun")
    else:
        log_info("No endpoints to scan for parameters")

    # ── Form harvest pass #2: brute-forced endpoints (e.g. /admin/login) ──
    # arjun can't see POST form fields, so harvest them from every endpoint
    # that Phase 3/3.6 added and feed them into Phase 5 probing below.
    extra_form_params = {}
    if not args.no_probe and not args.no_form_harvest and dynamic_endpoints:
        new_targets = [u for u in dynamic_endpoints
                       if u not in discovered_dirs]
        if new_targets:
            log_info(
                f"Harvesting HTML form fields on {len(new_targets)} "
                f"brute-forced endpoint(s)..."
            )
            extra_form_params = run_phase(
                "form harvest (brute-forced endpoints)",
                lambda: harvest_form_params(new_targets, verbose=verbose),
                default={},
            )

    # ── Phase 5: Vulnerability Probing on arjun params ──────────────────
    params_by_url = scan_results.get("params_by_url", {})
    for f_url, fields in extra_form_params.items():
        params_by_url[f_url] = sorted(
            set(params_by_url.get(f_url, [])) | set(fields)
        )
    if params_by_url:
        scan_results["params_by_url"] = params_by_url
    if not args.no_probe and params_by_url:
        log_phase("Phase 5: Vulnerability Probing — arjun Params")
        for probe_type, config in PROBE_CONFIG.items():
            wl = find_wordlist(config["wordlist_key"])
            if wl:
                log_info(f"{config['description']}: {wl}")
            else:
                log_warn(
                    f"{config['description']}: wordlist not found at "
                    f"{WORDLISTS.get(config['wordlist_key'], '?')}"
                )
        probe_file = os.path.join(output_dir, f"{safe_name}_probe_results.txt")
        log_info(f"Probe results file: {probe_file}")
        log_info("(file updates live as each check completes — open it in a text editor)")
        scan_results["probe_results"] = run_phase(
            "arjun-param probing",
            lambda: probe_all_params(
                params_by_url, probe_file=probe_file, verbose=verbose,
                threads=(GENTLE_PROBE_THREADS if args.gentle else 10),
                rate=(GENTLE_PROBE_RATE if args.gentle else None)),
            default={},
        )
        scan_results["probe_file"] = probe_file

    # ── Phase 6: Report Generation ──────────────────────────────────────
    log_phase("Phase 6: Report Generation")

    report_path = os.path.join(output_dir, f"{safe_name}_recon.md")
    has_vulns = run_phase(
        "report generation",
        lambda: write_recon_summary(url, scan_results, report_path),
        default=False,
    )

    print_cli_summary(url, scan_results)

    if has_vulns:
        log_vuln(f"Potential vulnerabilities found! Review: {report_path}")

    return scan_results


def main():
    """Entry point: parse arguments and run the pipeline."""
    parser = argparse.ArgumentParser(
        description=(
            "Web Recon - Directory, Parameter & Vulnerability Discovery"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -u http://10.10.10.15/
  %(prog)s -u http://10.10.10.15/ --tech php
  %(prog)s -f targets.txt --threads 3
  %(prog)s -u http://10.10.10.15/ --skip-dir-scan
  %(prog)s -u http://10.10.10.15/ --no-probe
  %(prog)s -u http://10.10.10.15/ --ffuf-flags "-mc 200,301 -fs 0"
        """,
    )

    # Target input (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-u", "--url", help="Single target URL (e.g., http://10.10.10.15/)"
    )
    target_group.add_argument(
        "-f", "--file",
        help="File with target URLs (one per line)",
    )

    # Options
    parser.add_argument(
        "-o", "--output-dir", default="./recon_output",
        help="Output directory for raw tool output (default: ./recon_output)",
    )
    parser.add_argument(
        "--tech", choices=["php", "aspx", "java", "all"],
        help=(
            "Force tech preset for extensions "
            "(default: auto-detect via whatweb)"
        ),
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help=(
            "ffuf directory scan timeout in minutes (default: 30). "
            "Increase for large wordlists or slow targets. "
            "Recursion scans against remote hosts may need 60+."
        ),
    )
    parser.add_argument(
        "--threads", type=int, default=None,
        help=(
            "Max concurrent targets for -f mode "
            "(default: no limit)"
        ),
    )
    parser.add_argument(
        "--skip-dir-scan", action="store_true",
        help="Skip the ffuf brute force (Phase 3) if its JSON output already exists",
    )
    parser.add_argument(
        "--skip-quick-checks", action="store_true",
        help="Skip Phase 0.5 quick-win pre-checks (robots.txt, api-docs, etc.)",
    )
    parser.add_argument(
        "--skip-spider", action="store_true",
        help="Skip Phase 1 katana spidering of on-page endpoints/params",
    )
    parser.add_argument(
        "--depth", type=int, default=3,
        help="katana crawl depth (default: 3)",
    )
    parser.add_argument(
        "--headless", action="store_true", default=None,
        help=(
            "Force headless katana crawl (JS rendering via Chrome/Chromium). "
            "Default: auto — headless is used automatically when Chromium is "
            "detected on the system."
        ),
    )
    parser.add_argument(
        "--no-headless", action="store_false", dest="headless",
        help="Disable headless katana crawl even if Chromium is installed.",
    )
    parser.add_argument(
        "--recursive", action="store_true", default=True,
        help=(
            "Enable ffuf recursion (depth 2). ON by default — each discovered "
            "directory gets one deeper pass. Disable with --no-recursive."
        ),
    )
    parser.add_argument(
        "--no-recursive", action="store_false", dest="recursive",
        help="Disable ffuf recursion (depth 2)",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help=(
            "Quick triage mode. Uses small wordlist, 3 extensions max, "
            "and disables recursion. Finishes in ~2 mins."
        ),
    )
    parser.add_argument(
        "--gentle", action="store_true",
        help=(
            "Gentle mode for fragile single-container targets (e.g. Juice "
            "Shop): reduced ffuf/probe/katana concurrency + probe rate cap."
        ),
    )
    parser.add_argument(
        "--wordlist",
        help="Override default directory wordlist path",
    )
    parser.add_argument(
        "--ffuf-flags",
        help='Additional ffuf flags (e.g., "-mc 200,301 -fs 0")',
    )
    parser.add_argument(
        "--no-probe", action="store_true",
        help="Disable all vulnerability probing (Phases 2 & 5); discovery only",
    )
    parser.add_argument(
        "--no-form-harvest", action="store_true",
        help=(
            "Skip HTML form field harvesting (POST form params like "
            "username/password that arjun can't find)"
        ),
    )
    parser.add_argument(
        "--no-api-fuzz", action="store_true",
        help="Disable Phase 3.6 API route fuzzing (/api/FUZZ, /rest/FUZZ)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Extra verbose output (show full subprocess commands)",
    )

    args = parser.parse_args()

    # ── Banner ──────────────────────────────────────────────────────────
    print(f"""{CYAN}{BOLD}
██╗    ██╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║    ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}
{BOLD}  Web Recon - Directory, Parameter & Vulnerability Discovery{RESET}
{CYAN}  Discovery only. No automated exploitation.{RESET}
""")

    # ── Dependency Checks ───────────────────────────────────────────────
    log_phase("Dependency Check")

    tools = {
        "ffuf":    {"required": True, "install": "apt install ffuf"},
        "whatweb": {"required": True, "install": "apt install whatweb"},
        "arjun":   {"required": True, "install": "pip3 install arjun"},
        "katana":  {"required": True, "install": "apt install katana"},
        "curl":    {"required": True, "install": "apt install curl"},
    }

    all_ok = True
    for tool_name, info in tools.items():
        if check_tool(tool_name):
            log_success(f"{tool_name} found: {shutil.which(tool_name)}")
        elif info["required"]:
            log_error(
                f"{tool_name} NOT FOUND (required). "
                f"Install: {info['install']}"
            )
            all_ok = False
        else:
            log_warn(
                f"{tool_name} not found (optional). "
                f"Install: {info['install']}"
            )

    # Check directory wordlist
    dir_wl = find_wordlist("dir_primary")
    if dir_wl:
        log_success(f"Directory wordlist: {dir_wl}")
    elif not args.wordlist:
        log_error(
            "No directory wordlist found! "
            "Install: apt install seclists"
        )
        all_ok = False

    # Check probe wordlists
    if not args.no_probe:
        for probe_type, config in PROBE_CONFIG.items():
            wl = find_wordlist(config["wordlist_key"])
            if wl:
                log_success(f"{config['description']} wordlist: {wl}")
            else:
                log_warn(
                    f"{config['description']} wordlist not found: "
                    f"{WORDLISTS.get(config['wordlist_key'], '?')}"
                )

    if not all_ok:
        log_error("Required dependencies missing. Aborting.")
        sys.exit(1)

    print()

    # ── Collect Targets ─────────────────────────────────────────────────
    targets = []
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, "r") as f:
                raw_targets = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
                seen = set()
                for t in raw_targets:
                    if t not in seen:
                        seen.add(t)
                        targets.append(t)
        except FileNotFoundError:
            log_error(f"Target file not found: {args.file}")
            sys.exit(1)

    if not targets:
        log_error("No targets specified.")
        sys.exit(1)

    log_info(f"Loaded {len(targets)} unique target(s)")

    # ── Execute Scans ───────────────────────────────────────────────────
    if len(targets) == 1:
        scan_target(targets[0], args)
    else:
        max_workers = args.threads or min(5, len(targets))
        log_info(
            f"Running {len(targets)} targets with "
            f"{max_workers} concurrent worker(s)"
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_target, target, args): target
                for target in targets
            }
            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                except Exception as e:
                    log_error(f"Error scanning {target}: {e}")


if __name__ == "__main__":
    main()
