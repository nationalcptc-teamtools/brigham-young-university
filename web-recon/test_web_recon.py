import pytest
import os
import tempfile
import json
from web_recon import (
    sanitize_filename,
    detect_tech_preset,
    filter_static_assets,
    filter_static_urls,
    find_api_bases,
    parse_arjun_output,
    parse_katana_output,
    parse_form_fields,
    write_recon_summary,
    TOP_20_LFI_PAYLOADS,
)


def test_find_api_bases():
    eps = [
        "http://t/",
        "http://t/rest",
        "http://t/api/experiments",
        "http://t/v1/users",
        "http://t/assets",          # not an API base
        "http://t/redirect",        # not an API base
    ]
    bases = find_api_bases(eps, "http://t/")
    assert "http://t/rest" in bases
    assert "http://t/api" in bases
    assert "http://t/v1" in bases
    assert "http://t/assets" not in bases
    # self-gating: no API paths → no bases
    assert find_api_bases(["http://t/", "http://t/login"], "http://t/") == []


def test_filter_static_urls():
    urls = [
        "http://t/",
        "http://t/main.js",
        "http://t/styles.css",
        "http://t/rest/products/search",
        "http://t/logo.png",
        "http://t/static/js/.exec",       # jsluice garbage — no extension
        "http://t/static/js/8000/static/js/e.action",
    ]
    kept = filter_static_urls(urls)
    assert "http://t/rest/products/search" in kept
    assert "http://t/" in kept
    assert "http://t/main.js" not in kept
    assert "http://t/styles.css" not in kept
    assert "http://t/logo.png" not in kept
    assert "http://t/static/js/.exec" not in kept
    assert "http://t/static/js/8000/static/js/e.action" not in kept


def test_parse_katana_output():
    out = (
        "http://t/\n"
        "http://t/rest/products/search?q=apple\n"
        "http://t/redirect?to=https://evil\n"
        "http://evil.com/offsite\n"          # off-scope, dropped
        "http://t/main.js\n"
    )
    eps, params = parse_katana_output(out, "http://t/")
    assert "http://t/rest/products/search" in eps
    assert "http://t/redirect" in eps
    assert "http://evil.com/offsite" not in eps      # scope enforced
    assert params["http://t/rest/products/search"] == ["q"]
    assert params["http://t/redirect"] == ["to"]


def test_parse_katana_output_skips_static_params():
    out = (
        "http://t/wp-includes/js/jquery/jquery.min.js?ver=3.6.3\n"
        "http://t/styles.css?ver=1.2\n"
        "http://t/setup-config.php?language=en_US\n"
    )
    eps, params = parse_katana_output(out, "http://t/")
    # endpoints are still recorded...
    assert "http://t/wp-includes/js/jquery/jquery.min.js" in eps
    assert "http://t/styles.css" in eps
    # ...but version params on static assets are dropped
    assert "http://t/wp-includes/js/jquery/jquery.min.js" not in params
    assert "http://t/styles.css" not in params
    # real application params survive
    assert params["http://t/setup-config.php"] == ["language"]

def test_parse_form_fields():
    html = """
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="user">
      <input type="password" name="password">
      <input type="hidden" name="csrfmiddlewaretoken" value="abc123">
      <select name="role"><option>admin</option></select>
      <textarea name="comment"></textarea>
      <button name="save">Go</button>
      <input type="text" value="no name attr">
    </form>
    """
    fields = parse_form_fields(html)
    assert "username" in fields
    assert "password" in fields
    assert "role" in fields
    assert "comment" in fields
    assert "save" in fields
    assert "csrfmiddlewaretoken" not in fields


def test_sanitize_filename():
    assert sanitize_filename("http://example.com/") == "example.com"
    assert sanitize_filename("http://example.com:8080/") == "example.com_8080"
    assert sanitize_filename("http://example.com/api/v1/users") == "example.com_api_v1_users"
    long_path = "http://example.com/" + "a" * 50
    sanitized = sanitize_filename(long_path)
    assert sanitized.startswith("example.com_")
    assert len(sanitized) < 40

def test_detect_tech_preset():
    # JavaScript trips Node.js, not Java
    ww_js = {"raw": "WhatWeb report for http://example.com [200 OK] Script[text/javascript] HTML5"}
    assert detect_tech_preset(ww_js) == "all"

    # Java trips Java preset
    ww_java = {"raw": "WhatWeb report for http://example.com [200 OK] Java[1.8.0] Tomcat[9.0]"}
    assert detect_tech_preset(ww_java) == "java"

    # PHP trips PHP preset
    ww_php = {"raw": "WhatWeb report for http://example.com [200 OK] PHP[7.4.3] WordPress[5.8]"}
    assert detect_tech_preset(ww_php) == "php"

def test_filter_static_assets():
    results = [
        {"url": "http://example.com/index.html"},
        {"url": "http://example.com/style.css"},
        {"url": "http://example.com/logo.png"},
        {"url": "http://example.com/api/data"},
    ]
    dynamic = filter_static_assets(results)
    urls = [r["url"] for r in dynamic]
    assert "http://example.com/index.html" in urls
    assert "http://example.com/api/data" in urls
    assert "http://example.com/style.css" not in urls
    assert "http://example.com/logo.png" not in urls

def test_parse_arjun_output():
    stdout = "Scanning http://example.com/api\nParameters found: id, token, debug"
    res = parse_arjun_output("/nonexistent_file.txt", stdout_text=stdout)
    assert "http://example.com/api" in res
    assert res["http://example.com/api"] == ["debug", "id", "token"]

def test_write_recon_summary_b1_fix():
    scan_results = {
        "target_url": "http://example.com",
        "preset": "all",
        "probe_results": {
            "http://example.com/page.php": {
                "file": [
                    {
                        "description": "LFI (Local File Inclusion)",
                        "advisory_hits": [
                            {"payload": "/etc/passwd", "status": 200, "length": 1234}
                        ],
                        "wordlist": "/tmp/lfi.txt",
                        "ffuf_cmd": "ffuf -u http://example.com/page.php?file=FUZZ ..."
                    }
                ]
            }
        },
        "params_by_url": {"http://example.com/page.php": ["file"]}
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "recon.md")
        has_vulns = write_recon_summary("http://example.com", scan_results, report_path)
        assert has_vulns is True
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Phase 4.5: Vulnerability Indicators" in content
        assert "[!] LFI (Local File Inclusion)" in content
        assert "⚠️ LIKELY VULNERABLE (LFI (Local File Inclusion))" in content


def test_write_recon_summary_differential_candidate():
    scan_results = {
        "target_url": "http://example.com",
        "preset": "all",
        "probe_results": {
            "http://example.com/search": {
                "q": [
                    {
                        "description": "SQL Injection (error-based)",
                        "results": [
                            {"payload": "'^'", "status": 500,
                             "length": 976, "advisory": False},
                            {"payload": "admin' #", "status": 500,
                             "length": 994, "advisory": False},
                        ],
                        "advisory_hits": [],
                        "wordlist": "/tmp/sqli.txt",
                        "ffuf_cmd": "ffuf -u http://example.com/search?q=FUZZ ..."
                    }
                ]
            }
        },
        "params_by_url": {"http://example.com/search": ["q"]}
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "recon.md")
        has_vulns = write_recon_summary("http://example.com", scan_results, report_path)
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "Differential candidate" in content
        assert "2 non-baseline response(s)" in content
        assert "🧪 DIFFERENTIAL CANDIDATE (review manually)" in content
        assert "No indicators found." not in content


def test_top_20_lfi_payloads():
    assert len(TOP_20_LFI_PAYLOADS) == 20
    assert "../../../../etc/passwd" in TOP_20_LFI_PAYLOADS
    assert "../../../../windows/win.ini" in TOP_20_LFI_PAYLOADS

