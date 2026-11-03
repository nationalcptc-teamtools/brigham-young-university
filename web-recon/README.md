# web-recon

Automated web recon pipeline: whatweb → katana (spider + JS endpoint extraction) → ffuf (dir/file brute force) → arjun (param discovery) → ffuf vuln probing (LFI/SQLi/CMDi indicators) → report.

Discovery only. No automated exploitation — output is a markdown report of copy-paste curl/ffuf/Burp Repeater commands for manual follow-up.

## Requirements

`whatweb`, `katana`, `ffuf`, `arjun` on PATH (all installed by `bootstrap/kali-setup.sh`). `chromium` optional (katana headless mode; falls back automatically if absent).

## Usage

```
python3 web_recon.py -u http://10.10.10.15/
python3 web_recon.py -u http://10.10.10.15/ --tech php
python3 web_recon.py -u http://10.10.10.15/ --gentle
```

`--gentle` drops concurrency/rate for fragile single-container targets that SIGSEGV under default load.

`parse_ffuf.py <path_to_ffuf.json>` pretty-prints a saved ffuf results file sorted by status/size.

Run `python3 web_recon.py -h` for the full flag list.
