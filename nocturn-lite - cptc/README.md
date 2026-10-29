# Nocturn

**Nocturn** is a command console for offensive-security work: a curated catalog of
pentest and bug-bounty tools whose command lines you assemble by picking a tool,
toggling its flags, and watching the command build live — then copy it into your
proxy or run it in place. It runs two ways from one Go codebase:

- a **terminal UI** (TUI) built with [Bubble Tea](https://github.com/charmbracelet/bubbletea), and
- a **browser app** (`--web`) with split-screen live terminals and an
  engagement map.

Every command is scoped to a target you define, and **nothing executes unless
you ask it to** — `ctrl+r` in the TUI, the **Run** button in the browser.

> **This is the lite build.** It drops the account gate, the browser XSS Lab, and
> the AI output-evaluation agent, leaving just the tool catalogs, the command
> builder, the live terminals, and the engagement map. On a plain Kali VM,
> `run.sh` installs any catalog tools you're missing.

## The TUI

The screen is split into three bordered panels:

- **Project picker** (top-left, 1/3 height) — define the target you're hunting:
  its in-scope URLs/hosts and the things to keep out of scope.
- **Tool picker / configurator** (bottom-left, 2/3 height) — pick a tool and
  toggle its flags while the command builds live.
- **Output** (right half) — streams the command's output when you run it.

Select a project first; its in-scope targets then auto-fill the tool's URL/host
flag (and the out-of-scope list blocks any command that would touch it).
**Nothing is executed unless you explicitly press `ctrl+r`.**



## Browser view

The same catalog can be driven from a browser tab instead of the terminal —
handy for keeping the builder open beside your proxy:

```bash
./run.sh --web              # serves http://localhost:7702/ and opens a tab
./run.sh --web --no-open    # just serve
./run.sh --web --port 9000  # pick another port
```

Pick a tool on the left; on the right choose an active project, fill its flags,
and watch the command assemble live. **Copy** puts it on your clipboard, and
**Run** (`ctrl+enter`) executes it on the machine serving the page, streaming
stdout/stderr into the output console just like `ctrl+r` in the TUI. Each tool
has its own link (e.g. `http://localhost:7702/#web/subfinder`).

There is no account gate — anyone who can reach the page can use it. The server
still binds to `127.0.0.1` only and rejects cross-origin requests, so it is not
exposed beyond the machine serving it. Don't bind it to a public interface.

### Key-info filter (grep)

Many tools print far more than the lines you actually care about. Where it
helps, a tool carries a suggested filter pipeline — live `200`s from `httpx`,
open ports from `nmap`, `$krb5tgs$` hashes from a Kerberoast, and so on. Toggle
it with the **key-info filter** checkbox above the command (or `ctrl+g` in the
TUI) and the assembled command gains a `| grep …` that trims the output to the
important part. It's off by default, so you always start from the raw command.

### The catalogs

The browser view bundles several catalogs and a toggle in the top-left to switch
between them:

- **setup** — engagement-setup helpers (/etc/hosts, a fully-knobbed nmap).
- **Footprinting** — per-service enumeration one-liners (DNS, FTP, SMB/RPC, NFS,
  SMTP, IMAP/POP3, SNMP, SSH, MySQL, MSSQL, Oracle TNS, IPMI, RDP, WinRM, WMI,
  R-Services, RSYNC) plus crt.sh/Shodan OSINT, built from the HTBNotes vault's
  Service Enumeration notes (`footprinting_catalog.go`).
- **web** — the bug-bounty / web-recon tools and payloads documented below.
- **AD** — the Active Directory tooling from the sibling `active-directory` app
  (netexec, BloodHound, Kerberos attacks, impacket, ACL/delegation/shadow-cred
  privilege escalation, Certipy, coercion/relay, …).
- **Linux** / **Reverse Shells** — local-privesc enumeration and the reverse-shell
  payload builder.
- **File Transfers** — move files on/off a box: attacker HTTP/upload/SMB/WebDAV
  servers, Linux & Windows download cradles (wget/curl, WebClient, certutil,
  bitsadmin), uploads, netcat, and base64/openssl encoding, built from the
  vault's File Transfers notes (`filetransfer_catalog.go`).

Click a catalog to switch; each remembers its own selected tool, filter, and
active project, and the URL carries the mode (`#ad/netexec`) so links and
reloads land in the right place. The AD catalog itself still lives in the
standalone `active-directory` TUI — here it's served read-only from a baked-in
copy (`ad_catalog.go`), so re-copy that file if the AD catalog changes.

Projects are **shared** across modes: the list lives in one file
(`…/pentest-suite/projects.json`) that both the TUI and every browser mode read
and write, so a project created anywhere shows up everywhere. (Older per-mode
lists — `web`, `active-directory`, `linux`, `setup` — are picked up and merged
automatically.)

A few things to know:

- **It runs real commands on this machine.** The server binds to `127.0.0.1`
  only and rejects cross-origin requests, but anything that can reach the port
  can run the catalog's tools. Only run it on a machine you control, and don't
  bind it to a public interface.
- **Scope still applies.** The active project's out-of-scope list is enforced
  server-side before anything runs — the same block as `ctrl+r`, per mode.
- **Projects are editable here too.** Use **＋ New** to create a project,
  **✎ Scope** to add/remove its in- and out-of-scope entries, and **🗑 Delete**
  to remove it. Changes write straight to the shared `projects.json`; the
  **↻** button reloads it if you've also been editing in a TUI.
- The page is `webui/index.html`, embedded in the binary with the catalogs
  baked in at build time, so rebuild after editing `catalog.go` / `ad_catalog.go`
  (`run.sh` always rebuilds).

| Key (browser)        | Action                                   |
| -------------------- | ---------------------------------------- |
| `/`                  | filter the tool list                     |
| `j`/`k`, `↑`/`↓`     | move through the list                    |
| `g` / `G`            | first / last tool                        |
| `y`                  | copy the assembled command               |
| key-info filter      | checkbox above the command — pipe through the tool's `grep` |
| `ctrl+enter`         | run (or stop) the command                |
| `esc`                | clear the filter                         |

### Interactive terminal (split screen)

The command builder's **Run** is one-shot: it assembles a catalog command and
streams its output back, with no way to type into the running process. For
anything that wants a real shell — responding to a prompt, chaining ad-hoc
commands, poking at a target interactively — there's a full terminal.

Click **⌗ Terminal** in the top-right to open the terminal workspace (it takes
over the catalog view; click it again, or **✕ Close**, to go back). Each pane is
an independent shell running on the machine serving the page, over a WebSocket
to `/api/terminal`, backed by a real pseudo-terminal — so interactive programs,
colours, and line editing all work.

**Split screen** lets you watch several at once:

- **＋ Split** (or `ctrl+shift+t`) opens another shell pane.
- **Columns 1–4** sets how the panes tile, so you can line up two or three
  side by side and compare their output live.
- **A− / A+** change the text size; **✕** on a pane closes that shell.
- Click a pane to focus it; what you type goes to that pane's shell. Paste works
  too. Closing a pane (or the workspace) ends its shell.

A few things to know:

- **These are unrestricted shells**, not catalog commands — the project
  out-of-scope block does **not** apply to what you type here (it can't know your
  intent the way it can with an assembled command). Same trust model as the rest
  of the app: localhost-only, same-origin-checked, your machine.
- The terminal is **Linux-only** (it needs a PTY; see `run.sh`). On other
  platforms the pane opens and says so rather than failing silently.
- The emulator is a compact, built-in one (no `xterm.js`, so it works offline).
  It handles colours, carriage-return progress bars, cursor moves, and the
  alternate-screen buffer; heavy full-screen TUIs (e.g. `vim`, `htop`) mostly
  work but aren't pixel-perfect.

### Application Map (Obsidian-style canvas)


The **Application Map** tab (top-left toggle, alongside web / AD / Linux / …)
draws a per-project, Obsidian-style canvas of the whole engagement and **builds
itself from command output across every catalog**. Whenever you Run a tool, its
output is parsed and the important parts are added as linked nodes:

- **recon / probe** — `subfinder`, `amass`, `dnsx` FQDNs become **host /
  subdomain** nodes; `naabu` `host:port` and `nmap` `PORT open SERVICE` lines
  become **port** nodes; `nmap` `Nmap scan report for …` adds the host
- **crawl / content discovery** — URLs from `httpx`, `katana`, `gau`,
  `waybackurls` become **host → endpoint → param** nodes; `gobuster` / `ffuf` /
  dirsearch path+status lines become **endpoint** nodes on the target host;
  `arjun` discovered parameters become **param** nodes
- **tech** — `httpx -tech-detect` / Wappalyzer `[nginx, PHP, WordPress]`
  brackets become **tech** nodes on the host
- **AD** — netexec/crackmapexec protocol lines become **host** + **domain**
  nodes, with **user**, **cred** (valid logons / `Pwn3d!`) and **share**
  (READ/WRITE) nodes from enumeration
- **findings / attack vectors** — nuclei severities (`[high]`/`[critical]`),
  `sqlmap` vulnerable parameters, `dalfox`/`[POC]` lines, `nikto` vuln notes and
  nmap `VULNERABLE` become **finding** nodes linked to the host/param they hit

Output is run through an ANSI-colour strip first, so colourised tools (`ffuf`,
`gobuster`, `nuclei`, …) map correctly, and path-only output is attached to the
target pulled from the command's `-u`/`-h`/URL so nothing floats free.

Everything is laid out automatically but **fully draggable**; drag the
background to pan and scroll to zoom. **⤢ Fit** reframes the graph, **＋ Node**
drops a free note (double-click to rename, hover + **✕** to delete).

It is **specific to a project** — pick one in the tab's own dropdown; each
project stores its own map (in the browser, via `localStorage`), so one map
accumulates everything you find on that engagement regardless of which catalog
you ran the tool from. A seeded **★ Example map** (a small AD + web + nmap
engagement) shows what a populated map looks like; **🗑 Delete map** removes the
selected map (the example included), and **★ Example** reloads/resets it.

## Tools included

Curated toward **bug bounty** — tools that find leads on their own and
complement a proxy like Caido/Burp rather than duplicating it. Grouped by
workflow stage (filter with `/` by stage name, e.g. `recon`):

- **recon** — `subfinder` · `amass` · `dnsx`
- **probe** — `httpx` · `naabu` · `gowitness`
- **crawl** — `katana` · `gau` · `waybackurls`
- **content discovery** — `ffuf` · `ffuf · token` (brute-force reset
  tokens/OTPs/IDs with regex match/filter) · `arjun` · `gobuster`
- **vuln scan** — `nuclei` · `dalfox` · `subzy` · `sqlmap` · `nikto`
- **shells** — GTFOBins reverse / bind / spawn shells (`bash`, `nc`, `socat`,
  `python`, `perl`, `php`, `ruby`, `openssl`, `telnet`, `lua`, `node`, `gawk`,
  `busybox`, `zsh`) for post-exploitation on hosts you're authorized to test
- **payloads** — a `PayloadsAllTheThings`-style cheat sheet of canonical
  detection probes (XSS, SQLi, SSTI, SSRF, path traversal, XXE, command
  injection, open redirect, NoSQL/LDAP/CRLF, JWT). Filter with `/payload`,
  fill the `{MARKER}`/`{HOST}`/`{FILE}`/`{CMD}` placeholder, then `ctrl+y` to
  copy the probe into Caido/Burp. See [Payloads](#payloads) below.

Each exposes a curated set of flags with sensible defaults, descriptions, and
required-field hints.

The **shells** branch is lifted from [GTFOBins](https://gtfobins.github.io).
Entries are named `<binary> · <technique>`; pick one, fill the `{LHOST}` /
`{LPORT}` placeholders (which are substituted straight into the payload), then
`ctrl+y` to copy or `ctrl+r` to run. The plain `· shell` spawns take no
parameters.

A typical chain: `subfinder` → `httpx` → `katana`/`gau` → `ffuf`/`arjun` →
`nuclei`, then pivot into Caido for manual testing. The sibling
[`pentest-learning`](../pentest-learning) project explains this whole workflow.

## Wordlists

Nothing ships with this app and nothing is installed. The fuzzing tools default
to the wordlists Kali already provides under `/usr/share/wordlists`, so
`ffuf`, `gobuster`, and `kerbrute` resolve to real files out of the box on a
default install:

| Path (under `/usr/share/wordlists`) | Used by |
|-------------------------------------|---------|
| `dirbuster/directory-list-2.3-medium.txt` | `ffuf` |
| `dirb/common.txt` | `gobuster` |
| `seclists/Discovery/DNS/subdomains-top1million-110000.txt` | subdomain brute / vhost fuzzing |
| `seclists/Usernames/top-usernames-shortlist.txt` | `kerbrute` user enum / spray |

Defaults resolve to an absolute path, so a command copied or run from the TUI
works from any directory. Every list is editable in the UI — just change the
`-w` path to any other wordlist on the box. To use a different root, set
`PENTEST_TUI_WORDLISTS` and the relative defaults follow it.

## Payloads

A curated, **detection-first** payload library ships in `payloads.go`, modelled
on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
and the [PortSwigger Web Security Academy](https://portswigger.net/web-security)
cheat sheets. Each entry is a well-known *probe* — the minimal input that
confirms whether a sink is reachable and how your input is treated — not a
weaponised exploit. They live in the same picker as the tools (filter with
`/payload`), grouped by class:

| Class | Example probes |
|-------|----------------|
| `xss` | script canary, img/svg handlers, attribute breakout, `javascript:` URI, polyglot, DOM hashprobe |
| `sqli` | quote probe, auth-bypass tautology, UNION column count/select, boolean & time-blind (MySQL/Postgres/MSSQL) |
| `sqli-build` | **composable builders** — pick a quote/paren context, comment style, DBMS primitive and column list, and the injection assembles live (see [SQLi builders](#sqli-builders)) |
| `ssti` | `${7*7}{{7*7}}` math detector, Jinja2 & Freemarker markers |
| `path-traversal` | `../`, URL- & double-encoded, PHP `filter` wrapper |
| `ssrf` | localhost, cloud metadata (`169.254.169.254`), decimal-IP bypass, OOB canary |
| `cmd-injection` | separators, command substitution, blind OOB |
| `xxe` | external-entity file read, OOB exfil |
| `privesc` | access-control probes — IDOR/BOLA id swap, mass-assignment role field, forced browsing to admin, 403-bypass rewrite headers, method-override, JWT claim tamper |
| `open-redirect`, `nosqli`, `ldapi`, `crlf`, `host-header`, `jwt` | the usual one-liners |

Placeholders are substituted straight into the copied string (same mechanism as
the GTFOBins shells):

| Token | Meaning |
|-------|---------|
| `{MARKER}` | a unique canary you grep responses for to see where input lands |
| `{HOST}` | your out-of-band host (Interactsh / Burp Collaborator) for blind detection |
| `{FILE}` | a file path target for traversal / LFI probes |
| `{CMD}` | a benign command (a timed `sleep`) to prove execution |
| `{ID}`, `{FIELD}`, `{PATH}`, `{VERB}`, `{CLAIM}`, `{VALUE}` | access-control knobs — the victim object id, privilege attribute, admin path, smuggled HTTP verb, and JWT role claim/value |

Workflow: pick a probe → fill the placeholder → `ctrl+y` to copy → paste into
your proxy and fire the request against a target **you are authorized to test**.
A payload entry's "command" is the bare payload string itself, so `ctrl+y`
(copy), `ctrl+o`, and the on-quit print all give you exactly the text to paste
into your proxy — nothing to strip off.

### SQLi builders

The `sqli-build` entries go a step past the fixed one-liners: instead of copying
a static string, you **assemble** an injection for the exact sink you're testing
by cycling a few configurable knobs (`←/→` on choice flags, type on the rest).
The command rebuilds live, and `ctrl+y` copies the finished payload.

| Builder | What you compose |
|---------|------------------|
| `build: auth bypass` | `' OR 1=1 --` tautology with your chosen quote/paren context |
| `build: boolean blind` | `AND <cond>` where `{COND}` flips between a true/false test |
| `build: time blind` | a DBMS timing primitive (MySQL `SLEEP`, Postgres `pg_sleep`, MSSQL `WAITFOR`, Oracle `RECEIVE_MESSAGE`) + delay |
| `build: UNION extract` | `UNION SELECT` with an editable column list sized to the `ORDER BY` count |
| `build: error-based extract` | leaks a subquery through a DBMS error (MySQL `extractvalue`/`updatexml`, Postgres `CAST`, MSSQL `CONVERT`) |
| `build: stacked query` | a second statement after `;` for drivers that allow it |

The shared knobs:

| Token | Flag | Meaning |
|-------|------|---------|
| `{Q}` | Break context | what closes the original value: `'`, `"`, `')`, `")`, `'))` |
| `{C}` | Comment | trailing comment that swallows the rest of the query (`-- -`, `#`, `/*`) |
| `{COLS}` | UNION columns | the `UNION SELECT` list — match the column count, carry data in a text column |
| `{SLEEP}`/`{T}` | Delay primitive / seconds | DBMS sleep function and how long |
| `{COND}` | Condition | the boolean oracle (`1=1` vs `1=2`, or a sample extraction test) |
| `{ERR}`/`{SUB}` | Error primitive / Leak subquery | the error-cast and the subquery it surfaces |
| `{STMT}` | Stacked statement | the statement run after `;` |

The assembled command is the bare SQL payload — `ctrl+y` copies exactly what you
paste into your proxy (quotes and all), with no wrapper to strip.

## Build & run

Go 1.27+ is required. This repo was set up with Go installed to `~/go-sdk/go`,
so either run `source ~/.bashrc` (adds it to PATH) or let `run.sh` find it:

```bash
cd ~/Desktop/nocturn-lite
go build -o web .     # pure-Go build; CGO is off (see run.sh)
./web                 # launch the TUI
```

Or just `./run.sh` (TUI) / `./run.sh --web` (browser) — it always rebuilds, puts
your Go-installed tools on PATH, and launches.

On a plain Kali/Debian VM, `run.sh` also installs the catalog's tools when they
are missing: apt packages (nmap, sqlmap, smbclient, enum4linux-ng, …), the
ProjectDiscovery Go tools (subfinder, httpx, nuclei, katana, …) via `go install`,
and the Python AD tooling (netexec, certipy, bloodhound-python, …) via pipx.
Each tool is checked first and skipped if already present, so re-runs are cheap.
Set `NOCTURN_SKIP_INSTALL=1` to skip the whole step.

To install it system-wide (binary at `/opt/pentest-tui`, launcher `web` on every
user's PATH), run `sudo ./install.sh` from inside the app directory
(`--build` to rebuild from source first).

## Projects & scope

A project is a hunting target: a name, a list of **in-scope** URLs/hosts, and a
list of **out-of-scope** entries. Projects persist between runs in a single
shared file, `…/pentest-suite/projects.json` under your OS config dir (e.g.
`~/.config/pentest-suite/projects.json` on Linux), read and written by both the
TUI and every browser mode.

- Press `ctrl+p` from anywhere to jump to the project panel.
- `n` creates a project, `s` edits its scope, `enter` makes it the active one.
- When a project is active, choosing a tool pre-fills its URL/host flag with the
  first in-scope target; `ctrl+n` in the configurator cycles through the rest.
- `ctrl+r` **refuses** to run any command that contains an out-of-scope entry.

## Keys

### Project picker (top-left)
| Key | Action |
|-----|--------|
| `↑/↓` | move between projects |
| `enter` | select the active project (scope in effect) |
| `n` | new project (type a name, `enter` to save) |
| `s` | edit scope → `ctrl+t` toggles in/out, `enter` adds, `↑/↓`+`ctrl+x` deletes, `esc` done |
| `d` | delete the highlighted project |
| `tab` | switch focus down to the tool picker |

### Tool list (bottom-left)
| Key | Action |
|-----|--------|
| `↑/↓` | move |
| `/` | filter |
| `enter` | configure selected tool |
| `ctrl+p` | jump to the project panel |
| `q` / `ctrl+c` | quit |

### Flag configurator (bottom-left)
| Key | Action |
|-----|--------|
| `↑/↓` or `tab` | move between flags |
| `space` | toggle a boolean flag |
| `←/→` | cycle a choice flag |
| *(type)* | edit the selected text/number flag |
| `ctrl+n` | fill the selected flag with the next in-scope target |
| `ctrl+g` | toggle the tool's key-info filter (pipes the command through its `grep`) |
| `ctrl+y` | copy the command to the clipboard |
| `ctrl+o` | print the command and quit |
| `ctrl+r` | **run** the command — output streams into the right panel |
| `ctrl+p` | jump to the project panel |
| `ctrl+c` | cancel a running command (or quit when idle) |
| `pgup/pgdn`, `home/end`, mouse wheel | scroll the output panel |
| `esc` | back to the tool list |

The command runs inside the TUI via `sh -c`, so compound binaries
(e.g. `gobuster dir`) and the shell quoting behave exactly as shown. Output
(stdout and stderr) streams live into the right panel and the exit status is
appended when it finishes. The last assembled command is also printed to stdout
when you quit (via `ctrl+o`, `ctrl+r`, or after a `ctrl+y` copy), so it survives
leaving the TUI.

## Adding a tool

Edit `catalog.go` and append a `Tool` to the `catalog` slice. Each `Flag` has a
`Kind` (`KindBool`, `KindString`, `KindInt`, `KindChoice`), an optional default
(`Value` / `Enabled`), a `Desc`, and flags like `Required` or `Positional`.
Positional flags (targets, URLs with no switch) are emitted at the end of the
command.

## Files

| File | Purpose |
|------|---------|
| `tool.go` | `Tool`/`Flag` types + command assembly and shell quoting |
| `catalog.go` | the built-in web tool definitions |
| `ad_catalog.go` | the Active Directory catalog (baked-in copy of the `active-directory` app's), served as the browser's **AD** mode |
| `footprinting_catalog.go` | per-service enumeration one-liners (**Footprinting** mode) |
| `filetransfer_catalog.go` | file-transfer servers, cradles, and encoders (**File Transfers** mode) |
| `linux_catalog.go` | Linux local-privesc enumeration (**Linux** mode) |
| `revshell_catalog.go` | the reverse-shell payload builder (**Reverse Shells** mode) |
| `setup_catalog.go` | engagement-setup helpers (**setup** mode) |
| `payloads.go` | the detection-probe payload library (appended into the catalog) |
| `model.go` | Bubble Tea model, update loop, and three-panel rendering |
| `project.go` | project/scope picker: state, persistence, and scope wiring |
| `run.go` | streams a running command's output into the right panel |
| `wordlists.go` | resolves Kali `/usr/share/wordlists` paths |
| `web.go` | `--web` server: serves the catalog, runs commands, manages projects, enforces scope |
| `terminal.go` / `ws.go` / `pty_linux.go` / `pty_other.go` | the split-screen browser terminals and their PTY backing |
| `license.go` | licensing / entitlement checks (local mode unlocks everything) |
| `webui/index.html` | the browser view (embedded in the binary) |
| `main.go` | entrypoint; `--web` flag; prints the last assembled command on quit |

## Safety

Nocturn builds commands and, only when you explicitly run them (`ctrl+r` in the
TUI, **Run** in the browser), executes them on the machine serving the app. The
browser view is localhost-only and same-origin-checked; the scope block refuses
any assembled command that would touch an out-of-scope target. Run it, and the
tools it drives, only against systems you are authorized to test.
