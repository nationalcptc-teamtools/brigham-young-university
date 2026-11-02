#!/usr/bin/env bash
# BYU CPTC — Kali box provisioning script.
#
# Run as root -- this script expects it, not a plain sudo-capable user:
#   sudo bash kali-setup.sh
#   curl -s https://raw.githubusercontent.com/nationalcptc-teamtools/brigham-young-university/main/bootstrap/kali-setup.sh | sudo bash
#
# Everything it installs lands under the real operator's home, not root's.
# That target user is $SUDO_USER (set automatically by sudo, including
# through a curl|sudo bash pipe) or 'kali' if the box is already a root shell
# with no sudo involved. Override with: TARGET_USER=<user> sudo -E bash kali-setup.sh
#
# Also sets up passwordless sudo for that user (see step 1) -- this is a
# disposable competition box, so speed beats re-typing a password on every
# sudo call for the rest of the engagement. Remove
# /etc/sudoers.d/99-byu-cptc-nopasswd afterward if that's not wanted.
#
# Patterns borrowed on purpose from other nationalcptc-teamtools repos we reviewed:
#   - Illinois Institute of Technology's kali-prep.sh: apt/pipx baseline tool list,
#     and resolving a tool's latest GitHub release via the API instead of a
#     hardcoded URL (so the script doesn't silently go stale).
#   - Dakota State University: staging offline copies of common Windows/Linux
#     binaries so the box isn't dependent on engagement-network egress. We fetch
#     fresh at setup time instead of committing binaries to git.
# Everything else (kitty config, the spraying tool, the light-terminal color
# scheme, and the specific Windows binary set) wasn't present in any other
# team's repo we found, so it's built here from scratch.

set +e  # keep going through flaky mirrors/downloads; failures are reported at the end, not fatal

FAILURES=()
run() {
  echo "+ $*"
  if ! "$@"; then
    FAILURES+=("$*")
    echo "[!] failed: $*"
  fi
}

if [ "$(id -u)" -ne 0 ]; then
  echo "This script needs root. Run it as:" >&2
  echo "  sudo bash kali-setup.sh" >&2
  echo "  curl -s https://raw.githubusercontent.com/nationalcptc-teamtools/brigham-young-university/main/bootstrap/kali-setup.sh | sudo bash" >&2
  exit 1
fi

TARGET_USER="${SUDO_USER:-${TARGET_USER:-kali}}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
if [ -z "$TARGET_HOME" ]; then
  echo "[!] no such user: $TARGET_USER -- set TARGET_USER=<user> and retry with 'sudo -E'" >&2
  exit 1
fi
export HOME="$TARGET_HOME"
export USER="$TARGET_USER"

# Where this script and its sibling kitty.conf are hosted for the
# 'curl | sudo bash' flow. Override with RAW_BASE_URL=... if testing from a
# fork/branch. Only actually used when there's no local sibling kitty.conf
# next to this script (see step 2).
RAW_BASE_URL="${RAW_BASE_URL:-https://raw.githubusercontent.com/nationalcptc-teamtools/brigham-young-university/main/bootstrap}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
TOOLS_DIR="$HOME/tools"
WIN_DIR="$TOOLS_DIR/windows"
mkdir -p "$TOOLS_DIR" "$WIN_DIR"

echo "===> [1/7] Base packages"
run apt -y update
# netexec, certipy-ad, coercer, evil-winrm, sharphound, bloodhound-ce-python,
# bloodyad are all native Kali apt packages now (checked against kali.org/tools)
# — install them here via apt instead of pipx/gem/raw-fetch so they track system
# updates. bloodyAD also doubles as a BloodHound CE collector in its own right
# ('bloodyad get bloodhound --path ...', confirmed in its wiki) on top of its
# main job as a post-BloodHound privesc tool (set passwords, shadow creds,
# LAPS/gMSA reads, group edits, all over plain LDAP) — its own docs flag that
# collector as still basic (no ADCS ESC nodes yet), so pair it with certipy-ad
# for certificate-template attack paths specifically.
run apt -y install git curl wget jq pipx kitty \
    nmap seclists enum4linux-ng enum4linux smbmap smbclient ldap-utils \
    netexec ffuf gobuster feroxbuster sqlmap proxychains4 xclip \
    certipy-ad coercer evil-winrm sharphound bloodhound-ce-python bloodyad \
    docker.io docker-compose \
    nbtscan onesixtyone oscanner nikto sslscan sslyze tnscmd10g whatweb \
    dnsrecon impacket-scripts redis-tools snmp sipvicious

run systemctl enable --now docker
run usermod -aG docker "$TARGET_USER"

# Passwordless sudo for $TARGET_USER -- validated with 'visudo -c' before
# being dropped into place so a typo here can't lock sudo up for everyone.
SUDOERS_FILE="/etc/sudoers.d/99-byu-cptc-nopasswd"
SUDOERS_TMP="$(mktemp)"
echo "$TARGET_USER ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_TMP"
if visudo -c -f "$SUDOERS_TMP" >/dev/null 2>&1; then
  install -m 440 -o root -g root "$SUDOERS_TMP" "$SUDOERS_FILE"
  echo "    $TARGET_USER can now sudo without a password (remove $SUDOERS_FILE to undo)."
else
  echo "[!] passwordless-sudo snippet failed visudo validation, not installed"
fi
rm -f "$SUDOERS_TMP"

run pipx ensurepath
# Kali's sudo config strips /usr/local/bin from PATH entirely (secure_path),
# which otherwise breaks every later 'command -v'/bare-name lookup against
# the things this script installs there (bloodhound-cli, kerbrute, etc).
export PATH="$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:$PATH"

echo "===> [2/7] kitty"
# Our own config, tracked in this repo (bootstrap/kitty.conf) -- not a cloned
# third-party dotfile set. Mirrors this team's own kitty.conf (ctrl+q prefix,
# same letters for splits/tabs/navigation) so there's no muscle-memory gap
# switching between a laptop and this box. Copy/paste is left at kitty's own
# defaults on purpose -- no custom mouse_map. Local checkout: copy the
# sibling file directly. No sibling file found (e.g. curl|sudo bash, where
# only this script itself was piped in): fetch it from wherever this script
# is hosted instead.
mkdir -p "$HOME/.config/kitty"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/kitty.conf" ]; then
  run install -m 644 "$SCRIPT_DIR/kitty.conf" "$HOME/.config/kitty/kitty.conf"
elif [ -n "$RAW_BASE_URL" ]; then
  run curl -fsSL "$RAW_BASE_URL/kitty.conf" -o "$HOME/.config/kitty/kitty.conf"
else
  echo "[!] no local bootstrap/kitty.conf and no RAW_BASE_URL set -- kitty left at its default config"
fi
echo "kitty ready — open a new kitty window (or ctrl+shift+f5) to pick this up."

echo "===> [3/7] Password spraying — TREVORspray + kerbrute"
# TREVORspray: multi-protocol spray tool (SMB/LDAP/EWS/O365/...) — picked over a
# single-protocol sprayer since this org's target infra leans on Microsoft 365.
run pipx install trevorspray

# kerbrute: Kerberos pre-auth spraying (AS-REQ), doesn't trip normal AD lockout
# counters the way SMB/LDAP spraying does — resolved via the GitHub API so this
# doesn't rot like a hardcoded version URL would (same trick IIT used for ligolo-ng).
KERBRUTE_URL=$(curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest \
  | jq -r '.assets[].browser_download_url' | grep linux_amd64)
if [ -n "$KERBRUTE_URL" ]; then
  run wget -q "$KERBRUTE_URL" -O /usr/local/bin/kerbrute
  run chmod +x /usr/local/bin/kerbrute
else
  echo "[!] could not resolve latest kerbrute release"
fi

echo "===> [4/7] AD tooling with no Kali apt package"
# Everything here still needs pipx/git/raw-fetch — unlike netexec/certipy-ad/
# coercer/evil-winrm/sharphound (installed via apt in step 1), Kali has no
# package for any of these as of this writing.
run pipx install git+https://github.com/garrettfoster13/pre2k
run pipx install git+https://github.com/garrettfoster13/sccmhunter

for repo in dirkjanm/PKINITtools dirkjanm/krbrelayx ShutdownRepo/pywhisker \
            insidetrust/statistically-likely-usernames Ridter/noPac; do
  name="${repo##*/}"
  if [ ! -d "$TOOLS_DIR/$name" ]; then
    run git clone "https://github.com/$repo" "$TOOLS_DIR/$name"
  fi
done
# Per-tool venv isolation so these loosely-packaged scripts don't fight each
# other's (or the system's) Python dependencies.
find "$TOOLS_DIR" -maxdepth 2 -type f -name 'requirements.txt' \
  -execdir python3 -m venv .venv \; \
  -execdir .venv/bin/pip install -q -r {} \;

# Standalone coercion scripts, fetched as raw files and chmod'd onto PATH.
declare -A COERCION_SCRIPTS=(
  [petitpotam]="https://raw.githubusercontent.com/topotam/PetitPotam/main/PetitPotam.py"
  [dfscoerce]="https://raw.githubusercontent.com/Wh04m1001/DFSCoerce/main/dfscoerce.py"
  [shadowcoerce]="https://raw.githubusercontent.com/ShutdownRepo/ShadowCoerce/main/shadowcoerce.py"
  [cheeseounce]="https://raw.githubusercontent.com/evilashz/CheeseOunce/main/cheese.py"
)
for name in "${!COERCION_SCRIPTS[@]}"; do
  run wget -q "${COERCION_SCRIPTS[$name]}" -O "/usr/local/bin/$name"
  run chmod +x "/usr/local/bin/$name"
done

# ligolo-ng (pivoting) — asset names carry the version, so resolve via the
# GitHub API instead of hardcoding a URL (same trick as kerbrute above).
LIGOLO_ASSETS=$(curl -s https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | jq -r '.assets[].browser_download_url')
LIGOLO_TMP=$(mktemp -d)
mkdir -p "$TOOLS_DIR/ligolo"
ligolo_fetch() { # <asset regex> <extract dir>
  local url
  url=$(echo "$LIGOLO_ASSETS" | grep -E "$1" | head -n1)
  [ -z "$url" ] && { echo "[!] ligolo-ng: no release asset matching $1"; return 1; }
  local f="$LIGOLO_TMP/${url##*/}"
  wget -q "$url" -O "$f" || return 1
  mkdir -p "$2"
  case "$f" in
    *.zip) python3 -m zipfile -e "$f" "$2" ;;
    *) tar -xzf "$f" -C "$2" ;;
  esac
}
if ligolo_fetch 'ligolo-ng_proxy_[^/]*_linux_amd64\.tar\.gz$' "$LIGOLO_TMP/proxy"; then
  run install -m 755 "$LIGOLO_TMP/proxy/proxy" /usr/local/bin/ligolo-proxy
fi
if ligolo_fetch 'ligolo-ng_agent_[^/]*_linux_amd64\.tar\.gz$' "$LIGOLO_TMP/agent-linux"; then
  run install -m 755 "$LIGOLO_TMP/agent-linux/agent" "$TOOLS_DIR/ligolo/agent"
fi
if ligolo_fetch 'ligolo-ng_agent_[^/]*_windows_amd64\.zip$' "$LIGOLO_TMP/agent-windows"; then
  run install -m 644 "$LIGOLO_TMP/agent-windows/agent.exe" "$TOOLS_DIR/ligolo/agent.exe"
fi
rm -rf "$LIGOLO_TMP"

# Backup copies of netexec and impacket, each in their own venv, in case the
# apt-installed versions (step 1: netexec, impacket-scripts) act up mid-engagement.
# Not on PATH by default -- apt's copies stay primary; these are an explicit fallback.
for repo in Pennyw0rth/NetExec fortra/impacket; do
  name="${repo##*/}"
  if [ ! -d "$TOOLS_DIR/$name" ]; then
    run git clone "https://github.com/$repo" "$TOOLS_DIR/$name"
  fi
  if [ -d "$TOOLS_DIR/$name" ] && [ ! -d "$TOOLS_DIR/$name/.venv" ]; then
    run python3 -m venv "$TOOLS_DIR/$name/.venv"
    run "$TOOLS_DIR/$name/.venv/bin/pip" install -q -e "$TOOLS_DIR/$name"
  fi
done
# netexec backup: $TOOLS_DIR/NetExec/.venv/bin/nxc
# impacket backup: its examples/*.py scripts land in the venv's bin/, e.g.
#   $TOOLS_DIR/impacket/.venv/bin/secretsdump.py

echo "===> [5/7] BloodHound CE — via Docker (SpecterOps' own recommended install path)"
# bloodhound-cli is SpecterOps' own wrapper around docker compose: it pulls the
# official images, generates docker-compose.yml + a random admin password, and
# starts the stack (Postgres + Neo4j + API + web UI), all sandboxed from the
# host. Preferred over Kali's 'bloodhound'/'neo4j' apt packages + bloodhound-setup
# (a third-party repackaging that trails upstream CE releases and manages Neo4j/
# Postgres directly on the host) for exactly that reason: it's the path upstream
# actually tests and documents, and a bad state resets cleanly with
# 'bloodhound-cli down -v' + 'bloodhound-cli up' instead of debugging host services.
BH_DIR="$TOOLS_DIR/bloodhound"
mkdir -p "$BH_DIR"
BHCLI_URL=$(curl -s https://api.github.com/repos/SpecterOps/bloodhound-cli/releases/latest \
  | jq -r '.assets[].browser_download_url' | grep 'linux-amd64\.tar\.gz$')
if [ -n "$BHCLI_URL" ]; then
  BHCLI_TMP=$(mktemp -d)
  run wget -q "$BHCLI_URL" -O "$BHCLI_TMP/bloodhound-cli.tar.gz"
  run tar -xzf "$BHCLI_TMP/bloodhound-cli.tar.gz" -C "$BHCLI_TMP"
  run install -m 755 "$BHCLI_TMP/bloodhound-cli" /usr/local/bin/bloodhound-cli
  rm -rf "$BHCLI_TMP"
else
  echo "[!] could not resolve latest bloodhound-cli release"
fi
if command -v bloodhound-cli >/dev/null 2>&1; then
  # Running '(cd ... && run ...)' in a subshell would hide a failure here from
  # the FAILURES summary at the end -- array writes inside run() don't escape
  # a subshell. Piping 'y' also makes a re-run idempotent: on a box that
  # already has a prior install, bloodhound-cli asks to overwrite its
  # existing compose YAML and otherwise hangs on EOF with no tty to answer it.
  run bash -c "cd '$BH_DIR' && yes | bloodhound-cli install"
  echo "    ^ admin credentials are printed above by 'install' — save them now, they aren't shown again."
fi
echo "    Start later with: (cd $BH_DIR && sudo bloodhound-cli up)   (stop: sudo bloodhound-cli down)"
echo "    Full reset if something breaks: (cd $BH_DIR && sudo bloodhound-cli down -v && sudo bloodhound-cli up)"
echo "    UI: http://localhost:8080/ui/login"

echo "===> [6/7] Useful Windows binaries -> $WIN_DIR"
# SharpCollection — precompiled C# AD tooling, rebuilt regularly, no build toolchain needed.
# SharpHound.exe is NOT fetched here — apt's sharphound package (step 1) ships
# the prebuilt binary straight from Kali, kept in step with the BloodHound CE
# apt package, so it's no longer best fetched from SharpCollection separately.
SHARP_BASE="https://raw.githubusercontent.com/Flangvik/SharpCollection/master/NetFramework_4.7_Any"
for exe in Rubeus.exe Certify.exe Seatbelt.exe SharpUp.exe Snaffler.exe; do
  run wget -q "$SHARP_BASE/$exe" -O "$WIN_DIR/$exe"
done

# mimikatz — official releases, asset name is constant across tags
run wget -q "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" -O "$WIN_DIR/mimikatz_trunk.zip"
[ -s "$WIN_DIR/mimikatz_trunk.zip" ] && run unzip -oq "$WIN_DIR/mimikatz_trunk.zip" -d "$WIN_DIR/mimikatz"

# winPEAS — PEASS-ng releases, asset names are constant across tags too
run wget -q "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" -O "$WIN_DIR/winPEASx64.exe"
run wget -q "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe" -O "$WIN_DIR/winPEASx86.exe"

# PowerView / PowerUp — classic AD + local-privesc enumeration, still broadly useful
run wget -q "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -O "$WIN_DIR/PowerView.ps1"
run wget -q "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1" -O "$WIN_DIR/PowerUp.ps1"

echo "===> [7/7] Light-terminal colors (dark palette tuned for a WHITE background)"
# Kali's stock dircolors/prompt assume a dark terminal — bright yellow/cyan on
# white is unreadable. This swaps in a dark-on-light palette instead.
cat > "$HOME/.dircolors-light" << 'EOF'
# dircolors db tuned for a light/white terminal background
RESET 0
DIR 01;34
LINK 01;35
EXEC 01;31
FIFO 33
SOCK 01;35
BLK 33;01
CHR 33;01
SETUID 37;41
SETGID 30;43
STICKY_OTHER_WRITABLE 30;42
OTHER_WRITABLE 34;42
STICKY 37;44
.tar 01;31
.zip 01;31
.gz 01;31
.txt 00;30
.md 00;30
EOF

MARK_BEGIN="# >>> byu-cptc light-terminal colors >>>"
MARK_END="# <<< byu-cptc light-terminal colors <<<"
if ! grep -q "$MARK_BEGIN" "$HOME/.zshrc" 2>/dev/null; then
  cat >> "$HOME/.zshrc" << EOF

$MARK_BEGIN
eval "\$(dircolors \$HOME/.dircolors-light)"
# dark palette so the prompt is readable on a white background
PROMPT='%F{17}%n@%m%f %F{54}%~%f %F{22}%#%f '
$MARK_END
EOF
fi

# Best-effort: if this box uses Kali's default xfce4-terminal, drop in a light
# color scheme too. Skipped harmlessly if xfce4-terminal isn't installed.
if command -v xfce4-terminal >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/xfce4/terminal"
  cat > "$HOME/.config/xfce4/terminal/terminalrc" << 'EOF'
[Configuration]
ColorForeground=#000000
ColorBackground=#FFFFFF
ColorCursor=#000000
ColorPalette=#000000;#AA0000;#00AA00;#AA5500;#0000AA;#AA00AA;#00AAAA;#AAAAAA;#555555;#FF5555;#55FF55;#FFFF55;#5555FF;#FF55FF;#55FFFF;#FFFFFF
EOF
  echo "    xfce4-terminal light scheme written — restart the terminal to pick it up."
fi

# Everything above ran as root -- hand it all back to the real operator so
# none of it is left root-owned (and therefore unreadable/unwritable) once
# this script exits and $TARGET_USER is back to being a normal user. A
# specific-paths list missed things in testing (bloodhound-cli writes its
# config/compose files to ~/.config/bloodhound, not the ~/tools/bloodhound
# dir we ran it from), so just sweep the whole home directory instead.
# Exception: on a box accessed over RDP, xrdp-chansrv FUSE-mounts the
# client's shared drives at ~/thinclient_drives (a fixed name in xrdp's own
# source), mounted without 'allow_other' -- so it's only accessible to the
# mounting user (kali), not root, not even to stat it. A find-based skip
# still trips over that denial while just evaluating the exclusion, so this
# walks the directory with a glob instead (no stat needed to match a name)
# and never touches that path at all -- leaving any real chown failure
# elsewhere still visible and tracked, instead of blanket-silencing stderr.
run bash -c '
  shopt -s dotglob nullglob
  for entry in "$2"/*; do
    [ "${entry##*/}" = "thinclient_drives" ] && continue
    chown -R "$1:$1" "$entry"
  done
  chown "$1:$1" "$2"
' _ "$TARGET_USER" "$HOME"

echo
echo "Done."
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "The following steps failed and may need a manual retry:"
  printf '  - %s\n' "${FAILURES[@]}"
else
  echo "Everything completed without a reported failure."
fi
echo
echo "Next steps:"
echo "  1. Open a new shell (or 'source ~/.zshrc') to pick up the prompt/colors."
echo "  2. Open a new kitty window (or ctrl+shift+f5 in an existing one) to pick up the new config."
echo "  3. BloodHound: (cd \$HOME/tools/bloodhound && sudo bloodhound-cli up), then http://localhost:8080/ui/login"
echo "  4. Windows binaries staged in: $WIN_DIR (SharpHound.exe comes from apt — run 'sharphound -h')"
echo "  5. Spraying: 'trevorspray --help' or 'kerbrute passwordspray -d <domain> users.txt <password>'"
echo "  6. Pivoting: 'ligolo-proxy' on this box, copy \$HOME/tools/ligolo/agent(.exe) to the target"
echo "  7. AD tool scripts cloned into \$HOME/tools/ (PKINITtools, krbrelayx, pywhisker, noPac, etc.)"
echo "  8. BloodHound loot: 'bloodyad -H <dc> -d <domain> -u <user> -p <pass> get bloodhound --path ./bh' then upload the zip via File Ingest"
echo "  9. If apt's netexec/impacket act up: backups at \$HOME/tools/NetExec/.venv/bin/nxc and \$HOME/tools/impacket/.venv/bin/<script>.py"
