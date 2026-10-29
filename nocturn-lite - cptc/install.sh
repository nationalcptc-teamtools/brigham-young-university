#!/usr/bin/env bash
# Install the pentest TUI system-wide so every user on this box can run `web`.
#
# Layout:
#   /opt/pentest-tui/web        the real binary (prebuilt amd64, or rebuilt below)
#   /usr/local/bin/web          global launcher (on everyone's PATH)
#
# Wordlists are NOT bundled: the app resolves them from Kali's own
# /usr/share/wordlists at runtime (dirb, dirbuster, seclists). Nothing to copy
# or install here.
#
# Run from inside the app directory on the target box:
#   sudo ./install.sh            # use the prebuilt ./web binary
#   sudo ./install.sh --build    # rebuild from source first (needs Go 1.27+)
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
APP_DIR=/opt/pentest-tui

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: run me with sudo (needs to write /opt and /usr/local/bin)." >&2
	exit 1
fi

# Optionally rebuild so the binary matches this box exactly.
if [ "${1:-}" = "--build" ]; then
	if [ -x "$HOME/go-sdk/go/bin/go" ]; then
		export PATH="$HOME/go-sdk/go/bin:$PATH"
	fi
	if ! command -v go >/dev/null 2>&1; then
		echo "install.sh: --build given but 'go' not found on PATH." >&2
		exit 1
	fi
	echo "==> building web from source"
	( cd "$SRC" && CGO_ENABLED=0 go build -o web . )
fi

if [ ! -f "$SRC/web" ]; then
	echo "install.sh: no 'web' binary in $SRC (run with --build, or build it first)." >&2
	exit 1
fi

echo "==> installing app into $APP_DIR"
install -d -m 0755 "$APP_DIR"
install -m 0755 "$SRC/web" "$APP_DIR/web"
# World-readable files, traversable dirs; nothing group/other-writable.
chmod -R a+rX "$APP_DIR"
chmod 0755 "$APP_DIR/web"

echo "==> writing global launcher /usr/local/bin/web"
cat > /usr/local/bin/web <<'EOF'
#!/usr/bin/env bash
# Global launcher for the pentest TUI. Augments the invoking user's PATH so the
# tools assembled in the TUI (and run with ctrl+r / the browser Run button)
# resolve, then execs the real binary. Mirrors run.sh's runtime PATH setup.
APP_DIR=/opt/pentest-tui

# Go-installed tools (subfinder, dnsx, httpx, nuclei, ffuf, ...) live in the
# caller's GOBIN / GOPATH/bin, which aren't on the default PATH.
if command -v go >/dev/null 2>&1; then
	gobin="$(go env GOBIN 2>/dev/null)"
	if [ -z "$gobin" ]; then
		gopath="$(go env GOPATH 2>/dev/null)"
		[ -n "$gopath" ] && gobin="$gopath/bin"
	fi
	[ -n "$gobin" ] && PATH="$gobin:$PATH"
fi

# pipx/pip user installs (netexec, impacket-*, certipy, ...) and common sbin dirs.
PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin"
export PATH

exec "$APP_DIR/web" "$@"
EOF
chmod 0755 /usr/local/bin/web

echo
echo "Done. Any user can now run:"
echo "    web            # terminal UI"
echo "    web --web      # serve the browser UI"
