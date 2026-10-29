#!/usr/bin/env bash
# Build (if needed) and launch the pentest TUI.
set -e
cd "$(dirname "$0")"

# Go toolchain first, so the `go build` below is found. This repo was set up
# with Go installed to ~/go-sdk/go; only prepend that if it exists, otherwise
# fall back to whatever `go` is already on PATH.
if [ -x "$HOME/go-sdk/go/bin/go" ]; then
	export PATH="$HOME/go-sdk/go/bin:$PATH"
fi

# If Go still isn't available, try to install it automatically. This targets a
# Kali VM (Debian-based) but works on any Linux: it drops a fresh toolchain into
# ~/go-sdk/go, the same path the block above looks for, so re-runs are cheap.
install_go() {
	local version="1.27.0"
	local arch
	case "$(uname -m)" in
		x86_64|amd64)  arch="amd64" ;;
		aarch64|arm64) arch="arm64" ;;
		armv6l|armv7l) arch="armv6l" ;;
		i386|i686)     arch="386" ;;
		*)
			echo "run.sh: unsupported architecture '$(uname -m)' for auto-install." >&2
			return 1
			;;
	esac

	local tarball="go${version}.linux-${arch}.tar.gz"
	local url="https://go.dev/dl/${tarball}"
	local tmp
	tmp="$(mktemp -d)"

	echo "run.sh: 'go' not found — installing Go ${version} to ~/go-sdk/go ..." >&2

	local fetch
	if command -v curl >/dev/null 2>&1; then
		fetch="curl -fsSL -o"
	elif command -v wget >/dev/null 2>&1; then
		fetch="wget -qO"
	else
		echo "run.sh: need curl or wget to download Go (apt-get install -y curl)." >&2
		rm -rf "$tmp"
		return 1
	fi

	if ! $fetch "$tmp/$tarball" "$url"; then
		echo "run.sh: failed to download $url" >&2
		rm -rf "$tmp"
		return 1
	fi

	mkdir -p "$HOME/go-sdk"
	rm -rf "$HOME/go-sdk/go"
	if ! tar -C "$HOME/go-sdk" -xzf "$tmp/$tarball"; then
		echo "run.sh: failed to extract $tarball" >&2
		rm -rf "$tmp"
		return 1
	fi

	rm -rf "$tmp"
	export PATH="$HOME/go-sdk/go/bin:$PATH"
}

if ! command -v go >/dev/null 2>&1; then
	if ! install_go || ! command -v go >/dev/null 2>&1; then
		echo "run.sh: 'go' not found on PATH and auto-install failed." >&2
		echo "Install Go 1.27+ (or put it at ~/go-sdk/go) and try again." >&2
		exit 1
	fi
fi

# Pure-Go build: the --web server pulls in net/http, and the system gcc here
# crashes on cgo, so keep cgo off (the DNS resolver falls back to pure Go).
export CGO_ENABLED=0
go build -o web .

# Put Go-installed tools on PATH so the commands assembled in the TUI and run
# with ctrl+r (or the browser's Run button under --web) can actually find their
# binaries. Most of the catalog
# (subfinder, dnsx, httpx, naabu, katana, gau, waybackurls, ffuf, gobuster,
# nuclei, dalfox, subzy, gowitness, amass, …) is installed with `go install`,
# which drops binaries in $GOBIN or $GOPATH/bin — neither of which is on the
# default PATH. The TUI shells out via `sh -c`, inheriting this PATH, so
# without this they come back "command not found".
gobin="$(go env GOBIN 2>/dev/null)"
if [ -z "$gobin" ]; then
	gopath="$(go env GOPATH 2>/dev/null)"
	[ -n "$gopath" ] && gobin="$gopath/bin"
fi
[ -n "$gobin" ] && export PATH="$gobin:$PATH"

# System pentest tools (sqlmap, nikto, …) sometimes live in sbin / local dirs,
# and the AD-mode tools (netexec, impacket-*, certipy, bloodhound-python, …) are
# usually pipx/pip installs under ~/.local/bin.
export PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin"

# Wordlists are whatever Kali already ships — nothing is bundled or installed.
# The TUI defaults ffuf/gobuster/kerbrute at paths under /usr/share/wordlists
# (dirb, dirbuster, and the seclists symlink), so they resolve out of the box on
# a default Kali install. Just warn if that directory isn't there; the user can
# still pick a different list in the UI, or point PENTEST_TUI_WORDLISTS at one.
if [ -z "${PENTEST_TUI_WORDLISTS:-}" ] && [ ! -d /usr/share/wordlists ]; then
	echo "run.sh: /usr/share/wordlists not found — wordlist defaults may not resolve." >&2
	echo "        Edit the list path in the UI, or set PENTEST_TUI_WORDLISTS." >&2
fi

exec ./web "$@"
