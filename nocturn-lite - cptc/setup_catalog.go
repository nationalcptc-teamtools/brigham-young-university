package main

// setupCatalog holds the engagement-setup helpers you reach for first on a new
// target: dropping the box's IP/hostnames into /etc/hosts so named vhosts
// resolve, and a fully-knobbed nmap so you can dial in exactly the scan you
// want instead of memorising flags. It's the leftmost tab in the web view.
var setupCatalog = []Tool{
	// ── /etc/hosts ─────────────────────────────────────────────────────────
	{
		Name: "add-hosts", Binary: "echo '{IP} {DOMAINS}' | sudo tee -a /etc/hosts",
		Category: "hosts",
		Desc:     "Append an IP → domain(s) line to /etc/hosts (sudo)",
		Flags: []Flag{
			{Flag: "{IP}", Name: "IP address", Kind: KindString, Required: true,
				Placeholder: "10.10.11.23", Desc: "Target IP the names should resolve to"},
			{Flag: "{DOMAINS}", Name: "Domain(s)", Kind: KindString, Required: true,
				Placeholder: "box.htb www.box.htb admin.box.htb",
				Desc:        "One or more space-separated hostnames/vhosts to map to the IP"},
		},
	},
	{
		Name: "show-hosts", Binary: "cat /etc/hosts", Category: "hosts",
		Desc:  "Print the current /etc/hosts so you can confirm your entries",
		Flags: []Flag{},
	},

	// ── nmap ───────────────────────────────────────────────────────────────
	// Every knob you'd reach for, so you can compose a precise scan rather than
	// recalling flags. Target is positional; leave the rest off for a bare scan.
	{
		Name: "nmap", Binary: "nmap", Category: "scan",
		Desc: "Port/service scanner — every scan type, timing, and NSE knob",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|VULNERABLE|CVE-'`,
		Flags: []Flag{
			// Target
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "10.10.11.23", Desc: "Host, CIDR, or hostname to scan"},

			// ── Host discovery ──
			{Flag: "-Pn", Name: "No ping", Kind: KindBool, Enabled: true,
				Desc: "Skip host discovery — treat the host as up (usual for firewalled/HTB boxes)"},
			{Flag: "-sn", Name: "Ping scan", Kind: KindBool,
				Desc: "Ping sweep only — discover live hosts, no port scan"},
			{Flag: "-n", Name: "No DNS", Kind: KindBool,
				Desc: "Never do reverse-DNS resolution (faster)"},
			{Flag: "-R", Name: "Force DNS", Kind: KindBool,
				Desc: "Always resolve, even for hosts that seem down"},
			{Flag: "-6", Name: "IPv6", Kind: KindBool, Desc: "Scan over IPv6"},

			// ── Scan technique ──
			{Flag: "-sS", Name: "SYN scan", Kind: KindBool,
				Desc: "Stealth TCP SYN scan (needs root; the default when privileged)"},
			{Flag: "-sT", Name: "Connect scan", Kind: KindBool,
				Desc: "Full TCP connect scan (no root needed)"},
			{Flag: "-sU", Name: "UDP scan", Kind: KindBool,
				Desc: "UDP port scan (slow; pair with a small -p or --top-ports)"},
			{Flag: "-sA", Name: "ACK scan", Kind: KindBool,
				Desc: "ACK scan — map firewall rules (filtered vs unfiltered)"},

			// ── Ports ──
			{Flag: "-p", Name: "Ports", Kind: KindString,
				Placeholder: "22,80,443 | 1-65535 | U:53,T:80",
				Desc:        "Port spec: list, range, or protocol-qualified"},
			{Flag: "-p-", Name: "All ports", Kind: KindBool,
				Desc: "Scan all 65535 TCP ports (shorthand for -p 1-65535)"},
			{Flag: "-F", Name: "Fast (top 100)", Kind: KindBool,
				Desc: "Fast scan — only the 100 most common ports"},
			{Flag: "--top-ports", Name: "Top N ports", Kind: KindInt,
				Placeholder: "1000", Desc: "Scan the N most common ports"},
			{Flag: "--open", Name: "Open only", Kind: KindBool, Enabled: true,
				Desc: "Only report open (or possibly-open) ports"},

			// ── Detection ──
			{Flag: "-sV", Name: "Version", Kind: KindBool, Enabled: true,
				Desc: "Probe open ports to determine service/version"},
			{Flag: "--version-intensity", Name: "Version intensity", Kind: KindChoice,
				Choices: []string{"", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"},
				Desc:    "0 (light) … 9 (try every probe)"},
			{Flag: "-O", Name: "OS detect", Kind: KindBool,
				Desc: "OS fingerprinting (needs root)"},
			{Flag: "-A", Name: "Aggressive", Kind: KindBool,
				Desc: "OS + version + default scripts + traceroute (loud)"},
			{Flag: "--reason", Name: "Reason", Kind: KindBool,
				Desc: "Show why a port is in a given state"},

			// ── NSE scripts ──
			{Flag: "-sC", Name: "Default scripts", Kind: KindBool, Enabled: true,
				Desc: "Run the default NSE script set (equivalent to --script=default)"},
			{Flag: "--script", Name: "Script(s)", Kind: KindString,
				Placeholder: "vuln | http-enum | smb-enum-shares | safe,discovery",
				Desc:        "NSE script, category, wildcard, or comma-list — be as selective as you like"},
			{Flag: "--script-args", Name: "Script args", Kind: KindString,
				Placeholder: "user=admin,pass=secret",
				Desc:        "Arguments passed to the selected NSE scripts"},

			// ── Timing & performance ──
			{Flag: "-T", Name: "Timing template", Kind: KindChoice,
				Choices: []string{"", "0", "1", "2", "3", "4", "5"},
				Desc:    "0 paranoid … 3 normal … 5 insane (4 is the usual pick)"},
			{Flag: "--min-rate", Name: "Min rate", Kind: KindInt,
				Placeholder: "1000", Desc: "Send at least this many packets/sec"},
			{Flag: "--max-rate", Name: "Max rate", Kind: KindInt,
				Placeholder: "5000", Desc: "Cap packets/sec (be gentle / evade)"},
			{Flag: "--max-retries", Name: "Max retries", Kind: KindInt,
				Placeholder: "2", Desc: "Retransmission cap per probe"},
			{Flag: "--host-timeout", Name: "Host timeout", Kind: KindString,
				Placeholder: "30m", Desc: "Give up on a host after this long"},

			// ── Evasion ──
			{Flag: "-f", Name: "Fragment", Kind: KindBool,
				Desc: "Fragment packets to slip past simple filters"},
			{Flag: "-D", Name: "Decoys", Kind: KindString,
				Placeholder: "RND:5 | 10.0.0.1,ME,10.0.0.2",
				Desc:        "Cloak the scan among decoy source addresses"},
			{Flag: "-S", Name: "Spoof source", Kind: KindString,
				Placeholder: "10.10.14.7", Desc: "Spoof the source IP (usually needs -e/-Pn)"},
			{Flag: "-g", Name: "Source port", Kind: KindInt,
				Placeholder: "53", Desc: "Use a fixed source port (e.g. 53/88 to evade filters)"},
			{Flag: "-e", Name: "Interface", Kind: KindString,
				Placeholder: "tun0", Desc: "Send on this network interface"},

			// ── Output & verbosity ──
			{Flag: "-v", Name: "Verbose", Kind: KindBool, Desc: "Verbose output"},
			{Flag: "-vv", Name: "Very verbose", Kind: KindBool, Desc: "More verbose output"},
			{Flag: "-oN", Name: "Normal out", Kind: KindString,
				Placeholder: "nmap.txt", Desc: "Write normal-format output to file"},
			{Flag: "-oG", Name: "Grepable out", Kind: KindString,
				Placeholder: "nmap.gnmap", Desc: "Write grepable output to file"},
			{Flag: "-oA", Name: "All formats", Kind: KindString,
				Placeholder: "scans/box", Desc: "Write normal+XML+grepable with this basename"},
		},
	},
}
