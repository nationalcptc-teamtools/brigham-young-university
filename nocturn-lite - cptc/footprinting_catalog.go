package main

// footprintingCatalog turns the per-service enumeration cheat sheets from the
// HTBNotes vault ("02 - Information Gathering / Service Enumeration") into a
// builder: pick a service, drop in the target's IP/host (and a user, password,
// share, or community string where the command needs one) and copy a
// ready-to-run enumeration one-liner. It walks the usual service-by-service
// footprinting checklist — DNS, FTP, SMB/RPC, NFS, SMTP, IMAP/POP3, SNMP, SSH,
// MySQL, MSSQL, Oracle TNS, IPMI, RDP, WinRM, WMI, R-Services, RSYNC — plus the
// infrastructure-level OSINT you reach for first.
//
// Every target value is a {PLACEHOLDER} woven into the command template in
// place (see Tool.Command / isPlaceholder), the same mechanism the reverse-shell
// catalog uses. These are standard enumeration commands for authorized
// pentests, CTFs, and lab boxes (HTB/THM); the engagement-scope guard that
// covers the other modes applies here too when a command is Run.
var footprintingCatalog = []Tool{

	// ── Infrastructure / OSINT ───────────────────────────────────────────────
	{
		Name: "osint: crt.sh certs", Binary: `curl -s "https://crt.sh/?q={DOMAIN}&output=json" | jq .`,
		Category: "infrastructure",
		Desc:     "Certificate-transparency lookup — pull every cert crt.sh knows for a domain",
		Flags:    []Flag{fpDomain()},
	},
	{
		Name:     "osint: crt.sh subdomains",
		Binary:   `curl -s "https://crt.sh/?q={DOMAIN}&output=json" | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u`,
		Category: "infrastructure",
		Desc:     "Same crt.sh query, filtered down to a clean sorted list of (sub)domain names",
		Flags:    []Flag{fpDomain()},
	},
	{
		Name: "osint: shodan host", Binary: "shodan host {IP}", Category: "infrastructure",
		Desc:  "Everything Shodan has indexed for an IP — open ports, banners, tech, history",
		Flags: []Flag{fpIP()},
	},

	// ── DNS (53) ─────────────────────────────────────────────────────────────
	{
		Name: "dns: dig SOA", Binary: "dig soa {DOMAIN} @{NS}", Category: "DNS (53)",
		Desc:  "Who runs this zone — Start Of Authority record (primary NS + admin contact)",
		Flags: []Flag{fpDomain(), fpNS()},
	},
	{
		Name: "dns: dig NS", Binary: "dig ns {DOMAIN} @{NS}", Category: "DNS (53)",
		Desc:  "Name-server records for the domain from a specific resolver",
		Flags: []Flag{fpDomain(), fpNS()},
	},
	{
		Name: "dns: dig ANY", Binary: "dig any {DOMAIN} @{NS}", Category: "DNS (53)",
		Desc:  "Ask for every record type at once — quick way to surface extra records",
		Flags: []Flag{fpDomain(), fpNS()},
	},
	{
		Name: "dns: zone transfer (AXFR)", Binary: "dig axfr {DOMAIN} @{NS}", Category: "DNS (53)",
		Desc:  "Attempt a full zone transfer — dumps every record if the NS allows AXFR",
		Flags: []Flag{fpDomain(), fpNS()},
	},
	{
		Name: "dns: version.bind", Binary: "dig CH TXT version.bind {IP}", Category: "DNS (53)",
		Desc:  "CHAOS-class query for the BIND version string (fingerprint the resolver)",
		Flags: []Flag{fpIP()},
	},
	{
		Name:     "dns: dnsenum brute",
		Binary:   "dnsenum --dnsserver {NS} --enum -p 0 -s 0 -o found_subdomains.txt -f {WORDLIST} {DOMAIN}",
		Category: "DNS (53)",
		Desc:     "Brute-force subdomains against a nameserver using a wordlist",
		Flags: []Flag{
			fpNS(), fpDomain(),
			{Flag: "{WORDLIST}", Name: "Wordlist", Kind: KindString, Required: true,
				Placeholder: "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
				Desc:        "Subdomain wordlist to feed dnsenum"},
		},
	},
	{
		Name: "dns: nmap", Binary: "sudo nmap {IP} -p53 -sV -sC", Category: "DNS (53)",
		Desc:  "Version + default-script scan of the DNS port",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags: []Flag{fpIP()},
	},

	// ── FTP (21) ─────────────────────────────────────────────────────────────
	{
		Name: "ftp: connect", Binary: "ftp {IP}", Category: "FTP (21)",
		Desc:  "Interact with the FTP service (try anonymous / anonymous)",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "ftp: nc banner", Binary: "nc -nv {IP} 21", Category: "FTP (21)",
		Desc:  "Grab the FTP banner with netcat",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "ftp: openssl (FTPS)", Binary: "openssl s_client -connect {IP}:21 -starttls ftp",
		Category: "FTP (21)",
		Desc:     "Talk to the FTP service over an encrypted (STARTTLS) connection",
		Flags:    []Flag{fpIP()},
	},
	{
		Name: "ftp: wget mirror (anon)", Binary: "wget -m --no-passive ftp://anonymous:anonymous@{IP}",
		Category: "FTP (21)",
		Desc:     "Recursively download every file from an anonymous FTP server",
		Flags:    []Flag{fpIP()},
	},
	{
		Name: "ftp: nmap", Binary: "sudo nmap -sV -p21 -sC -A {IP}", Category: "FTP (21)",
		Desc:  "Version, default scripts, and aggressive detection on the FTP port",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags: []Flag{fpIP()},
	},

	// ── SMB / RPC (137-139, 445) ─────────────────────────────────────────────
	{
		Name: "smb: list shares (null)", Binary: "smbclient -N -L //{IP}", Category: "SMB/RPC (445)",
		Desc:  "List shares using a null (unauthenticated) session",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "smb: connect share", Binary: "smbclient //{IP}/{SHARE}", Category: "SMB/RPC (445)",
		Desc:  "Connect to a specific SMB share",
		Flags: []Flag{fpIP(), fpShare()},
	},
	{
		Name: "smb: rpcclient (null)", Binary: `rpcclient -U "" {IP}`, Category: "SMB/RPC (445)",
		Desc:  "Interact with the target over MS-RPC using a null session",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "smb: samrdump", Binary: "samrdump.py {IP}", Category: "SMB/RPC (445)",
		Desc:  "Enumerate users via Impacket's SAMR dump",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "smb: smbmap", Binary: "smbmap -H {IP}", Category: "SMB/RPC (445)",
		Desc:  "Enumerate shares and the access level you have to each",
		Grep: `grep -iE 'READ|WRITE'`,
		Flags: []Flag{fpIP()},
	},
	{
		Name: "smb: crackmapexec (null)", Binary: "crackmapexec smb {IP} --shares -u '' -p ''",
		Category: "SMB/RPC (445)",
		Desc:     "Enumerate shares with a null session via CME/NetExec",
		Flags:    []Flag{fpIP()},
	},
	{
		Name: "smb: enum4linux-ng", Binary: "enum4linux-ng.py {IP} -A", Category: "SMB/RPC (445)",
		Desc:  "Do-everything SMB enumeration (users, shares, groups, policy)",
		Grep: `grep -iE 'user|share|group|password policy'`,
		Flags: []Flag{fpIP()},
	},
	{
		Name: "smb: nmap scripts", Binary: "sudo nmap {IP} -p139,445 -sV -sC --script smb-enum-shares,smb-os-discovery",
		Category: "SMB/RPC (445)",
		Desc:     "Version scan plus the SMB share/OS-discovery NSE scripts",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags:    []Flag{fpIP()},
	},

	// ── NFS (111, 2049) ──────────────────────────────────────────────────────
	{
		Name: "nfs: showmount", Binary: "showmount -e {IP}", Category: "NFS (2049)",
		Desc:  "List the NFS exports the server is offering",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "nfs: mount share", Binary: "sudo mount -t nfs {IP}:/{SHARE} ./target-NFS/ -o nolock",
		Category: "NFS (2049)",
		Desc:     "Mount an export locally (mkdir ./target-NFS first) to browse it",
		Flags:    []Flag{fpIP(), fpShare()},
	},
	{
		Name: "nfs: nmap", Binary: "sudo nmap {IP} -p111,2049 -sV -sC", Category: "NFS (2049)",
		Desc:  "Version + default scripts on the portmapper and NFS ports",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags: []Flag{fpIP()},
	},
	{
		Name: "nfs: nmap scripts", Binary: "sudo nmap --script nfs* {IP} -sV -p111,2049",
		Category: "NFS (2049)",
		Desc:     "Run every NFS NSE script (shows exports, stats, ACLs)",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags:    []Flag{fpIP()},
	},

	// ── SMTP (25) ────────────────────────────────────────────────────────────
	{
		Name: "smtp: telnet", Binary: "telnet {IP} 25", Category: "SMTP (25)",
		Desc:  "Talk to the mail server by hand (HELO/VRFY/EXPN to enumerate users)",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "smtp: nmap", Binary: "sudo nmap {IP} -sC -sV -p25", Category: "SMTP (25)",
		Desc:  "Version + default-script scan of the SMTP port",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags: []Flag{fpIP()},
	},
	{
		Name: "smtp: open-relay check", Binary: "sudo nmap {IP} -p25 --script smtp-open-relay -v",
		Category: "SMTP (25)",
		Desc:     "Test whether the server is an open relay",
		Flags:    []Flag{fpIP()},
	},

	// ── IMAP / POP3 (143, 993, 110, 995) ─────────────────────────────────────
	{
		Name: "imap: curl login", Binary: "curl -k 'imaps://{IP}' --user {USER}:{PASS}",
		Category: "IMAP/POP3",
		Desc:     "Log in to IMAPS and list the mailbox with cURL",
		Flags:    []Flag{fpIP(), fpUser(), fpPass()},
	},
	{
		Name: "imap: openssl", Binary: "openssl s_client -connect {IP}:imaps", Category: "IMAP/POP3",
		Desc:  "Open a TLS session to the IMAPS service (then LOGIN / LIST by hand)",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "pop3: openssl", Binary: "openssl s_client -connect {IP}:pop3s", Category: "IMAP/POP3",
		Desc:  "Open a TLS session to the POP3S service (USER/PASS/RETR by hand)",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "imap/pop3: nmap", Binary: "sudo nmap {IP} -sV -p110,143,993,995 -sC",
		Category: "IMAP/POP3",
		Desc:     "Version + default-script scan across the IMAP/POP3 (plain + TLS) ports",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags:    []Flag{fpIP()},
	},

	// ── SNMP (161, 162) ──────────────────────────────────────────────────────
	{
		Name: "snmp: snmpwalk", Binary: "snmpwalk -v2c -c {COMMUNITY} {IP}", Category: "SNMP (161)",
		Desc:  "Walk the MIB tree with a known community string",
		Grep: `grep -iE 'string:|hrSWRunName|hrSWInstalledName|user'`,
		Flags: []Flag{fpCommunity(), fpIP()},
	},
	{
		Name: "snmp: onesixtyone", Binary: "onesixtyone -c community-strings.list {IP}",
		Category: "SNMP (161)",
		Desc:     "Brute-force community strings from a wordlist",
		Flags:    []Flag{fpIP()},
	},
	{
		Name: "snmp: braa", Binary: "braa {COMMUNITY}@{IP}:.1.*", Category: "SNMP (161)",
		Desc:  "Fast bulk SNMP OID walker once you have a community string",
		Flags: []Flag{fpCommunity(), fpIP()},
	},

	// ── SSH (22) ─────────────────────────────────────────────────────────────
	{
		Name: "ssh: login", Binary: "ssh {USER}@{IP}", Category: "SSH (22)",
		Desc:  "Log in over SSH with a username",
		Flags: []Flag{fpUser(), fpIP()},
	},
	{
		Name: "ssh: key login", Binary: "ssh -i {KEY} {USER}@{IP}", Category: "SSH (22)",
		Desc:  "Log in with a private key (chmod 600 the key first)",
		Flags: []Flag{
			{Flag: "{KEY}", Name: "Private key", Kind: KindString, Required: true,
				Placeholder: "~/.ssh/id_rsa_htb", Desc: "Path to the private key file"},
			fpUser(), fpIP(),
		},
	},
	{
		Name: "ssh: force password auth", Binary: "ssh {USER}@{IP} -o PreferredAuthentications=password",
		Category: "SSH (22)",
		Desc:     "Force password authentication (skip key/GSSAPI methods)",
		Flags:    []Flag{fpUser(), fpIP()},
	},
	{
		Name: "ssh: audit", Binary: "ssh-audit {IP}", Category: "SSH (22)",
		Desc:  "Audit supported algorithms/config and flag weak crypto",
		Grep: `grep -iE 'warn|fail|vulnerable|\(rem\)'`,
		Flags: []Flag{fpIP()},
	},

	// ── MySQL (3306) ─────────────────────────────────────────────────────────
	{
		Name: "mysql: login", Binary: "mysql -u {USER} -p{PASS} -h {IP}", Category: "MySQL (3306)",
		Desc:  "Connect to MySQL (no space between -p and the password)",
		Flags: []Flag{fpUser(), fpPass(), fpIP()},
	},
	{
		Name: "mysql: login (no cert verify)", Binary: "mysql -u {USER} -p{PASS} -h {IP} --ssl-verify-server-cert=FALSE",
		Category: "MySQL (3306)",
		Desc:     "Same, but skip server-cert verification (fixes self-signed-cert chain errors)",
		Flags:    []Flag{fpUser(), fpPass(), fpIP()},
	},
	{
		Name: "mysql: nmap", Binary: "sudo nmap {IP} -sV -sC -p3306 --script mysql*",
		Category: "MySQL (3306)",
		Desc:     "Run the MySQL NSE scripts (info, empty-password, users, variables)",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags:    []Flag{fpIP()},
	},

	// ── MSSQL (1433) ─────────────────────────────────────────────────────────
	{
		Name: "mssql: mssqlclient (winauth)", Binary: "mssqlclient.py {USER}@{IP} -windows-auth",
		Category: "MSSQL (1433)",
		Desc:     "Impacket MSSQL client using Windows authentication",
		Flags:    []Flag{fpUser(), fpIP()},
	},
	{
		Name:     "mssql: nmap scripts",
		Binary:   "sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p1433 {IP}",
		Category: "MSSQL (1433)",
		Desc:     "The full MSSQL NSE sweep (info, empty sa, xp_cmdshell, tables, hashes)",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags:    []Flag{fpIP()},
	},

	// ── Oracle TNS (1521) ────────────────────────────────────────────────────
	{
		Name: "oracle: SID brute", Binary: "sudo nmap -p1521 -sV {IP} --open --script oracle-sid-brute",
		Category: "Oracle TNS (1521)",
		Desc:     "Brute-force the Oracle SID (needed before you can log in)",
		Flags:    []Flag{fpIP()},
	},
	{
		Name: "oracle: odat all", Binary: "./odat.py all -s {IP}", Category: "Oracle TNS (1521)",
		Desc:  "Run every ODAT check against the TNS listener",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "oracle: sqlplus", Binary: "sqlplus {USER}/{PASS}@{IP}/XE", Category: "Oracle TNS (1521)",
		Desc:  "Log in to the database as a user (SID defaults to XE here)",
		Flags: []Flag{fpUser(), fpPass(), fpIP()},
	},
	{
		Name: "oracle: sqlplus sysdba", Binary: "sqlplus {USER}/{PASS}@{IP}/XE as sysdba",
		Category: "Oracle TNS (1521)",
		Desc:     "Try to log in with SYSDBA (admin) privileges",
		Flags:    []Flag{fpUser(), fpPass(), fpIP()},
	},

	// ── IPMI (623) ───────────────────────────────────────────────────────────
	{
		Name: "ipmi: nmap version", Binary: "sudo nmap -sU --script ipmi-version -p623 {IP}",
		Category: "IPMI (623)",
		Desc:     "UDP scan for the IPMI version (2.0 is vulnerable to the RAKP hash leak)",
		Flags:    []Flag{fpIP()},
	},
	{
		Name:     "ipmi: dump hashes (msf)",
		Binary:   `msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {IP}; run"`,
		Category: "IPMI (623)",
		Desc:     "Leak RAKP password hashes via the Metasploit IPMI module",
		Flags:    []Flag{fpIP()},
	},
	{
		Name:     "ipmi: crack HP iLO hash",
		Binary:   "hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u",
		Category: "IPMI (623)",
		Desc:     "Crack an HP iLO RAKP hash (default 8-char [0-9A-Z] factory password)",
		Flags:    []Flag{},
	},

	// ── RDP (3389) ───────────────────────────────────────────────────────────
	{
		Name: "rdp: nmap", Binary: "nmap -sV -sC {IP} -p3389 --script rdp*", Category: "RDP (3389)",
		Desc:  "Version scan plus the RDP NSE scripts (NLA, encryption, CVE checks)",
		Grep: `grep -E '^[0-9]+/(tcp|udp) +open|^\|'`,
		Flags: []Flag{fpIP()},
	},
	{
		Name: "rdp: xfreerdp", Binary: `xfreerdp /u:{USER} /p:{PASS} /v:{IP}`, Category: "RDP (3389)",
		Desc:  "Connect to the RDP service with credentials",
		Flags: []Flag{fpUser(), fpPass(), fpIP()},
	},

	// ── WinRM (5985, 5986) ───────────────────────────────────────────────────
	{
		Name: "winrm: nmap", Binary: "nmap -sV -sC {IP} -p5985,5986 --disable-arp-ping -n",
		Category: "WinRM (5985)",
		Desc:     "Check whether WinRM (HTTP 5985 / HTTPS 5986) is listening",
		Flags:    []Flag{fpIP()},
	},
	{
		Name: "winrm: evil-winrm", Binary: "evil-winrm -i {IP} -u {USER} -p {PASS}",
		Category: "WinRM (5985)",
		Desc:     "Get an interactive PowerShell session over WinRM with credentials",
		Flags:    []Flag{fpIP(), fpUser(), fpPass()},
	},

	// ── WMI (135) ────────────────────────────────────────────────────────────
	{
		Name: "wmi: wmiexec", Binary: `wmiexec.py {USER}:{PASS}@{IP} "hostname"`, Category: "WMI (135)",
		Desc:  "Run a command over WMI/DCOM with Impacket (semi-interactive shell)",
		Flags: []Flag{fpUser(), fpPass(), fpIP()},
	},

	// ── R-Services (512, 513, 514) ───────────────────────────────────────────
	{
		Name: "rservices: nmap", Binary: "sudo nmap -sV -p512,513,514 {IP}", Category: "R-Services",
		Desc:  "Fingerprint the Berkeley r-services (rexec/rlogin/rsh)",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "rservices: rlogin", Binary: "rlogin {IP} -l {USER}", Category: "R-Services",
		Desc:  "Log in via rlogin (abuses trusted .rhosts / hosts.equiv entries)",
		Flags: []Flag{fpIP(), fpUser()},
	},
	{
		Name: "rservices: rusers", Binary: "rusers -al {IP}", Category: "R-Services",
		Desc:  "List users currently logged in on the target",
		Flags: []Flag{fpIP()},
	},

	// ── RSYNC (873) ──────────────────────────────────────────────────────────
	{
		Name: "rsync: nmap", Binary: "sudo nmap -sV -p873 {IP}", Category: "RSYNC (873)",
		Desc:  "Fingerprint the rsync daemon",
		Flags: []Flag{fpIP()},
	},
	{
		Name: "rsync: list modules", Binary: "rsync -av --list-only rsync://{IP}/{SHARE}",
		Category: "RSYNC (873)",
		Desc:     "List the contents of an rsync module/share (try with no share to list modules)",
		Flags:    []Flag{fpIP(), fpShare()},
	},
}

// ── shared footprinting flag helpers ─────────────────────────────────────────
// Each returns a fresh Flag value so reusing one across tools never aliases.

func fpIP() Flag {
	return Flag{Flag: "{IP}", Name: "Target IP", Kind: KindString, Required: true,
		Placeholder: "10.129.14.128", Desc: "Target host or IP to enumerate"}
}

func fpDomain() Flag {
	return Flag{Flag: "{DOMAIN}", Name: "Domain", Kind: KindString, Required: true,
		Placeholder: "inlanefreight.htb", Desc: "Domain name to query"}
}

func fpNS() Flag {
	return Flag{Flag: "{NS}", Name: "Nameserver", Kind: KindString, Required: true,
		Placeholder: "10.129.14.128", Desc: "DNS server to send the query to"}
}

func fpUser() Flag {
	return Flag{Flag: "{USER}", Name: "Username", Kind: KindString, Required: true,
		Placeholder: "admin", Desc: "Account to authenticate as"}
}

func fpPass() Flag {
	return Flag{Flag: "{PASS}", Name: "Password", Kind: KindString, Required: true,
		Placeholder: "Password123", Desc: "Password for the account"}
}

func fpShare() Flag {
	return Flag{Flag: "{SHARE}", Name: "Share", Kind: KindString, Required: true,
		Placeholder: "share", Desc: "Share / export / module name"}
}

func fpCommunity() Flag {
	return Flag{Flag: "{COMMUNITY}", Name: "Community string", Kind: KindString, Required: true,
		Placeholder: "public", Desc: "SNMP community string"}
}
