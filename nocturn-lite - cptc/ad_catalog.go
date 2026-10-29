package main

// adCatalog is the built-in set of Active Directory tools, served by --web as
// the "AD" mode alongside the web catalog. It mirrors the standalone
// active-directory TUI's catalog, ordered roughly along an AD attack workflow:
// enumeration →
// BloodHound collection → Kerberos attacks (user-enum, spraying, AS-REP &
// Kerberoast) → credential dumping → privilege escalation (ACL/delegation/
// shadow-credential abuse) → lateral movement → coercion/relay →
// AD CS (certificate) abuse → directory-object manipulation.
//
// Fill in the domain/user/password (or -H hashes) and the DC, watch the
// command build live, then copy (ctrl+y) or run (ctrl+r). Use only against
// domains you are authorized to test.
var adCatalog = []Tool{
	// ── Enumeration ────────────────────────────────────────────────────────
	{
		Name: "netexec", Binary: "nxc {PROTO}", Category: "enumeration",
		Desc: "Swiss-army AD sweeper (ex-CrackMapExec) across many protocols",
		Grep: `grep -iE '\[\+\]|Pwn3d|\(admin\)'`,
		Flags: []Flag{
			{Flag: "{PROTO}", Name: "Protocol", Kind: KindChoice, Value: "smb",
				Choices: []string{"smb", "ldap", "winrm", "mssql", "rdp", "wmi", "ssh", "ftp", "nfs"},
				Desc:    "Service to target (cycle with ←/→)"},
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "10.10.10.1 / 10.10.10.0/24 / hosts.txt", Desc: "Host, CIDR or file of targets"},
			{Flag: "-u", Name: "Username", Kind: KindString, Placeholder: "administrator", Desc: "User (or a users file)"},
			{Flag: "-p", Name: "Password", Kind: KindString, Placeholder: "Passw0rd!", Desc: "Password (or a passwords file)"},
			{Flag: "-H", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH or :NTHASH", Desc: "Pass-the-hash instead of a password"},
			{Flag: "-d", Name: "Domain", Kind: KindString, Placeholder: "corp.local", Desc: "AD domain (omit with --local-auth)"},
			{Flag: "--local-auth", Name: "Local auth", Kind: KindBool, Desc: "Authenticate against the local SAM, not the domain"},
			{Flag: "--shares", Name: "Shares", Kind: KindBool, Desc: "List SMB shares and access"},
			{Flag: "--users", Name: "Users", Kind: KindBool, Desc: "Enumerate domain users"},
			{Flag: "--sam", Name: "SAM", Kind: KindBool, Desc: "Dump the local SAM hashes"},
			{Flag: "--lsa", Name: "LSA", Kind: KindBool, Desc: "Dump LSA secrets"},
			{Flag: "-M", Name: "Module", Kind: KindString, Placeholder: "spider_plus", Desc: "Run an nxc module"},
			{Flag: "-x", Name: "Command", Kind: KindString, Placeholder: "whoami", Desc: "Execute a command (cmd)"},
			{Flag: "--continue-on-success", Name: "Keep going", Kind: KindBool, Desc: "Don't stop after the first valid login (spraying)"},
		},
	},
	{
		Name: "enum4linux-ng", Binary: "enum4linux-ng", Category: "enumeration",
		Desc: "SMB/RPC/LDAP enumeration (users, shares, groups, policy)",
		Grep: `grep -iE '\[\+\]|Pwn3d|\(admin\)'`,
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "10.10.10.1", Desc: "Target host (DC)"},
			{Flag: "-A", Name: "All (aggressive)", Kind: KindBool, Enabled: true, Desc: "Run all simple enumeration"},
			{Flag: "-u", Name: "Username", Kind: KindString, Placeholder: "guest", Desc: "User for authenticated enum"},
			{Flag: "-p", Name: "Password", Kind: KindString, Placeholder: "", Desc: "Password for authenticated enum"},
			{Flag: "-oJ", Name: "JSON output", Kind: KindString, Placeholder: "enum", Desc: "Write results to <name>.json"},
		},
	},
	{
		Name: "ldapsearch", Binary: "ldapsearch", Category: "enumeration",
		Desc: "Raw LDAP queries against the DC",
		Flags: []Flag{
			{Flag: "-x", Name: "Simple auth", Kind: KindBool, Enabled: true, Desc: "Simple (not SASL) authentication"},
			{Flag: "-H", Name: "LDAP URI", Kind: KindString, Required: true,
				Placeholder: "ldap://10.10.10.1", Desc: "DC LDAP(S) URI"},
			{Flag: "-D", Name: "Bind DN", Kind: KindString, Placeholder: "CN=user,CN=Users,DC=corp,DC=local", Desc: "Bind distinguished name (user)"},
			{Flag: "-w", Name: "Password", Kind: KindString, Placeholder: "Passw0rd!", Desc: "Bind password"},
			{Flag: "-b", Name: "Base DN", Kind: KindString, Placeholder: "DC=corp,DC=local", Desc: "Search base"},
			{Name: "Filter", Kind: KindString, Positional: true,
				Placeholder: "(objectClass=user)", Desc: "LDAP search filter"},
		},
	},
	{
		Name: "rpcclient", Binary: "rpcclient", Category: "enumeration",
		Desc: "Manual MS-RPC queries (enumdomusers, querydispinfo, …)",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "10.10.10.1", Desc: "Target host (DC)"},
			{Flag: "-U", Name: "User", Kind: KindString, Placeholder: "corp.local\\user%Passw0rd!", Desc: "DOMAIN\\user%password (or '' for null)"},
			{Flag: "-N", Name: "No password", Kind: KindBool, Desc: "Null session (no password prompt)"},
			{Flag: "-c", Name: "Command", Kind: KindString, Placeholder: "enumdomusers", Desc: "Semicolon-separated rpcclient commands"},
		},
	},
	{
		Name: "smbclient", Binary: "smbclient", Category: "enumeration",
		Desc: "List and browse SMB shares",
		Flags: []Flag{
			{Flag: "-L", Name: "List shares", Kind: KindString, Placeholder: "//10.10.10.1", Desc: "List shares on this host"},
			{Name: "Share", Kind: KindString, Positional: true,
				Placeholder: "//10.10.10.1/share", Desc: "UNC path of a share to open"},
			{Flag: "-U", Name: "User", Kind: KindString, Placeholder: "corp.local\\user", Desc: "DOMAIN\\user (prompts for password)"},
			{Flag: "-N", Name: "No password", Kind: KindBool, Desc: "Null session"},
		},
	},

	// ── BloodHound collection ──────────────────────────────────────────────
	{
		Name: "bloodhound-python", Binary: "bloodhound-python", Category: "bloodhound",
		Desc: "Python ingestor — collect graph data for BloodHound",
		Flags: []Flag{
			{Flag: "-d", Name: "Domain", Kind: KindString, Required: true,
				Placeholder: "corp.local", Desc: "Target AD domain"},
			{Flag: "-u", Name: "Username", Kind: KindString, Required: true, Placeholder: "user", Desc: "Domain user"},
			{Flag: "-p", Name: "Password", Kind: KindString, Placeholder: "Passw0rd!", Desc: "Password (or use --hashes)"},
			{Flag: "--hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-ns", Name: "Nameserver", Kind: KindString, Placeholder: "10.10.10.1", Desc: "DNS server (usually the DC IP)"},
			{Flag: "-c", Name: "Collection", Kind: KindChoice, Value: "Default",
				Choices: []string{"Default", "All", "DCOnly", "Session", "LoggedOn", "ACL", "Group"}, Desc: "Collection method"},
			{Flag: "--zip", Name: "Zip output", Kind: KindBool, Enabled: true, Desc: "Compress the JSON into a single zip"},
		},
	},

	// ── Kerberos attacks ───────────────────────────────────────────────────
	{
		Name: "kerbrute · userenum", Binary: "kerbrute userenum", Category: "kerberos",
		Desc: "Enumerate valid domain users via Kerberos pre-auth (quiet)",
		Grep: `grep -E '\[\+\] VALID|\$krb5asrep\$'`,
		Flags: []Flag{
			{Flag: "-d", Name: "Domain", Kind: KindString, Required: true,
				Placeholder: "corp.local", Desc: "Target AD domain"},
			{Flag: "--dc", Name: "Domain controller", Kind: KindString, Placeholder: "10.10.10.1", Desc: "DC host/IP"},
			{Name: "User list", Kind: KindString, Positional: true, Required: true,
				Value:       wl("seclists/Usernames/top-usernames-shortlist.txt"),
				Placeholder: wl("seclists/Usernames/top-usernames-shortlist.txt"), Desc: "File of usernames to test (Kali /usr/share/wordlists/seclists)"},
		},
	},
	{
		Name: "kerbrute · passwordspray", Binary: "kerbrute passwordspray", Category: "kerberos",
		Desc: "Spray one password across a user list (watch lockouts!)",
		Flags: []Flag{
			{Flag: "-d", Name: "Domain", Kind: KindString, Required: true,
				Placeholder: "corp.local", Desc: "Target AD domain"},
			{Flag: "--dc", Name: "Domain controller", Kind: KindString, Placeholder: "10.10.10.1", Desc: "DC host/IP"},
			{Name: "User list", Kind: KindString, Positional: true, Required: true,
				Value:       wl("seclists/Usernames/top-usernames-shortlist.txt"),
				Placeholder: wl("seclists/Usernames/top-usernames-shortlist.txt"), Desc: "File of usernames to spray"},
			{Name: "Password", Kind: KindString, Positional: true, Required: true,
				Placeholder: "Spring2026!", Desc: "Single password to try for every user"},
		},
	},
	{
		Name: "GetNPUsers · AS-REP roast", Binary: "GetNPUsers.py", Category: "kerberos",
		Desc: "Harvest AS-REP hashes for users without pre-auth",
		Grep: `grep -E '\$krb5asrep\$'`,
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/", Desc: "domain/ (with -usersfile) or domain/user"},
			{Flag: "-usersfile", Name: "Users file", Kind: KindString, Placeholder: "users.txt", Desc: "File of users to check"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
			{Flag: "-no-pass", Name: "No password", Kind: KindBool, Enabled: true, Desc: "Don't prompt for a password"},
			{Flag: "-request", Name: "Request", Kind: KindBool, Enabled: true, Desc: "Request the TGTs (get the hashes)"},
			{Flag: "-format", Name: "Hash format", Kind: KindChoice, Value: "hashcat",
				Choices: []string{"hashcat", "john"}, Desc: "Crackable output format"},
			{Flag: "-outputfile", Name: "Output file", Kind: KindString, Placeholder: "asrep.txt", Desc: "Write hashes to file"},
		},
	},
	{
		Name: "GetUserSPNs · Kerberoast", Binary: "GetUserSPNs.py", Category: "kerberos",
		Desc: "Request service tickets for SPN accounts and crack offline",
		Grep: `grep -E '\$krb5tgs\$'`,
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!", Desc: "domain/user[:password]"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
			{Flag: "-request", Name: "Request", Kind: KindBool, Enabled: true, Desc: "Request the TGS tickets"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Authenticate with a hash"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use a ccache (KRB5CCNAME)"},
			{Flag: "-outputfile", Name: "Output file", Kind: KindString, Placeholder: "spns.txt", Desc: "Write hashes to file"},
		},
	},
	{
		Name: "getTGT", Binary: "getTGT.py", Category: "kerberos",
		Desc: "Request a TGT (overpass-the-hash) into a .ccache",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!", Desc: "domain/user[:password]"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Overpass-the-hash with an NT hash"},
			{Flag: "-aesKey", Name: "AES key", Kind: KindString, Placeholder: "<hex>", Desc: "AES128/256 key (pass-the-key)"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
		},
	},

	// ── Credential dumping ─────────────────────────────────────────────────
	{
		Name: "secretsdump", Binary: "secretsdump.py", Category: "credentials",
		Desc: "Dump SAM/LSA/NTDS hashes — DCSync with -just-dc",
		Grep: `grep -E ':::'`,
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!@10.10.10.1", Desc: "domain/user[:password]@target"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-just-dc", Name: "DCSync", Kind: KindBool, Desc: "Pull NTDS.dit secrets via replication (needs DCSync rights)"},
			{Flag: "-just-dc-ntlm", Name: "DCSync (NTLM only)", Kind: KindBool, Desc: "DCSync, NTLM hashes only"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use a ccache (KRB5CCNAME)"},
			{Flag: "-outputfile", Name: "Output file", Kind: KindString, Placeholder: "loot", Desc: "Write secrets to <name>.*"},
		},
	},

	// ── Privilege escalation ───────────────────────────────────────────────
	// Turn a foothold into Domain Admin (or any higher-priv principal) by
	// abusing object ACLs, delegation and shadow credentials that BloodHound
	// flags as a path. Each needs an existing write/control right over the
	// target object — these configure or exploit it, they don't grant it.
	{
		Name: "dacledit · grant DCSync", Binary: "dacledit.py", Category: "privilege escalation",
		Desc: "Abuse WriteDACL over the domain: add an ACE giving a principal you control replication rights, then DCSync with secretsdump",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!", Desc: "domain/user[:password] that holds the WriteDACL right"},
			{Flag: "-action", Name: "Action", Kind: KindChoice, Value: "write",
				Choices: []string{"read", "write", "remove", "backup", "restore"}, Desc: "ACL operation (write adds the ACE)"},
			{Flag: "-rights", Name: "Rights", Kind: KindChoice, Value: "DCSync",
				Choices: []string{"DCSync", "WriteMembers", "ResetPassword", "FullControl"}, Desc: "Right to grant the principal"},
			{Flag: "-principal", Name: "Principal", Kind: KindString, Required: true, Placeholder: "lowpriv", Desc: "The account that receives the right (you)"},
			{Flag: "-target-dn", Name: "Target DN", Kind: KindString, Placeholder: "DC=corp,DC=local", Desc: "DN of the object whose DACL you edit (the domain root for DCSync)"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use a ccache (KRB5CCNAME)"},
		},
	},
	{
		Name: "pywhisker · shadow credentials", Binary: "pywhisker.py", Category: "privilege escalation",
		Desc: "With GenericWrite/GenericAll over a target: add a msDS-KeyCredentialLink key, then PKINIT-auth as them (no password reset)",
		Flags: []Flag{
			{Flag: "-d", Name: "Domain", Kind: KindString, Required: true, Placeholder: "corp.local", Desc: "AD domain"},
			{Flag: "-u", Name: "Username", Kind: KindString, Required: true, Placeholder: "lowpriv", Desc: "Your controlling user"},
			{Flag: "-p", Name: "Password", Kind: KindString, Placeholder: "Passw0rd!", Desc: "Password (or use -H)"},
			{Flag: "-H", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "--target", Name: "Victim", Kind: KindString, Required: true, Placeholder: "VICTIM$ or victimuser", Desc: "Object you hold write rights over"},
			{Flag: "--action", Name: "Action", Kind: KindChoice, Value: "add",
				Choices: []string{"add", "list", "remove", "clear", "info"}, Desc: "KeyCredentialLink operation"},
			{Flag: "--dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
		},
	},
	{
		Name: "addcomputer · machine account", Binary: "addcomputer.py", Category: "privilege escalation",
		Desc: "Create a computer account (default MachineAccountQuota=10 lets any user) to own a principal for RBCD",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!", Desc: "domain/user[:password] creating the account"},
			{Flag: "-computer-name", Name: "Name", Kind: KindString, Required: true, Placeholder: "EVILPC$", Desc: "New machine account name (trailing $)"},
			{Flag: "-computer-pass", Name: "Password", Kind: KindString, Placeholder: "Computer123!", Desc: "Password for the new account (random if omitted)"},
			{Flag: "-method", Name: "Method", Kind: KindChoice, Value: "SAMR",
				Choices: []string{"SAMR", "LDAPS"}, Desc: "SAMR works without TLS; LDAPS needs a cert-enabled DC"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
		},
	},
	{
		Name: "rbcd · delegation write", Binary: "rbcd.py", Category: "privilege escalation",
		Desc: "With write rights over a computer: set msDS-AllowedToActOnBehalfOfOtherIdentity so your account can S4U-impersonate anyone to it",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!", Desc: "domain/user[:password] with write over the delegation target"},
			{Flag: "-delegate-to", Name: "Delegate to", Kind: KindString, Required: true, Placeholder: "VICTIM$", Desc: "The computer you will impersonate users against"},
			{Flag: "-delegate-from", Name: "Delegate from", Kind: KindString, Required: true, Placeholder: "EVILPC$", Desc: "The account you control (added to the RBCD list)"},
			{Flag: "-action", Name: "Action", Kind: KindChoice, Value: "write",
				Choices: []string{"read", "write", "remove", "flush"}, Desc: "RBCD operation"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use a ccache (KRB5CCNAME)"},
		},
	},
	{
		Name: "getST · S4U impersonation", Binary: "getST.py", Category: "privilege escalation",
		Desc: "Cash in RBCD/constrained delegation: request a service ticket as any user (e.g. Administrator) to the target service",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/EVILPC$:Computer123!", Desc: "domain/account[:password] that holds the delegation right"},
			{Flag: "-spn", Name: "SPN", Kind: KindString, Required: true, Placeholder: "cifs/victim.corp.local", Desc: "Service to request a ticket for"},
			{Flag: "-impersonate", Name: "Impersonate", Kind: KindString, Required: true, Placeholder: "Administrator", Desc: "User to impersonate via S4U2self/S4U2proxy"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash / pass-the-key"},
			{Flag: "-aesKey", Name: "AES key", Kind: KindString, Placeholder: "<hex>", Desc: "AES128/256 key (pass-the-key)"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
		},
	},

	// ── Lateral movement ───────────────────────────────────────────────────
	{
		Name: "wmiexec", Binary: "wmiexec.py", Category: "lateral movement",
		Desc: "Semi-interactive shell over WMI (no service, quieter)",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!@10.10.10.1", Desc: "domain/user[:password]@target"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use a ccache (KRB5CCNAME)"},
			{Flag: "-no-pass", Name: "No password", Kind: KindBool, Desc: "Don't prompt for a password (with -k/-hashes)"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
		},
	},
	{
		Name: "psexec", Binary: "psexec.py", Category: "lateral movement",
		Desc: "SYSTEM shell via a remote service (loud but reliable)",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!@10.10.10.1", Desc: "domain/user[:password]@target"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use a ccache (KRB5CCNAME)"},
			{Flag: "-no-pass", Name: "No password", Kind: KindBool, Desc: "Don't prompt for a password (with -k/-hashes)"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
		},
	},
	{
		Name: "mssqlclient", Binary: "mssqlclient.py", Category: "lateral movement",
		Desc: "Authenticate to MSSQL — run queries, enable_xp_cmdshell for exec, impersonate logins",
		Flags: []Flag{
			{Name: "Target", Kind: KindString, Positional: true, Required: true,
				Placeholder: "corp.local/user:Passw0rd!@10.10.10.1", Desc: "domain/user[:password]@target"},
			{Flag: "-windows-auth", Name: "Windows auth", Kind: KindBool, Desc: "Use Windows (AD) auth instead of SQL auth"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use a ccache (KRB5CCNAME)"},
			{Flag: "-no-pass", Name: "No password", Kind: KindBool, Desc: "Don't prompt for a password (with -k/-hashes)"},
			{Flag: "-port", Name: "Port", Kind: KindString, Placeholder: "1433", Desc: "MSSQL port (default 1433)"},
			{Flag: "-db", Name: "Database", Kind: KindString, Placeholder: "master", Desc: "Database to connect to"},
		},
	},
	{
		Name: "evil-winrm", Binary: "evil-winrm", Category: "lateral movement",
		Desc: "Interactive WinRM shell (needs Remote Management Users)",
		Flags: []Flag{
			{Flag: "-i", Name: "IP", Kind: KindString, Required: true,
				Placeholder: "10.10.10.1", Desc: "Target host (ctrl+n fills from scope)"},
			{Flag: "-u", Name: "Username", Kind: KindString, Required: true, Placeholder: "administrator", Desc: "User"},
			{Flag: "-p", Name: "Password", Kind: KindString, Placeholder: "Passw0rd!", Desc: "Password (or use -H)"},
			{Flag: "-H", Name: "NTLM hash", Kind: KindString, Placeholder: "NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-d", Name: "Domain", Kind: KindString, Placeholder: "corp.local", Desc: "Domain"},
			{Flag: "-S", Name: "SSL", Kind: KindBool, Desc: "Use HTTPS (port 5986)"},
		},
	},

	// ── Coercion & relay ───────────────────────────────────────────────────
	{
		Name: "responder", Binary: "responder", Category: "coercion/relay",
		Desc: "Poison LLMNR/NBT-NS/MDNS to capture NetNTLM hashes",
		Grep: `grep -iE 'NTLMv[12]|\[\+\]'`,
		Flags: []Flag{
			{Flag: "-I", Name: "Interface", Kind: KindString, Required: true,
				Placeholder: "eth0", Desc: "Network interface to listen on"},
			{Flag: "-A", Name: "Analyze", Kind: KindBool, Desc: "Passive analyze mode (no poisoning)"},
			{Flag: "-w", Name: "WPAD", Kind: KindBool, Desc: "Start the WPAD rogue proxy"},
			{Flag: "-d", Name: "DHCP", Kind: KindBool, Desc: "Enable DHCP poisoning"},
			{Flag: "-v", Name: "Verbose", Kind: KindBool, Desc: "Verbose output"},
		},
	},
	{
		Name: "ntlmrelayx", Binary: "ntlmrelayx.py", Category: "coercion/relay",
		Desc: "Relay captured NTLM auth to other hosts",
		Flags: []Flag{
			{Flag: "-t", Name: "Target", Kind: KindString, Placeholder: "smb://10.10.10.2", Desc: "Single relay target (ctrl+n fills from scope)"},
			{Flag: "-tf", Name: "Target file", Kind: KindString, Placeholder: "targets.txt", Desc: "File of relay targets"},
			{Flag: "-smb2support", Name: "SMB2 support", Kind: KindBool, Enabled: true, Desc: "Support SMB2 clients"},
			{Flag: "-i", Name: "Interactive", Kind: KindBool, Desc: "Open an interactive SMB client on success"},
			{Flag: "-socks", Name: "SOCKS", Kind: KindBool, Desc: "Keep sessions alive behind a SOCKS proxy"},
			{Flag: "--escalate-user", Name: "Escalate user", Kind: KindString, Placeholder: "lowpriv", Desc: "Grant this user DCSync via relayed LDAP"},
		},
	},

	// ── AD CS (certificate) abuse ──────────────────────────────────────────
	{
		Name: "certipy", Binary: "certipy {ACTION}", Category: "adcs",
		Desc: "Find and abuse vulnerable AD Certificate Services templates",
		Grep: `grep -iE 'vulnerable|ESC[0-9]+'`,
		Flags: []Flag{
			{Flag: "{ACTION}", Name: "Action", Kind: KindChoice, Value: "find",
				Choices: []string{"find", "req", "auth", "shadow", "relay", "ca", "account"},
				Desc:    "certipy subcommand (cycle with ←/→)"},
			{Flag: "-u", Name: "Username", Kind: KindString, Placeholder: "user@corp.local", Desc: "user@domain (UPN)"},
			{Flag: "-p", Name: "Password", Kind: KindString, Placeholder: "Passw0rd!", Desc: "Password (or use -hashes)"},
			{Flag: "-hashes", Name: "NTLM hash", Kind: KindString, Placeholder: "LMHASH:NTHASH", Desc: "Pass-the-hash"},
			{Flag: "-dc-ip", Name: "DC IP", Kind: KindString, Placeholder: "10.10.10.1", Desc: "Domain controller IP"},
			{Flag: "-target", Name: "Target (CA/host)", Kind: KindString, Placeholder: "dc.corp.local", Desc: "CA or host for the action"},
			{Flag: "-vulnerable", Name: "Vulnerable only", Kind: KindBool, Enabled: true, Desc: "find: only show vulnerable templates"},
			{Flag: "-enabled", Name: "Enabled only", Kind: KindBool, Desc: "find: only enabled templates"},
			{Flag: "-stdout", Name: "Stdout", Kind: KindBool, Desc: "find: print to stdout instead of files"},
		},
	},

	// ── Directory-object manipulation ──────────────────────────────────────
	{
		Name: "bloodyAD", Binary: "bloodyAD", Category: "ad objects",
		Desc: "Read/write AD objects & ACLs (add members, set passwords, …)",
		Flags: []Flag{
			{Flag: "--host", Name: "DC host", Kind: KindString, Required: true,
				Placeholder: "10.10.10.1", Desc: "Domain controller host/IP"},
			{Flag: "-d", Name: "Domain", Kind: KindString, Placeholder: "corp.local", Desc: "AD domain"},
			{Flag: "-u", Name: "Username", Kind: KindString, Placeholder: "user", Desc: "Domain user"},
			{Flag: "-p", Name: "Password", Kind: KindString, Placeholder: "Passw0rd! or :NTHASH", Desc: "Password or :NTHASH"},
			{Flag: "-k", Name: "Kerberos", Kind: KindBool, Desc: "Use Kerberos (ccache)"},
			{Name: "Action", Kind: KindString, Positional: true, Required: true,
				Placeholder: "get writable", Desc: "bloodyAD subcommand, e.g. 'get writable' or 'add user ...'"},
		},
	},
}
