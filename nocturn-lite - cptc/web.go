package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// Web view. Serves the same tool catalog as the TUI as a single localhost page
// where you pick a tool, fill its flags, and copy — or run — the assembled
// command, with the command's output streamed back live. Running is gated by
// the active project's scope exactly like ctrl+r in the TUI.
const (
	webTitle    = "NocTurn Lite"
	defaultPort = 7702
)

//go:embed webui/index.html
var indexHTML string

// The server serves several catalogs ("modes"): the web pentest catalog, the
// Active Directory catalog, and the Linux local-privilege-escalation catalog.
// All modes share one project store, so an engagement and its scope are visible
// whichever catalog you're working in.
type webMode struct {
	Key   string // stable id used in URLs and API calls
	Label string // shown on the banner toggle
	tools func() []Tool
}

// webModes returns the available modes. It is a function (not a package var) so
// the web catalog is read after payloads.go's init() has appended to it.
func webModes() []webMode {
	return []webMode{
		{Key: "setup", Label: "Setup", tools: func() []Tool { return setupCatalog }},
		{Key: "footprinting", Label: "Footprinting", tools: func() []Tool { return footprintingCatalog }},
		{Key: "web", Label: "Web", tools: func() []Tool { return catalog }},
		{Key: "ad", Label: "AD", tools: func() []Tool { return adCatalog }},
		{Key: "linux", Label: "Linux", tools: func() []Tool { return linuxCatalog }},
		{Key: "revshell", Label: "Reverse Shells", tools: func() []Tool { return revshellCatalog }},
		{Key: "filetransfer", Label: "File Transfers", tools: func() []Tool { return fileTransferCatalog }},
	}
}

// modeFor resolves a mode key (defaulting to the first, "web", when empty or
// unknown-but-blank) to its definition.
func modeFor(key string) (webMode, bool) {
	modes := webModes()
	if key == "" {
		return modes[0], true
	}
	for _, m := range modes {
		if m.Key == key {
			return m, true
		}
	}
	return webMode{}, false
}

// runWeb serves the catalog on localhost and, if open is set, points the
// default browser at it. It blocks until the process exits.
func runWeb(port int, open bool) error {
	// Load .env (if present) before anything resolves entitlements, so the
	// Supabase/license config is in the environment.
	loadDotEnv()

	page, err := buildPage()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("port %d is already in use (already running? try --port)", port)
		}
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(page)
	})

	// Monetization: the browser reads this to show locks / an upgrade prompt.
	// The server still enforces each paid feature on its own endpoint below.
	mux.HandleFunc("GET /api/entitlement", handleEntitlement)
	// Live refresh of the shared project list. The mode param is accepted (and
	// validated) for backward compatibility, but the list is the same for all.
	mux.HandleFunc("GET /api/projects", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if mode := r.URL.Query().Get("mode"); mode != "" {
			if _, ok := modeFor(mode); !ok {
				http.Error(w, "unknown mode", http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		projects := loadProjects()
		if projects == nil {
			projects = []Project{}
		}
		json.NewEncoder(w).Encode(projects)
	})
	mux.HandleFunc("POST /api/projects", handleProjects)
	// Paid features: assembling-and-running commands and the live terminals are
	// gated behind an active plan (requireFeature → 402 when locked). In the
	// default local/self-hosted mode every operator is Pro, so this is a no-op
	// until LICENSE_MODE=supabase enforces subscriptions.
	mux.HandleFunc("POST /api/run", requireFeature(FeatureRun, handleRun))
	// Interactive shell(s) for the split-screen terminal workspace. Each socket
	// is one PTY-backed shell; the page opens one per pane.
	mux.HandleFunc("GET /api/terminal", requireFeature(FeatureTerminal, handleTerminal))

	url := fmt.Sprintf("http://localhost:%d/", port)
	fmt.Printf("%s → %s   (ctrl+c to stop)\n", webTitle, url)
	fmt.Println("commands run on THIS machine, with the same scope block as the TUI's ctrl+r")
	if open {
		openBrowser(url)
	}
	return http.Serve(ln, mux)
}

// buildPage fills index.html's placeholders: the title and a JSON blob holding
// each mode's catalog and saved projects. The catalogs are baked in once at
// startup, so rebuild the binary after editing catalog.go / ad_catalog.go.
func buildPage() ([]byte, error) {
	modes := make([]map[string]any, 0, len(webModes()))
	shared := loadProjects()
	if shared == nil {
		shared = []Project{}
	}
	for _, m := range webModes() {
		projects := shared
		modes = append(modes, map[string]any{
			"key":      m.Key,
			"label":    m.Label,
			"catalog":  m.tools(),
			"projects": projects,
		})
	}
	// json.Marshal escapes <, > and &, so the result is safe inside <script>.
	cfg, err := json.Marshal(map[string]any{
		"title": webTitle,
		"modes": modes,
	})
	if err != nil {
		return nil, err
	}
	r := strings.NewReplacer("{{TITLE}}", html.EscapeString(webTitle), "{{CONFIG}}", string(cfg))
	return []byte(r.Replace(indexHTML)), nil
}

// projReq is the body the page POSTs to /api/projects to mutate the project
// list. Op is one of create, delete, addScope, removeScope; Scope is "in" or
// "out" for the scope ops.
type projReq struct {
	Mode  string `json:"mode"`
	Op    string `json:"op"`
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Value string `json:"value"`
}

// handleProjects creates, deletes, or edits the scope of projects — the same
// list the TUI's project panel manages, in the same projects.json. It loads the
// file fresh, applies one change, and saves, so edits made here and in the TUI
// don't clobber each other wholesale. It returns the updated list.
func handleProjects(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req projReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Mode != "" {
		if _, ok := modeFor(req.Mode); !ok {
			http.Error(w, "unknown mode", http.StatusBadRequest)
			return
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	projects := loadProjects()
	idx := -1
	for i, p := range projects {
		if p.Name == name {
			idx = i
			break
		}
	}

	switch req.Op {
	case "create":
		if idx >= 0 {
			http.Error(w, "a project with that name already exists", http.StatusConflict)
			return
		}
		projects = append(projects, Project{Name: name})
	case "delete":
		if idx >= 0 {
			projects = append(projects[:idx], projects[idx+1:]...)
		}
	case "addScope", "removeScope":
		if idx < 0 {
			http.Error(w, "no such project", http.StatusNotFound)
			return
		}
		val := strings.TrimSpace(req.Value)
		if val == "" {
			http.Error(w, "value required", http.StatusBadRequest)
			return
		}
		list := &projects[idx].InScope
		if req.Scope == "out" {
			list = &projects[idx].OutScope
		}
		if req.Op == "addScope" {
			if !contains(*list, val) {
				*list = append(*list, val)
			}
		} else {
			*list = removeString(*list, val)
		}
	default:
		http.Error(w, "unknown op", http.StatusBadRequest)
		return
	}

	if err := saveProjectsList(projects); err != nil {
		http.Error(w, "could not save projects", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(projects)
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func removeString(ss []string, v string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

// runReq is the body the page POSTs to /api/run: the index of the tool in the
// catalog and, parallel to that tool's Flags, the edited value/enabled state,
// plus the name of the active project (for the scope check).
type runReq struct {
	Mode    string `json:"mode"`
	Tool    int    `json:"tool"`
	Project string `json:"project"`
	Values  []struct {
		Value   string `json:"value"`
		Enabled bool   `json:"enabled"`
	} `json:"values"`
}

// handleRun rebuilds the command from the authoritative catalog (never from a
// client-supplied command string), enforces the same required-field and
// out-of-scope checks as the TUI's ctrl+r, then runs it and streams combined
// stdout/stderr back as newline-delimited JSON. The command is tied to the
// request context, so the browser aborting the fetch kills it.
func handleRun(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req runReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	mode, ok := modeFor(req.Mode)
	if !ok {
		http.Error(w, "unknown mode", http.StatusBadRequest)
		return
	}
	tools := mode.tools()
	if req.Tool < 0 || req.Tool >= len(tools) {
		http.Error(w, "no such tool", http.StatusBadRequest)
		return
	}

	// Apply the submitted values onto a fresh clone of the catalog tool.
	t := tools[req.Tool].clone()
	for i := range t.Flags {
		if i >= len(req.Values) {
			break
		}
		switch t.Flags[i].Kind {
		case KindBool:
			t.Flags[i].Enabled = req.Values[i].Enabled
		default:
			t.Flags[i].Value = req.Values[i].Value
		}
	}

	if miss := t.MissingRequired(); len(miss) > 0 {
		writeRunError(w, "missing required: "+strings.Join(miss, ", "))
		return
	}
	cmdStr := t.Command()
	if hit := outOfScopeHitFor(req.Project, cmdStr); hit != "" {
		writeRunError(w, "blocked — command targets out-of-scope: "+hit)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // don't let a proxy buffer the stream
	enc := json.NewEncoder(w)
	send := func(v any) {
		enc.Encode(v)
		flusher.Flush()
	}
	send(map[string]any{"line": "$ " + cmdStr})

	// Run through the shell (so compound binaries like "gobuster dir" and the
	// quoting from Command() behave as printed), tied to the request context.
	c := exec.CommandContext(r.Context(), "sh", "-c", cmdStr)
	pr, pw := io.Pipe()
	c.Stdout = pw
	c.Stderr = pw

	done := make(chan error, 1)
	go func() {
		err := c.Run()
		pw.Close() // unblock the scanner with EOF
		done <- err
	}()

	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		send(map[string]any{"line": sc.Text()})
	}

	runErr := <-done
	final := map[string]any{"final": true}
	if runErr != nil {
		final["err"] = runErr.Error()
	}
	send(final)
}

// writeRunError streams a single final-error record so the page shows it in the
// output console just like a failed run, with a 200 (the stream itself carries
// the error, matching the TUI's inline "blocked —" status).
func writeRunError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"final": true, "err": msg})
}

// outOfScopeHitFor returns the first out-of-scope entry of the named project
// (in the shared project store) that appears in cmd, or "" if none (or no such
// project). Projects are loaded fresh so scope edited in the TUI takes effect
// without a server restart.
func outOfScopeHitFor(projectName, cmd string) string {
	if strings.TrimSpace(projectName) == "" {
		return ""
	}
	for _, p := range loadProjects() {
		if p.Name != projectName {
			continue
		}
		for _, o := range p.OutScope {
			if o = strings.TrimSpace(o); o != "" && strings.Contains(cmd, o) {
				return o
			}
		}
	}
	return ""
}

// sameOrigin rejects cross-site requests so another website a browser has open
// cannot drive this localhost server. It requires a loopback Host and, when the
// browser sends an Origin (it does for cross-origin POSTs), that it match.
func sameOrigin(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // same-origin GETs and some same-origin requests omit it
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	oh := u.Hostname()
	return oh == "localhost" || oh == "127.0.0.1" || oh == "::1"
}

// openBrowser launches the default browser; under WSL that's the Windows one.
func openBrowser(target string) {
	var cmd *exec.Cmd
	switch {
	case runtime.GOOS == "darwin":
		cmd = exec.Command("open", target)
	case runtime.GOOS == "windows" || isWSL():
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "couldn't open a browser; visit the URL above")
		return
	}
	go cmd.Wait()
}

func isWSL() bool {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && strings.Contains(strings.ToLower(string(b)), "microsoft")
}
