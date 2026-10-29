package main

// Monetization / entitlement layer.
//
// This decides what a signed-in operator is allowed to do, so paid features can
// be gated without scattering billing logic through the handlers. It is
// deliberately provider-shaped:
//
//   - LICENSE_MODE unset / "local"  → self-hosted: every signed-in user gets the
//     full Pro feature set. This is the default, so running the binary on your
//     own box keeps working exactly as before.
//   - LICENSE_MODE="free"           → force the locked baseline, for exercising
//     the paywall UI during development.
//   - LICENSE_MODE="supabase"       → enforce subscriptions stored in Supabase
//     (see supabaseProvider below). This is the hosted-SaaS path.
//   - DEV_UNLOCK=1                  → everything unlocked regardless of mode.
//
// The browser reads GET /api/entitlement to show or lock parts of the page; the
// server independently enforces the same features with requireFeature on the
// valuable endpoints, so a hacked-up client can't unlock anything.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Plan is the coarse tier an account sits in.
type Plan string

const (
	PlanFree Plan = "free"
	PlanPro  Plan = "pro"
)

// Feature keys gate individual capabilities. Keep these in sync with whatever
// the browser UI checks against /api/entitlement.
const (
	FeatureRun      = "run"      // assemble-and-run with live output (/api/run)
	FeatureTerminal = "terminal" // interactive reverse-shell terminals (/api/terminal)
)

// Entitlement is what the current operator may do right now, resolved per
// request from the active provider.
type Entitlement struct {
	Plan      Plan            `json:"plan"`
	Active    bool            `json:"active"`
	Features  map[string]bool `json:"features"`
	ExpiresAt string          `json:"expiresAt,omitempty"` // RFC3339, "" = no expiry
	Source    string          `json:"source"`              // local | supabase | dev | ...
}

// Allows reports whether a feature is unlocked for this entitlement.
func (e Entitlement) Allows(feature string) bool {
	return e.Active && e.Features[feature]
}

// proEntitlement is a fully-unlocked grant (local/self-hosted and dev override).
func proEntitlement(source string) Entitlement {
	return Entitlement{
		Plan:   PlanPro,
		Active: true,
		Features: map[string]bool{
			FeatureRun:      true,
			FeatureTerminal: true,
		},
		Source: source,
	}
}

// freeEntitlement is the locked baseline: browse the catalog and copy commands,
// but running and live terminals are held behind a paid plan.
func freeEntitlement(source string) Entitlement {
	return Entitlement{
		Plan:   PlanFree,
		Active: true, // the account itself is valid; it just lacks paid features
		Features: map[string]bool{
			FeatureRun:      false,
			FeatureTerminal: false,
		},
		Source: source,
	}
}

// EntitlementProvider resolves what a signed-in user may do. Implementations
// must be safe for concurrent use.
type EntitlementProvider interface {
	For(user string) (Entitlement, error)
	Name() string
}

type licenseMode string

const (
	modeLocal    licenseMode = "local"    // self-hosted: every signed-in user is Pro
	modeFree     licenseMode = "free"     // force the locked UI (paywall testing)
	modeSupabase licenseMode = "supabase" // enforce subscriptions stored in Supabase
)

var (
	entProviderOnce sync.Once
	entProvider     EntitlementProvider
)

// entitlementProvider selects the provider once from the environment.
func entitlementProvider() EntitlementProvider {
	entProviderOnce.Do(func() {
		if os.Getenv("DEV_UNLOCK") == "1" {
			entProvider = staticProvider{ent: proEntitlement("dev"), name: "dev-unlock"}
			return
		}
		switch licenseMode(strings.ToLower(strings.TrimSpace(os.Getenv("LICENSE_MODE")))) {
		case modeSupabase:
			p, err := newSupabaseProvider()
			if err != nil {
				fmt.Fprintln(os.Stderr, "license: LICENSE_MODE=supabase but config invalid:", err)
				fmt.Fprintln(os.Stderr, "license: locking paid features until it's fixed")
				entProvider = staticProvider{ent: freeEntitlement("supabase-misconfigured"), name: "free-fallback"}
				return
			}
			entProvider = p
		case modeFree:
			entProvider = staticProvider{ent: freeEntitlement("forced-free"), name: "forced-free"}
		default: // modeLocal and unset
			entProvider = staticProvider{ent: proEntitlement("local"), name: "local"}
		}
	})
	return entProvider
}

// staticProvider returns the same entitlement for everyone — used for the
// local, forced-free, and dev-unlock modes.
type staticProvider struct {
	ent  Entitlement
	name string
}

func (s staticProvider) For(string) (Entitlement, error) { return s.ent, nil }
func (s staticProvider) Name() string                    { return s.name }

// currentEntitlement resolves the entitlement for the current operator. There
// is no account gate (anyone with the localhost page may use it), so this
// resolves a single fixed "local" identity; in the default local mode that is a
// fully-unlocked Pro grant. LICENSE_MODE=supabase can still key off this id.
func currentEntitlement(r *http.Request) Entitlement {
	ent, err := entitlementProvider().For("local")
	if err != nil {
		// Fail closed on paid features, but don't lock the account out of the
		// free tier just because the billing lookup hiccuped.
		fmt.Fprintln(os.Stderr, "license: entitlement lookup failed:", err)
		return freeEntitlement("error")
	}
	return ent
}

// requireFeature gates a handler behind a paid feature. In the default local
// mode every operator is Pro, so it is a no-op; a blocked request (e.g. under
// LICENSE_MODE=supabase) gets 402 Payment Required with a JSON body the page
// can turn into an upgrade prompt.
func requireFeature(feature string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if currentEntitlement(r).Allows(feature) {
			next(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusPaymentRequired) // 402
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "upgrade required",
			"feature": feature,
		})
	}
}

// handleEntitlement reports the caller's current entitlement so the browser can
// show locks / an upgrade prompt. This is advisory only — the server still
// enforces each feature on its own endpoint.
func handleEntitlement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(currentEntitlement(r))
}

// ── Supabase provider ────────────────────────────────────────────────────────
//
// Talks to Supabase's auto-generated REST API (PostgREST) to look up the
// caller's subscription. It is written against an assumed table shape and is a
// STARTING POINT: adjust the table/column names and the user key to match your
// schema once Supabase — and whatever writes rows into it (e.g. a Stripe
// webhook) — are in place.
//
// Assumed table `subscriptions`:
//     user_key   text         -- matches the app's signed-in identity (see TODO in For)
//     plan       text         -- 'free' | 'pro'
//     status     text         -- 'active' | 'trialing' | 'past_due' | 'canceled'
//     expires_at timestamptz  -- end of the current paid period (nullable)
//
// Required env (see .env.example):
//     SUPABASE_URL                  https://<project-ref>.supabase.co
//     SUPABASE_SERVICE_ROLE_KEY     service-role key — SERVER-SIDE ONLY, never
//                                   send this to the browser
//     SUPABASE_SUBSCRIPTIONS_TABLE  optional; defaults to "subscriptions"

type supabaseProvider struct {
	baseURL string
	key     string
	table   string
	client  *http.Client
}

func newSupabaseProvider() (supabaseProvider, error) {
	base := strings.TrimRight(os.Getenv("SUPABASE_URL"), "/")
	key := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	if base == "" || key == "" {
		return supabaseProvider{}, errors.New("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set")
	}
	table := os.Getenv("SUPABASE_SUBSCRIPTIONS_TABLE")
	if table == "" {
		table = "subscriptions"
	}
	return supabaseProvider{
		baseURL: base,
		key:     key,
		table:   table,
		client:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (p supabaseProvider) Name() string { return "supabase" }

type supabaseSubRow struct {
	Plan      string `json:"plan"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
}

func (p supabaseProvider) For(user string) (Entitlement, error) {
	// TODO: when you adopt Supabase Auth, key on the auth uid / email and verify
	// the browser's Supabase JWT instead of trusting the local session username.
	q := url.Values{}
	q.Set("user_key", "eq."+user)
	q.Set("select", "plan,status,expires_at")
	q.Set("limit", "1")

	req, err := http.NewRequest(http.MethodGet, p.baseURL+"/rest/v1/"+p.table+"?"+q.Encode(), nil)
	if err != nil {
		return Entitlement{}, err
	}
	req.Header.Set("apikey", p.key)
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return Entitlement{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Entitlement{}, fmt.Errorf("supabase %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rows []supabaseSubRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return Entitlement{}, err
	}
	if len(rows) == 0 {
		return freeEntitlement("supabase"), nil // no subscription row = free tier
	}
	return entitlementFromRow(rows[0]), nil
}

// entitlementFromRow maps a subscription row to an entitlement, honouring the
// status and expiry.
func entitlementFromRow(row supabaseSubRow) Entitlement {
	paid := row.Plan == string(PlanPro) &&
		(row.Status == "active" || row.Status == "trialing")
	if paid && row.ExpiresAt != "" {
		if exp, err := time.Parse(time.RFC3339, row.ExpiresAt); err == nil && time.Now().After(exp) {
			paid = false
		}
	}
	if !paid {
		e := freeEntitlement("supabase")
		e.ExpiresAt = row.ExpiresAt
		return e
	}
	e := proEntitlement("supabase")
	e.ExpiresAt = row.ExpiresAt
	return e
}

// ── .env loading ─────────────────────────────────────────────────────────────

// loadDotEnv reads a .env file (next to the binary, then the working directory)
// and sets any KEY=VALUE pairs not already present in the real environment. It
// is a minimal parser — it trims one surrounding pair of quotes and ignores
// blank/`#` lines — so secrets like the Supabase service-role key can live in a
// local file during development. Real deployments should prefer real
// environment variables and leave no .env on disk.
func loadDotEnv() {
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), ".env"))
	}
	paths = append(paths, ".env")

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			if k == "" {
				continue
			}
			if _, exists := os.LookupEnv(k); !exists {
				os.Setenv(k, v)
			}
		}
		f.Close()
	}
}
