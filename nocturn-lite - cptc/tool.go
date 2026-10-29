package main

import (
	"fmt"
	"strings"
)

// FlagKind describes how a flag is rendered and edited in the UI and how it is
// serialized into the final command line.
type FlagKind int

const (
	// KindBool is an on/off switch. When enabled, Flag is emitted with no value.
	KindBool FlagKind = iota
	// KindString is a free-text value, emitted as "<flag> <value>".
	KindString
	// KindInt is a numeric value; behaves like KindString but hints the editor.
	KindInt
	// KindChoice is one option out of a fixed set, cycled with left/right.
	KindChoice
)

// Flag is a single configurable option belonging to a Tool.
type Flag struct {
	// Flag is the literal switch written to the command line, e.g. "-w".
	// For positional arguments (the target/URL), leave this empty.
	Flag string
	// Name is the human label shown in the UI.
	Name string
	// Desc is a one-line explanation shown beneath the selected flag.
	Desc string
	// Kind controls editing behaviour and serialization.
	Kind FlagKind
	// Value holds the current string value (for String/Int/Choice).
	Value string
	// Enabled toggles a bool flag, or marks a value flag as "include me".
	Enabled bool
	// Placeholder is shown in the editor when Value is empty.
	Placeholder string
	// Choices is the option set for KindChoice.
	Choices []string
	// Required, when true, highlights the flag until it has a value.
	Required bool
	// Positional emits just the Value (no Flag token), used for targets/URLs.
	Positional bool
}

// Tool is a single command-line program with a curated set of flags.
type Tool struct {
	Name     string
	Binary   string
	Desc     string
	Category string // workflow stage, e.g. "recon", "web fuzzing"
	Flags    []Flag
	// Grep is a suggested filter pipeline (no leading "|") that pulls the
	// important lines out of this tool's output — e.g. live 200s from httpx,
	// unique hosts from subfinder. Left empty for tools where a filter doesn't
	// apply (reverse shells, file-transfer servers, payload snippets).
	Grep string
	// GrepOn toggles whether Grep is appended to the assembled command. It is a
	// per-working-copy switch (ctrl+g in the TUI, the checkbox in the web UI),
	// off by default so the raw command is shown until the operator opts in.
	GrepOn bool
}

// FilterValue implements list.Item so Tools can live in a bubbles list.
// Category is included so filtering by "recon" surfaces the whole stage.
func (t Tool) FilterValue() string { return t.Name + " " + t.Category }
func (t Tool) Title() string       { return t.Name }
func (t Tool) Description() string {
	if t.Category == "" {
		return t.Desc
	}
	return "[" + t.Category + "] " + t.Desc
}

// isPlaceholder reports whether a flag's "Flag" token is a template
// placeholder like "{LHOST}" — i.e. a value woven into the Binary string
// itself (used by the GTFOBins shells) rather than a switch appended to the
// command line.
func isPlaceholder(flag string) bool {
	return len(flag) >= 2 && flag[0] == '{' && flag[len(flag)-1] == '}'
}

// Command assembles a ready-to-run command string from the tool's flags.
// Only enabled bool flags and value flags that have a value are included.
func (t Tool) Command() string {
	// Placeholder flags ({LHOST}, {LPORT}, …) are substituted into the Binary
	// template in place, since their values sit inside the command's own
	// quoting (e.g. a reverse-shell one-liner) rather than at the end.
	base := t.Binary
	for _, f := range t.Flags {
		if isPlaceholder(f.Flag) {
			if v := strings.TrimSpace(f.Value); v != "" {
				base = strings.ReplaceAll(base, f.Flag, v)
			}
		}
	}

	parts := []string{base}
	var positionals []string

	for _, f := range t.Flags {
		if isPlaceholder(f.Flag) {
			continue // already substituted into the template above
		}
		switch f.Kind {
		case KindBool:
			if f.Enabled {
				parts = append(parts, f.Flag)
			}
		default:
			v := strings.TrimSpace(f.Value)
			if v == "" {
				continue
			}
			if f.Positional {
				positionals = append(positionals, shellQuote(v))
				continue
			}
			parts = append(parts, f.Flag, shellQuote(v))
		}
	}

	// Positional args (targets, URLs) go at the end by convention.
	parts = append(parts, positionals...)
	cmd := strings.Join(parts, " ")

	// When the key-info filter is toggled on, pipe the command through it so
	// the output console shows just the lines that matter.
	if t.GrepOn {
		if g := strings.TrimSpace(t.Grep); g != "" {
			cmd += " | " + g
		}
	}
	return cmd
}

// MissingRequired returns the names of required flags that have no value yet.
func (t Tool) MissingRequired() []string {
	var missing []string
	for _, f := range t.Flags {
		if !f.Required {
			continue
		}
		if f.Kind == KindBool {
			if !f.Enabled {
				missing = append(missing, f.Name)
			}
		} else if strings.TrimSpace(f.Value) == "" {
			missing = append(missing, f.Name)
		}
	}
	return missing
}

// shellQuote wraps a value in single quotes if it contains characters the
// shell would otherwise interpret, so the printed command is copy-paste safe.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("-_./:=@%+,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	// Escape embedded single quotes the POSIX way: ' -> '\''
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// clone returns a deep copy of a Tool so the catalog stays pristine while the
// user edits their own working copy.
func (t Tool) clone() Tool {
	cp := t
	cp.Flags = make([]Flag, len(t.Flags))
	copy(cp.Flags, t.Flags)
	for i := range cp.Flags {
		if cp.Flags[i].Choices != nil {
			ch := make([]string, len(cp.Flags[i].Choices))
			copy(ch, cp.Flags[i].Choices)
			cp.Flags[i].Choices = ch
		}
	}
	return cp
}

// summary is a short textual status of a flag for compact display.
func (f Flag) summary() string {
	switch f.Kind {
	case KindBool:
		if f.Enabled {
			return "on"
		}
		return "off"
	default:
		if strings.TrimSpace(f.Value) == "" {
			return "—"
		}
		return f.Value
	}
}

func (f Flag) label() string {
	if f.Flag == "" {
		return f.Name
	}
	return fmt.Sprintf("%s  %s", f.Flag, f.Name)
}
