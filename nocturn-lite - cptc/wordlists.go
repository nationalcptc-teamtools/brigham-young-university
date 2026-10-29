package main

import (
	"os"
	"path/filepath"
)

// wordlistDir resolves the absolute path to the bundled wordlists directory so
// that commands assembled in the TUI reference lists that actually exist on
// disk, no matter where the binary is launched from.
//
// Resolution order:
//  1. $PENTEST_TUI_WORDLISTS, if set (override / point at a system SecLists)
//  2. a "wordlists" directory next to the executable (the bundled copy)
//  3. a "wordlists" directory in the current working directory
//
// It always returns a path — the best candidate — even when none exist yet, so
// defaults stay stable and the user can still edit them in the UI.
func wordlistDir() string {
	if env := os.Getenv("PENTEST_TUI_WORDLISTS"); env != "" {
		return env
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "wordlists")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return "wordlists"
}

// wl joins a bundled-wordlist relative path (e.g. "web-content/common.txt")
// onto the resolved wordlist directory.
func wl(rel string) string {
	return filepath.Join(wordlistDir(), rel)
}
