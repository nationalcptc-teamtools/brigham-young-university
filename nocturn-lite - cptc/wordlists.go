package main

import (
	"os"
	"path/filepath"
)

// wordlistDir resolves the root of the wordlists that the commands assembled in
// the TUI reference. Nothing is bundled with this app — the lists come from
// whatever is already installed on the Kali box, under the standard
// /usr/share/wordlists tree (dirb, dirbuster, and the seclists symlink all live
// there on a default install).
//
// Resolution order:
//  1. $PENTEST_TUI_WORDLISTS, if set (override / point at lists elsewhere).
//  2. /usr/share/wordlists — Kali's default location.
//
// It always returns a path — the best candidate — even when none exist yet, so
// defaults stay stable and the user can still edit them in the UI.
func wordlistDir() string {
	if env := os.Getenv("PENTEST_TUI_WORDLISTS"); env != "" {
		return env
	}
	return "/usr/share/wordlists"
}

// wl joins a wordlist path relative to the Kali wordlists root
// (e.g. "dirb/common.txt") onto the resolved directory.
func wl(rel string) string {
	return filepath.Join(wordlistDir(), rel)
}
