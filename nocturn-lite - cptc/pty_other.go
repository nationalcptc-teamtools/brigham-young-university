//go:build !linux

package main

// Fallback for non-Linux builds. The interactive terminal needs a PTY, which
// this app only implements on Linux (its real deployment target — see run.sh).
// On other platforms the handshake still succeeds and the browser shows a clear
// "unavailable" message instead of failing silently.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
)

func ptySupported() bool { return false }

func startPTY(ctx context.Context) (*os.File, *exec.Cmd, error) {
	return nil, nil, errors.New("interactive terminal is only supported on Linux (running on " + runtime.GOOS + ")")
}

func resizePTY(f *os.File, rows, cols uint16) error { return nil }
