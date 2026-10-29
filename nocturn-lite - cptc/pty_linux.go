//go:build linux

package main

// Linux PTY allocation for the interactive terminal, using golang.org/x/sys/unix
// (already a dependency) so no cgo and no extra modules are needed. This is the
// same mechanism a shell gets from a real terminal: a master/slave pair where
// the child runs on the slave and we read/write the master.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func ptySupported() bool { return true }

// startPTY opens a pseudo-terminal and starts an interactive login shell on its
// slave side, returning the master file for I/O plus the running command. The
// caller reads/writes ptmx, resizes with resizePTY, and must Close ptmx and
// reap cmd when done. The command is bound to ctx so a dropped connection (and
// the handler's cancel) tears the shell down.
func startPTY(ctx context.Context) (ptmx *os.File, cmd *exec.Cmd, err error) {
	ptmx, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	// Unlock the slave and learn its number, then open it.
	if err = unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		ptmx.Close()
		return nil, nil, fmt.Errorf("unlock pty: %w", err)
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		ptmx.Close()
		return nil, nil, fmt.Errorf("get pty number: %w", err)
	}
	sname := fmt.Sprintf("/dev/pts/%d", n)
	tty, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		ptmx.Close()
		return nil, nil, fmt.Errorf("open %s: %w", sname, err)
	}
	defer tty.Close() // the child keeps its own copy via the fds below

	shell := loginShell()
	cmd = exec.CommandContext(ctx, shell, "-i")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	// TERM lets programs emit the colours/sequences our emulator understands.
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true, // new session, detached from the server's controlling tty
		Setctty: true, // make the slave the child's controlling terminal
	}
	if err = cmd.Start(); err != nil {
		ptmx.Close()
		return nil, nil, fmt.Errorf("start %s: %w", shell, err)
	}
	return ptmx, cmd, nil
}

// resizePTY tells the kernel the terminal's new dimensions so the shell and any
// child programs reflow and SIGWINCH fires.
func resizePTY(f *os.File, rows, cols uint16) error {
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, &unix.Winsize{
		Row: rows,
		Col: cols,
	})
}

// loginShell picks the user's shell, falling back to bash then sh.
func loginShell() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return "sh"
}
