package main

import (
	"bufio"
	"context"
	"io"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
)

// outMsg carries one line of command output to the UI, or — when final — the
// exit result of the command.
type outMsg struct {
	line  string
	final bool
	err   error
}

// waitForOut blocks on the output channel and delivers the next chunk to the
// Bubble Tea update loop.
func waitForOut(ch chan outMsg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// startRun launches cmdStr through the shell (so compound binaries like
// "gobuster dir" and the shell quoting from Command() behave as printed),
// streaming combined stdout/stderr into the output channel one line at a time,
// then a final message with the exit error. It returns the tea.Cmd that waits
// for the first chunk. The command is cancelable via m.cancel.
func (m *model) startRun(cmdStr string) tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.running = true
	m.out = []string{"$ " + cmdStr, ""}
	m.refreshOut()

	ch := make(chan outMsg, 512)
	m.outCh = ch

	go func() {
		c := exec.CommandContext(ctx, "sh", "-c", cmdStr)
		pr, pw := io.Pipe()
		c.Stdout = pw
		c.Stderr = pw

		scanDone := make(chan struct{})
		go func() {
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				ch <- outMsg{line: sc.Text()}
			}
			close(scanDone)
		}()

		runErr := c.Run()
		pw.Close() // unblock the scanner with EOF
		<-scanDone // let it drain any buffered output first
		cancel()   // release the context
		ch <- outMsg{final: true, err: runErr}
	}()

	return waitForOut(ch)
}
