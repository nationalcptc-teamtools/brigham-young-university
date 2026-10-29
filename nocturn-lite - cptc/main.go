// Command web is an interactive terminal UI for assembling pentest
// tool command lines. Pick a tool, toggle and fill in flags, watch the command
// build live, then copy, print, or run it in the output panel. Run with --web
// to drive the same catalog from a browser tab instead.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	web := flag.Bool("web", false, "serve the tool catalog as a web page instead of the TUI")
	port := flag.Int("port", defaultPort, "port for --web")
	noOpen := flag.Bool("no-open", false, "with --web, don't open a browser tab")
	flag.Parse()

	if *web {
		if err := runWeb(*port, !*noOpen); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	p := tea.NewProgram(newModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
	res, err := p.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	// Print the last assembled command so it survives leaving the alt screen
	// (commands are run inside the TUI's output panel via ctrl+r).
	if m, ok := res.(model); ok && strings.TrimSpace(m.finalCmd) != "" {
		fmt.Println(m.finalCmd)
	}
}
