package main

// Interactive terminal endpoint. Unlike /api/run (which assembles one catalog
// command and streams its output one-way), this gives the browser a real shell
// over a pseudo-terminal: keystrokes go in, output comes back, and the page can
// open several of these at once for a split-screen workspace. It is gated by
// the same same-origin check as the rest of the API and still only ever runs on
// the machine serving the page, bound to localhost.

import (
	"encoding/json"
	"net/http"
)

// termMsg is the JSON control message the page sends over the socket. "input"
// carries typed bytes (as a UTF-8 string); "resize" carries the new grid size.
type termMsg struct {
	Type string `json:"type"`
	Data string `json:"data"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// handleTerminal upgrades to WebSocket, spawns a shell on a PTY, and shuttles
// bytes between them until either side closes. Each connection is one
// independent shell, so the page gets a fresh session per pane.
func handleTerminal(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ws, err := wsUpgrade(w, r)
	if err != nil {
		http.Error(w, "bad websocket request", http.StatusBadRequest)
		return
	}
	defer ws.Close()

	ptmx, cmd, err := startPTY(r.Context())
	if err != nil {
		// The socket is live, so report the reason into the pane itself (red).
		ws.WriteText("\x1b[31m" + err.Error() + "\x1b[0m\r\n")
		return
	}
	defer func() {
		ptmx.Close()
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
	}()

	// Output pump: PTY → socket. Ends on shell exit or a write failure, then
	// closes the socket so the input loop below unblocks.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, rerr := ptmx.Read(buf)
			if n > 0 {
				if werr := ws.WriteBinary(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		ws.Close()
	}()

	// Input loop: socket → PTY (and resize). Ends when the browser closes the
	// socket or the output pump closes it; the deferred cleanup then kills the
	// shell and the master read in the pump returns, ending that goroutine too.
	for {
		_, data, rerr := ws.ReadMessage()
		if rerr != nil {
			break
		}
		var m termMsg
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch m.Type {
		case "input":
			if _, werr := ptmx.Write([]byte(m.Data)); werr != nil {
				return
			}
		case "resize":
			if m.Cols > 0 && m.Rows > 0 {
				resizePTY(ptmx, m.Rows, m.Cols)
			}
		}
	}
}
