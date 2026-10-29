package main

// Minimal RFC 6455 WebSocket server, implemented on the standard library so the
// app keeps its zero-dependency, offline build. It supports exactly what the
// interactive terminal needs: a server-side handshake, reading masked client
// frames (with fragment reassembly and automatic ping/pong), and writing
// unmasked text/binary frames. It is not a general-purpose implementation.

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// WebSocket opcodes (RFC 6455 §5.2).
const (
	wsContinuation = 0x0
	wsText         = 0x1
	wsBinary       = 0x2
	wsClose        = 0x8
	wsPing         = 0x9
	wsPong         = 0xA
)

// wsMagic is the fixed GUID concatenated with the client key to derive the
// Sec-WebSocket-Accept response header.
const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsMaxMessage caps a single (possibly fragmented) inbound message. Terminal
// input is keystrokes and tiny resize JSON, so this is generous.
const wsMaxMessage = 4 << 20

// wsConn is an upgraded connection. Writes are serialized by mu so the output
// pump and automatic pong replies don't interleave on the wire.
type wsConn struct {
	conn net.Conn
	r    *bufio.Reader
	mu   sync.Mutex
	once sync.Once
}

// wsUpgrade performs the server handshake and hijacks the connection. On
// success the HTTP handler must stop writing to w and use the returned wsConn.
func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("not a websocket upgrade request")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection hijacking unsupported")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write([]byte(key + wsMagic))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, r: brw.Reader}, nil
}

// readFrame reads one frame, unmasking the payload (all client frames are
// masked per spec). It rejects oversized frames.
func (c *wsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(c.r, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	if n > wsMaxMessage {
		err = errors.New("websocket frame too large")
		return
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.r, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return
}

// ReadMessage returns the next complete data message (text or binary),
// reassembling fragments. Control frames are handled transparently: pings are
// answered with pongs, and a close frame (or a read error) ends the stream.
func (c *wsConn) ReadMessage() (opcode byte, data []byte, err error) {
	var msg []byte
	msgOp := byte(0)
	for {
		fin, op, payload, rerr := c.readFrame()
		if rerr != nil {
			return 0, nil, rerr
		}
		switch op {
		case wsPing:
			if werr := c.write(wsPong, payload); werr != nil {
				return 0, nil, werr
			}
			continue
		case wsPong:
			continue
		case wsClose:
			c.Close()
			return 0, nil, io.EOF
		case wsContinuation:
			msg = append(msg, payload...)
		case wsText, wsBinary:
			msgOp = op
			msg = append(msg, payload...)
		default:
			return 0, nil, errors.New("unsupported websocket opcode")
		}
		if len(msg) > wsMaxMessage {
			return 0, nil, errors.New("websocket message too large")
		}
		if fin {
			return msgOp, msg, nil
		}
	}
}

// write sends a single unmasked frame with the given opcode.
func (c *wsConn) write(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hdr [10]byte
	hdr[0] = 0x80 | opcode // FIN set; we never fragment outbound
	n := len(payload)
	switch {
	case n < 126:
		hdr[1] = byte(n)
		if _, err := c.conn.Write(hdr[:2]); err != nil {
			return err
		}
	case n < 1<<16:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		if _, err := c.conn.Write(hdr[:4]); err != nil {
			return err
		}
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		if _, err := c.conn.Write(hdr[:10]); err != nil {
			return err
		}
	}
	if n > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// WriteBinary sends a binary data message (used for raw terminal output).
func (c *wsConn) WriteBinary(b []byte) error { return c.write(wsBinary, b) }

// WriteText sends a text data message (used for human-readable status lines).
func (c *wsConn) WriteText(s string) error { return c.write(wsText, []byte(s)) }

// Close best-effort sends a close frame and shuts the socket. It is safe to
// call more than once and from multiple goroutines.
func (c *wsConn) Close() error {
	c.once.Do(func() {
		c.write(wsClose, nil)
		c.conn.Close()
	})
	return nil
}
