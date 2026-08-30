package irc

import (
	"bufio"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	irc "github.com/thoj/go-ircevent"
)

// AUDIT-319: go-ircevent's Connect allocates the socket and spawns readLoop,
// writeLoop and pingLoop BEFORE it negotiates capabilities, then returns the
// negotiateCaps error without unwinding any of it. Bot.Start's error branch
// used to just drop the conn, stranding two goroutines and the socket on every
// attempt — repeated forever by the manager's 30s reconnect sweep.

// TestConnectPreDialFailure_LeavesErrorChanNil_AUDIT319 pins the invariant the
// fix's gate depends on. Connect allocates irc.Error immediately before
// irc.Add(3), so a nil ErrorChan means nothing was ever spawned. Tearing down
// in that state would be strictly worse than the leak we are fixing:
// Disconnect ends by sending on that nil channel while holding the connection
// lock, and a send on a nil channel blocks forever.
func TestConnectPreDialFailure_LeavesErrorChanNil_AUDIT319(t *testing.T) {
	for _, tc := range []struct{ name, server string }{
		{"empty server", ""},
		{"missing port", "127.0.0.1:"},
		{"unparseable port", "127.0.0.1:notaport"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := irc.IRC("fwmon-test", "fwmon-test")
			conn.Log = log.New(io.Discard, "", 0)

			if err := conn.Connect(tc.server); err == nil {
				t.Fatalf("Connect(%q) unexpectedly succeeded", tc.server)
			}
			if conn.ErrorChan() != nil {
				t.Fatal("a pre-dial Connect failure allocated the Error channel: " +
					"the AUDIT-319 gate would then call Disconnect, which blocks " +
					"forever sending on a channel nothing reads")
			}
		})
	}
}

// TestTeardownConn_UnwindsLoops_AUDIT319 drives the real post-spawn
// failure: the server answers CAP LS without advertising sasl, which makes
// negotiateCaps fail fast, after the three loops and the socket already exist.
//
// The assertion is that teardownConn RETURNS. Disconnect calls
// irc.Wait() on the library's WaitGroup of three, so returning is proof that
// readLoop, writeLoop and pingLoop all exited and the socket was closed —
// which is precisely the leak. The fixture closes on QUIT the way a real ircd
// does, so a teardown that skipped the QUIT would sit on readLoop's 16-minute
// read deadline and blow the timeout instead.
func TestTeardownConn_UnwindsLoops_AUDIT319(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	gotQuit := make(chan struct{})
	serverStalled := make(chan struct{})
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			return
		}
		defer sc.Close()
		r := bufio.NewReader(sc)
		for {
			// Long enough that only a genuinely silent client trips it; a
			// timeout here means no QUIT ever arrived, never that we were slow.
			_ = sc.SetReadDeadline(time.Now().Add(25 * time.Second))
			line, err := r.ReadString('\n')
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					close(serverStalled)
				}
				return
			}
			switch {
			case strings.HasPrefix(line, "CAP LS"):
				// Advertise a capability set WITHOUT sasl: the library reports
				// "no SASL capability" at once instead of waiting out its 15s
				// CAP_TIMEOUT.
				_, _ = sc.Write([]byte(":test.server CAP * LS :multi-prefix\r\n"))
			case strings.HasPrefix(line, "QUIT"):
				// A real ircd drops the session here, which is what lets
				// readLoop's blocking read return promptly.
				close(gotQuit)
				return
			}
		}
	}()

	conn := irc.IRC("fwmon-test", "fwmon-test")
	conn.Log = log.New(io.Discard, "", 0)
	conn.UseSASL = true
	conn.SASLLogin = "fwmon"
	conn.SASLPassword = "wrong-password"

	if err := conn.Connect(ln.Addr().String()); err == nil {
		conn.Disconnect()
		t.Fatal("Connect unexpectedly succeeded; the fixture must fail capability negotiation")
	}
	if conn.ErrorChan() == nil {
		t.Fatal("Error channel is nil after a post-spawn failure — the fixture no longer " +
			"reaches the leak path this test exists to cover")
	}

	done := make(chan struct{})
	go func() {
		teardownConn(conn)
		close(done)
	}()

	select {
	case <-done:
	case <-serverStalled:
		t.Fatal("AUDIT-319 regression: no QUIT reached the server, so the connection was " +
			"never unwound — writeLoop, pingLoop and the socket stay stranded for the " +
			"life of the process, once per reconnect attempt")
	case <-time.After(20 * time.Second):
		t.Fatal("teardownConn never returned: irc.Wait() is still blocked on a live " +
			"loop, so the connection was not fully unwound")
	}

	select {
	case <-gotQuit:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown completed without ever sending QUIT: without it, Disconnect " +
			"stalls on readLoop's 16-minute read deadline against a real server")
	}
}
