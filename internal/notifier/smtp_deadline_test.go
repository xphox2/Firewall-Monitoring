package notifier

import (
	"net"
	"testing"
	"time"
)

// TestSendMailWithDeadline_StalledServerDoesNotHang is the AUDIT C1/AL-H1
// regression: net/smtp.SendMail has no I/O deadline, so an SMTP host that
// accepts the TCP connection then never speaks would block the caller (the
// poller's single monitoring goroutine) forever. sendMailWithDeadline must
// return an error within its bounded deadline instead.
func TestSendMailWithDeadline_StalledServerDoesNotHang(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept connections but never write the 220 greeting — the classic
	// half-open/blackhole stall.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open, silent, until it is closed by the peer.
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			go func(c net.Conn) {
				buf := make([]byte, 1)
				_, _ = c.Read(buf) // blocks; we never reply
			}(conn)
		}
	}()

	orig := smtpSendTimeout
	smtpSendTimeout = 500 * time.Millisecond
	defer func() { smtpSendTimeout = orig }()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- sendMailWithDeadline(ln.Addr().String(), "127.0.0.1", nil,
			"from@example.com", []string{"to@example.com"}, []byte("test"), nil)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from the stalled server, got nil")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("returned but took too long (%v); deadline not enforced", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sendMailWithDeadline hung past the deadline (the C1 bug)")
	}
}

// TestSendMailWithDeadline_DialTimeout covers the connect-phase stall: a
// destination that never completes the TCP handshake must also be bounded.
func TestSendMailWithDeadline_DialTimeout(t *testing.T) {
	orig := smtpSendTimeout
	smtpSendTimeout = 500 * time.Millisecond
	defer func() { smtpSendTimeout = orig }()

	// 203.0.113.0/24 (TEST-NET-3) is reserved and non-routable → dial stalls.
	done := make(chan error, 1)
	go func() {
		done <- sendMailWithDeadline("203.0.113.1:25", "203.0.113.1", nil,
			"from@example.com", []string{"to@example.com"}, []byte("test"), nil)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a dial error, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not respect the timeout")
	}
}
