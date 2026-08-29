package notifier

import (
	"bufio"
	"net"
	"strings"
	"sync"
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

// startFakeSMTP runs a scripted plaintext SMTP server (no STARTTLS, no AUTH)
// that completes sendMailWithDeadline's exchange and records every RCPT TO
// command. Returns the listen port and an accessor for the recorded commands.
func startFakeSMTP(t *testing.T) (port int, rcpts func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var got []string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				write := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
				write("220 fwmon-test ESMTP")
				inData := false
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if inData {
						if line == "." {
							inData = false
							write("250 OK: queued")
						}
						continue
					}
					switch {
					case strings.HasPrefix(strings.ToUpper(line), "EHLO"),
						strings.HasPrefix(strings.ToUpper(line), "HELO"):
						write("250 fwmon-test greets you")
					case strings.HasPrefix(strings.ToUpper(line), "MAIL FROM"):
						write("250 OK")
					case strings.HasPrefix(strings.ToUpper(line), "RCPT TO"):
						mu.Lock()
						got = append(got, line)
						mu.Unlock()
						write("250 OK")
					case strings.HasPrefix(strings.ToUpper(line), "DATA"):
						inData = true
						write("354 go ahead")
					case strings.HasPrefix(strings.ToUpper(line), "QUIT"):
						write("221 bye")
						return
					default:
						write("250 OK")
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(got))
		copy(out, got)
		return out
	}
}

// TestSendEmail_SplitsCommaRecipients (AUDIT-209): "a@x.com, b@y.com" must
// produce one RCPT TO per address on the wire. sendEmail used to hand the RAW
// comma string to the envelope as a single recipient, which multi-recipient
// relays reject — every alert email to more than one address silently failed
// while the report path (which splits) delivered.
func TestSendEmail_SplitsCommaRecipients(t *testing.T) {
	cases := []struct {
		name string
		to   string
		want []string
	}{
		{"two recipients", "a@x.com, b@y.com", []string{"a@x.com", "b@y.com"}},
		{"single recipient", "a@x.com", []string{"a@x.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, rcpts := startFakeSMTP(t)
			n := &Notifier{}
			nc := NotifyConfig{
				SMTPHost: "127.0.0.1", SMTPPort: port,
				SMTPFrom: "fwmon@example.com", SMTPTo: tc.to,
			}
			if err := n.sendEmail(fireAlert("warning"), nc); err != nil {
				t.Fatalf("sendEmail: %v", err)
			}
			got := rcpts()
			if len(got) != len(tc.want) {
				t.Fatalf("RCPT TO commands = %d (%q), want %d", len(got), got, len(tc.want))
			}
			for i, addr := range tc.want {
				if got[i] != "RCPT TO:<"+addr+">" {
					t.Errorf("RCPT %d = %q, want %q", i, got[i], "RCPT TO:<"+addr+">")
				}
			}
		})
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
