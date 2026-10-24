package irc

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"firewall-mon/internal/models"

	irclib "github.com/thoj/go-ircevent"
)

// TestSanitizeErrorText_L11 pins L-11: error text that reaches the API client,
// last_error or a log line must carry no control runes (CR/LF forge log lines,
// ESC drives terminals) and must be length-capped, without splitting a rune.
func TestSanitizeErrorText_L11(t *testing.T) {
	cases := []struct{ in, want string }{
		{"dial tcp: connection refused", "dial tcp: connection refused"},
		{"SASL failed\r\nIRC: Connected to evil as admin", "SASL failed IRC: Connected to evil as admin"},
		{"bad\x1b[31mred\x00nul\ttab", "bad [31mred nul tab"},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeErrorText(c.in); got != c.want {
			t.Errorf("SanitizeErrorText(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	long := strings.Repeat("é", maxErrorTextLen) // 2 bytes per rune
	got := SanitizeErrorText(long)
	if len(got) > maxErrorTextLen+len("...") {
		t.Errorf("len = %d, want <= %d", len(got), maxErrorTextLen+3)
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncation split a rune: %q", got)
	}
}

// TestUpdateStatus_SanitizesLastError_L11: last_error is rendered in the admin
// IRC page, so the stored value must be the sanitized form.
func TestUpdateStatus_SanitizesLastError_L11(t *testing.T) {
	db := openIRCTestDB(t)
	srv := &models.IRCServer{Name: "s", ServerHost: "irc.example.com", Nick: "bot"}
	if err := db.Create(srv).Error; err != nil {
		t.Fatalf("create server: %v", err)
	}
	b := &Bot{Server: srv, db: db}
	b.updateStatus("error", "SASL failed\r\nforged line\x1b[0m")

	var got models.IRCServer
	if err := db.First(&got, srv.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if strings.ContainsAny(got.LastError, "\r\n\x1b") {
		t.Fatalf("last_error kept control bytes: %q", got.LastError)
	}
}

// TestOnNotice_NickServBodyRedacted_D33 pins D-33: a NickServ notice about
// IDENTIFY is logged without its body, which services commonly fill with the
// echoed command — i.e. the bot's NickServ password.
func TestOnNotice_NickServBodyRedacted_D33(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	b := &Bot{Server: &models.IRCServer{ServerHost: "irc.example.com"}}
	b.onNotice(&irclib.Event{
		Nick:      "NickServ",
		Arguments: []string{"bot", "Invalid command. Syntax: IDENTIFY hunter2-secret"},
	})

	out := buf.String()
	if !strings.Contains(out, "NickServ") {
		t.Fatalf("expected a NickServ log line, got %q", out)
	}
	if strings.Contains(out, "hunter2-secret") {
		t.Fatalf("NickServ notice body (credential) was logged: %q", out)
	}
}
