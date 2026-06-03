package irc

import (
	"testing"

	"firewall-mon/internal/models"
)

// TestChannelNickAllowed_AUDIT019 is the headline regression for the
// per-channel admin allow-list. It exercises channelNickAllowed directly
// (the unexported helper used by Bot.isAdmin) and covers the cases that
// the old "only the bot itself is admin" behavior got wrong:
//
//   - The bot's own nick is NOT auto-admin (fail-closed default).
//   - Empty allow list denies everyone.
//   - Single nick, multiple nicks, mixed case, surrounding whitespace,
//     and the "missing trailing entry" edge case.
//
// The new Bot.isAdmin(channel, nick) is also tested end-to-end below.
func TestChannelNickAllowed_AUDIT019(t *testing.T) {
	tests := []struct {
		name      string
		allowList string
		nick      string
		want      bool
	}{
		{"empty list denies everyone", "", "alice", false},
		{"empty list denies bot-self too (fail-closed)", "", "fwmon-bot", false},
		{"whitespace-only list denies", "   ", "alice", false},
		{"single nick match", "alice", "alice", true},
		{"single nick mismatch", "alice", "bob", false},
		{"case-insensitive match (lower in list)", "alice", "Alice", true},
		{"case-insensitive match (upper in list)", "Alice", "ALICE", true},
		{"multiple nicks, second matches", "alice;bob", "bob", true},
		{"multiple nicks, first matches", "alice;bob", "alice", true},
		{"multiple nicks, neither matches", "alice;bob", "carol", false},
		{"surrounding whitespace around nicks", " alice ; bob ", "bob", true},
		{"empty entry between semicolons is skipped", "alice;;bob", "bob", true},
		{"trailing semicolon with empty entry", "alice;", "alice", true},
		{"leading semicolon with empty entry", ";alice", "alice", true},
		{"nick with leading/trailing whitespace is rejected", "alice", " alice ", false},
		// Negative: a partial match must NOT count. "alic" must not match "alice".
		{"partial nick is not a match", "alice", "alic", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := channelNickAllowed(tc.allowList, tc.nick)
			if got != tc.want {
				t.Errorf("channelNickAllowed(%q, %q) = %v, want %v", tc.allowList, tc.nick, got, tc.want)
			}
		})
	}
}

// TestBot_IsAdmin_AUDIT019 — end-to-end check that Bot.isAdmin consults
// the per-channel allow-list correctly. Uses a stub Server with a couple
// of channels. We never connect to IRC (Bot.Conn is nil), which exercises
// the path where "no live connection" should NOT cause isAdmin to crash
// or to fall back to the old bot-self behavior.
func TestBot_IsAdmin_AUDIT019(t *testing.T) {
	b := &Bot{
		Server: &models.IRCServer{
			Nick: "fwmon-bot",
			Channels: []models.IRCChannel{
				{ChannelName: "#ops", AdminNicks: "alice;bob"},
				{ChannelName: "#alerts", AdminNicks: ""}, // explicitly no admins
				{ChannelName: "#mixed", AdminNicks: "ChanOp"},
			},
		},
	}

	cases := []struct {
		name    string
		target  string
		nick    string
		wantAdm bool
	}{
		// #ops — alice and bob are admins
		{"#ops alice is admin", "#ops", "alice", true},
		{"#ops bob is admin", "#ops", "bob", true},
		{"#ops carol is not admin", "#ops", "carol", false},
		{"#ops case-insensitive", "#ops", "ALICE", true},
		// #alerts — explicitly no admins
		{"#alerts nobody is admin (empty list)", "#alerts", "alice", false},
		{"#alerts bot-self is NOT admin (regression)", "#alerts", "fwmon-bot", false},
		// #mixed — single admin
		{"#mixed configured admin is admin", "#mixed", "ChanOp", true},
		{"#mixed case-insensitive single admin", "#mixed", "chanop", true},
		{"#mixed other user is not admin", "#mixed", "alice", false},
		// Private message to the bot
		{"PM to bot is denied even for admin nick", "fwmon-bot", "alice", false},
		{"PM to bot is denied for bot-self too", "fwmon-bot", "fwmon-bot", false},
		// Unknown channel
		{"unknown channel denied", "#notconfigured", "alice", false},
		{"unknown channel denied for bot-self too", "#notconfigured", "fwmon-bot", false},
		// Empty target
		{"empty target denied", "", "alice", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := b.isAdmin(tc.target, tc.nick)
			if got != tc.wantAdm {
				t.Errorf("Bot.isAdmin(%q, %q) = %v, want %v", tc.target, tc.nick, got, tc.wantAdm)
			}
		})
	}
}

// TestBot_IsAdmin_NilServer_AUDIT019 — guard against the deref panic if
// the bot is constructed without a Server (e.g. in a partial init path).
// isAdmin must return false rather than crash.
func TestBot_IsAdmin_NilServer_AUDIT019(t *testing.T) {
	b := &Bot{}
	if got := b.isAdmin("#ops", "alice"); got != false {
		t.Errorf("Bot.isAdmin with nil Server returned %v, want false", got)
	}
}
