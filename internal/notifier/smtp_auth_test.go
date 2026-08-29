package notifier

import (
	"net/smtp"
	"testing"
)

func TestLoginAuthStart(t *testing.T) {
	const host = "smtp.example.com"
	cases := []struct {
		name     string
		host     string // LoginAuth host; defaults to the const above
		server   *smtp.ServerInfo
		wantErr  bool
		wantMech string
	}{
		{"valid TLS + matching host", "", &smtp.ServerInfo{Name: host, TLS: true}, false, "LOGIN"},
		{"wrong host rejected", "", &smtp.ServerInfo{Name: "evil.example.com", TLS: true}, true, ""},
		{"cleartext rejected", "", &smtp.ServerInfo{Name: host, TLS: false}, true, ""},
		// AUDIT-285: the stdlib PlainAuth parity — cleartext is allowed to an
		// explicitly-local relay, so a LOGIN-only localhost relay works too.
		{"cleartext localhost allowed", "localhost", &smtp.ServerInfo{Name: "localhost", TLS: false}, false, "LOGIN"},
		{"cleartext 127.0.0.1 allowed", "127.0.0.1", &smtp.ServerInfo{Name: "127.0.0.1", TLS: false}, false, "LOGIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authHost := tc.host
			if authHost == "" {
				authHost = host
			}
			a := LoginAuth("user", "pass", authHost)
			mech, resp, err := a.Start(tc.server)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mech=%q", mech)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mech != tc.wantMech {
				t.Errorf("mech = %q, want %q", mech, tc.wantMech)
			}
			if resp != nil {
				t.Errorf("LOGIN must send no initial response, got %q", resp)
			}
		})
	}
}

func TestLoginAuthNextSequence(t *testing.T) {
	a := LoginAuth("alice", "s3cret", "smtp.example.com")

	// more=false → nothing to send.
	if got, err := a.Next(nil, false); err != nil || got != nil {
		t.Fatalf("Next(_, false) = %q, %v; want nil, nil", got, err)
	}

	// Step 0 → username, step 1 → password, regardless of the prompt text.
	if got, err := a.Next([]byte("Username:"), true); err != nil || string(got) != "alice" {
		t.Fatalf("step 0 = %q, %v; want \"alice\", nil", got, err)
	}
	if got, err := a.Next([]byte("Password:"), true); err != nil || string(got) != "s3cret" {
		t.Fatalf("step 1 = %q, %v; want \"s3cret\", nil", got, err)
	}
	// A third challenge is a protocol error.
	if _, err := a.Next([]byte("???"), true); err == nil {
		t.Fatal("expected error on unexpected third challenge")
	}
}

func TestCompoundAuthSelection(t *testing.T) {
	const host = "smtp.example.com"
	cases := []struct {
		name       string
		host       string // defaults to the const above
		noTLS      bool
		advertised []string
		wantMech   string
		wantErr    bool
	}{
		{"PLAIN preferred over LOGIN", "", false, []string{"LOGIN", "PLAIN"}, "PLAIN", false},
		{"LOGIN when only LOGIN", "", false, []string{"LOGIN"}, "LOGIN", false},
		{"PLAIN when only PLAIN", "", false, []string{"PLAIN"}, "PLAIN", false},
		{"case-insensitive + whitespace", "", false, []string{" plain "}, "PLAIN", false},
		{"neither offered → error", "", false, []string{"CRAM-MD5", "XOAUTH2"}, "", true},
		// AUDIT-285: a LOGIN-only cleartext relay on localhost must work — the
		// stdlib's PlainAuth already allows the identical PLAIN configuration.
		{"LOGIN-only no-TLS localhost", "localhost", true, []string{"LOGIN"}, "LOGIN", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authHost := tc.host
			if authHost == "" {
				authHost = host
			}
			a := CompoundAuth("user", "pass", authHost)
			// Matching host (and TLS unless the case tests cleartext) so the
			// inner auth's Start() gate passes.
			_, _, err := a.Start(&smtp.ServerInfo{Name: authHost, TLS: !tc.noTLS, Auth: tc.advertised})
			ca := a.(*compoundAuth)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, chose %q", ca.ChosenMechanism())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ca.ChosenMechanism() != tc.wantMech {
				t.Errorf("ChosenMechanism() = %q, want %q", ca.ChosenMechanism(), tc.wantMech)
			}
		})
	}
}

func TestCompoundAuthNextBeforeStart(t *testing.T) {
	a := CompoundAuth("user", "pass", "smtp.example.com")
	if _, err := a.Next(nil, true); err == nil {
		t.Fatal("expected error when Next is called before Start")
	}
}

func TestCompoundAuthChosenMechanismBeforeStart(t *testing.T) {
	a := CompoundAuth("user", "pass", "smtp.example.com").(*compoundAuth)
	if got := a.ChosenMechanism(); got != "" {
		t.Errorf("ChosenMechanism() before Start = %q, want \"\"", got)
	}
}
