package middleware

import (
	"strings"
	"testing"
)

// TestParseCORSAllowedOrigins_WildcardRejected locks in AUDIT-015: the
// CORS_ALLOWED_ORIGINS value MUST NOT contain "*" because the CORS middleware
// always sends Access-Control-Allow-Credentials: true and the combination
// allows any third-party site to issue authenticated cross-origin requests
// against the cookie-based admin session.
func TestParseCORSAllowedOrigins_WildcardRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"bare star", "*"},
		{"star alongside real origin", "https://example.com,*"},
		{"star with leading whitespace", " *"},
		{"star with surrounding whitespace", "  *  "},
		{"star in middle of list", "https://a.example, *, https://b.example"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseCORSAllowedOrigins(c.raw)
			if err == nil {
				t.Fatalf("parseCORSAllowedOrigins(%q) returned no error; wildcard must be rejected", c.raw)
			}
			if !strings.Contains(err.Error(), "*") {
				t.Errorf("error message %q does not mention the wildcard", err.Error())
			}
			if !strings.Contains(strings.ToLower(err.Error()), "credentials") {
				t.Errorf("error message %q does not explain the Allow-Credentials interaction", err.Error())
			}
		})
	}
}

// TestParseCORSAllowedOrigins_ValidInputs verifies the happy paths and
// edge cases that DO NOT involve a wildcard.
func TestParseCORSAllowedOrigins_ValidInputs(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]bool
	}{
		{"empty", "", map[string]bool{}},
		{"only whitespace", "   ", map[string]bool{}},
		{"one origin", "https://admin.example", map[string]bool{"https://admin.example": true}},
		{"two origins", "https://a.example,https://b.example", map[string]bool{"https://a.example": true, "https://b.example": true}},
		{"surrounding whitespace trimmed", " https://a.example , https://b.example ", map[string]bool{"https://a.example": true, "https://b.example": true}},
		{"empty entries skipped", "https://a.example,,https://b.example", map[string]bool{"https://a.example": true, "https://b.example": true}},
		{"trailing comma skipped", "https://a.example,", map[string]bool{"https://a.example": true}},
		{"with port", "https://a.example:8443", map[string]bool{"https://a.example:8443": true}},
		{"http and https treated as distinct", "http://a.example,https://a.example", map[string]bool{"http://a.example": true, "https://a.example": true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseCORSAllowedOrigins(c.raw)
			if err != nil {
				t.Fatalf("parseCORSAllowedOrigins(%q) returned unexpected error: %v", c.raw, err)
			}
			if len(got) != len(c.want) {
				t.Errorf("len(got) = %d, want %d (got=%v want=%v)", len(got), len(c.want), got, c.want)
			}
			for k := range c.want {
				if !got[k] {
					t.Errorf("expected origin %q missing", k)
				}
			}
			for k := range got {
				if !c.want[k] {
					t.Errorf("unexpected origin %q in result", k)
				}
			}
		})
	}
}
