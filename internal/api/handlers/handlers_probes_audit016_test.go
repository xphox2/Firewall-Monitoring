package handlers

import (
	"net/http"
	"strings"
	"testing"
)

// TestValidateProbe_ConstantTimeKeyCompare_AUDIT016 locks in AUDIT-016:
// the registration-key check inside validateProbe must use a constant-time
// compare so a network attacker cannot reduce the key search space via a
// single-character timing oracle.
//
// We can't actually measure timing in a unit test (CI noise), but we CAN
// assert the behavioral contract:
//  1. Token equal to stored key → accepted.
//  2. Token of same length but different content → rejected (the case where
//     a naive `==` would short-circuit at the first mismatched byte).
//  3. Token of different length → rejected.
//  4. Empty token after `Bearer ` → rejected.
//  5. Token that is a prefix of the stored key → rejected (length differs).
//  6. Token that has the stored key as a prefix → rejected (length differs).
func TestValidateProbe_ConstantTimeKeyCompare_AUDIT016(t *testing.T) {
	h, db := setupTestHandler(t)
	probe, device := setupProbeAndDevice(t, db)
	correct := probe.RegistrationKey

	if len(correct) < 8 {
		t.Fatalf("test fixture key too short to mutate: %q", correct)
	}

	type tc struct {
		name     string
		token    string
		wantCode int
		why      string
	}
	cases := []tc{
		{"correct", correct, http.StatusOK, "matches stored key exactly"},
		{"flip last byte", correct[:len(correct)-1] + "Z", http.StatusUnauthorized, "same length, last byte differs"},
		{"flip first byte", "Z" + correct[1:], http.StatusUnauthorized, "same length, first byte differs (would short-circuit a == compare)"},
		{"flip middle byte", correct[:len(correct)/2] + "Z" + correct[len(correct)/2+1:], http.StatusUnauthorized, "same length, middle byte differs"},
		{"shorter by one", correct[:len(correct)-1], http.StatusUnauthorized, "prefix of stored key"},
		{"longer by one", correct + "Z", http.StatusUnauthorized, "stored key is prefix of token"},
		{"all uppercase", strings.ToUpper(correct), http.StatusUnauthorized, "compare is case-sensitive"},
		{"empty", "", http.StatusUnauthorized, "empty token rejected"},
		{"whitespace-padded", " " + correct, http.StatusUnauthorized, "leading whitespace rejected (no trimming)"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := doTestRequest(t, h.ReceiveConfigRevision, "POST", "/config-revision", probe.ID, c.token, map[string]interface{}{
				"device_id":   device.ID,
				"config_text": "test",
				"checksum":    "abc",
				"length":      4,
			})
			if w.Code != c.wantCode {
				t.Errorf("token %q (%s): got status %d, want %d; body: %s", c.token, c.why, w.Code, c.wantCode, w.Body.String())
			}
		})
	}
}
