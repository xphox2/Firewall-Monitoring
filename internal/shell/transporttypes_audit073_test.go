package shell

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestTransportTypesMovedOutOfModels_AUDIT073 pins the architectural boundary
// the audit asked for: the HTTP transport envelope (APIResponse + its
// Success/Error/Message constructors) must live in internal/api/response, NOT
// in the GORM model package internal/models. The model package should describe
// database rows only; mixing the wire shape in there coupled two unrelated
// concerns.
//
// The guard has two halves: (1) internal/models no longer declares the
// transport type/constructors, and (2) internal/api/response does.
func TestTransportTypesMovedOutOfModels_AUDIT073(t *testing.T) {
	const modelsPath = "../models/models.go"
	const responsePath = "../api/response/response.go"

	modelsBody, err := os.ReadFile(modelsPath)
	if err != nil {
		t.Skipf("%s not found; err: %v", modelsPath, err)
	}
	responseBody, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatalf("internal/api/response/response.go is missing (AUDIT-073): the transport types must have a home; err: %v", err)
	}

	// (1) models must not DECLARE the transport type or its constructors.
	// Match declarations specifically (a comment mentioning the move is fine).
	bannedDecls := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^type APIResponse struct`),
		regexp.MustCompile(`(?m)^func SuccessResponse\(`),
		regexp.MustCompile(`(?m)^func ErrorResponse\(`),
		regexp.MustCompile(`(?m)^func MessageResponse\(`),
	}
	for _, re := range bannedDecls {
		if re.MatchString(string(modelsBody)) {
			t.Errorf("internal/models/models.go still declares %q (AUDIT-073); the HTTP transport envelope belongs in internal/api/response, not the GORM model package.", re.String())
		}
	}

	// (2) response must declare the envelope + the three constructors.
	rb := string(responseBody)
	for _, want := range []string{"type APIResponse struct", "func Success(", "func Error(", "func Message("} {
		if !strings.Contains(rb, want) {
			t.Errorf("internal/api/response/response.go is missing %q (AUDIT-073); the moved transport contract must be complete.", want)
		}
	}
}
