package database

import (
	"testing"
	"time"

	"firewall-mon/internal/auth"
	"firewall-mon/internal/models"
)

// TestAdminProfile_UpdateTouchesOnlyProfileColumns pins the v28 self-service
// write path: UpdateAdminProfile must change exactly email/full_name and leave
// the security-bearing columns (password, role, token_version, TOTP state)
// untouched, so a profile save can never become an escalation or lockout.
func TestAdminProfile_UpdateTouchesOnlyProfileColumns(t *testing.T) {
	d := NewDatabaseForTesting(t)

	u := models.Admin{Username: "op", Password: "hash", Role: auth.RoleOperator}
	if err := d.CreateAdmin(&u); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	tvBefore, _ := d.GetAdminTokenVersion(u.ID)

	if err := d.UpdateAdminProfile(u.ID, "noc@example.test", "Ops Person"); err != nil {
		t.Fatalf("UpdateAdminProfile: %v", err)
	}

	got, err := d.GetAdminByID(u.ID)
	if err != nil || got == nil {
		t.Fatalf("GetAdminByID: %v", err)
	}
	if got.Email != "noc@example.test" || got.FullName != "Ops Person" {
		t.Fatalf("profile fields not persisted: email=%q full_name=%q", got.Email, got.FullName)
	}
	if got.Password != "hash" || got.Role != auth.RoleOperator {
		t.Fatalf("profile update clobbered security columns: password=%q role=%q", got.Password, got.Role)
	}
	if tvAfter, _ := d.GetAdminTokenVersion(u.ID); tvAfter != tvBefore {
		t.Fatalf("profile update must not bump token_version: %d -> %d", tvBefore, tvAfter)
	}

	// Clearing works too (empty strings are valid values, not "no change").
	if err := d.UpdateAdminProfile(u.ID, "", ""); err != nil {
		t.Fatalf("UpdateAdminProfile clear: %v", err)
	}
	got, _ = d.GetAdminByID(u.ID)
	if got.Email != "" || got.FullName != "" {
		t.Fatalf("clear did not stick: email=%q full_name=%q", got.Email, got.FullName)
	}
}

// TestAdminProfile_MFAPromptDismissedFirstTimestampWins pins the decline
// semantics: NULL until the user explicitly declines, set exactly once, and
// repeat declines preserve the ORIGINAL acceptance-of-risk timestamp.
func TestAdminProfile_MFAPromptDismissedFirstTimestampWins(t *testing.T) {
	d := NewDatabaseForTesting(t)

	u := models.Admin{Username: "viewer", Password: "hash", Role: auth.RoleViewer}
	if err := d.CreateAdmin(&u); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	got, _ := d.GetAdminByID(u.ID)
	if got.MFAPromptDismissedAt != nil {
		t.Fatalf("fresh account must have NULL mfa_prompt_dismissed_at, got %v", got.MFAPromptDismissedAt)
	}

	if err := d.SetAdminMFAPromptDismissed(u.ID); err != nil {
		t.Fatalf("SetAdminMFAPromptDismissed: %v", err)
	}
	got, _ = d.GetAdminByID(u.ID)
	if got.MFAPromptDismissedAt == nil {
		t.Fatal("decline did not persist")
	}
	first := *got.MFAPromptDismissedAt

	time.Sleep(15 * time.Millisecond)
	if err := d.SetAdminMFAPromptDismissed(u.ID); err != nil {
		t.Fatalf("second SetAdminMFAPromptDismissed: %v", err)
	}
	got, _ = d.GetAdminByID(u.ID)
	if !got.MFAPromptDismissedAt.Equal(first) {
		t.Fatalf("repeat decline must keep the first timestamp: %v -> %v", first, *got.MFAPromptDismissedAt)
	}
}
