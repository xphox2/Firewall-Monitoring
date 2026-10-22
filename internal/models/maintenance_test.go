package models

import (
	"strings"
	"testing"
	"time"
)

func maintenanceWindow(start, end time.Time, rule, days string) MaintenanceWindow {
	return MaintenanceWindow{
		Name:      "test",
		StartTime: start,
		EndTime:   end,
		Recurring: true,
		RecurRule: rule,
		RecurDays: days,
	}
}

func TestMaintenanceWindowActiveAt_OneOff(t *testing.T) {
	start := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	window := MaintenanceWindow{StartTime: start, EndTime: end}

	if window.ActiveAt(start.Add(-time.Minute)) {
		t.Error("active before the window")
	}
	if !window.ActiveAt(start) || !window.ActiveAt(end) {
		t.Error("boundaries must count as active")
	}
	if window.ActiveAt(end.Add(time.Second)) {
		t.Error("active after the window")
	}
}

func TestMaintenanceWindowActiveAt_Daily(t *testing.T) {
	start := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	window := maintenanceWindow(start, start.Add(2*time.Hour), MaintenanceDaily, "")

	if !window.ActiveAt(time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)) {
		t.Error("daily occurrence should be active")
	}
	if window.ActiveAt(time.Date(2026, 10, 22, 8, 59, 0, 0, time.UTC)) {
		t.Error("daily window active before its clock time")
	}
	if window.ActiveAt(time.Date(2026, 10, 22, 11, 1, 0, 0, time.UTC)) {
		t.Error("daily window active after its duration")
	}
	if window.ActiveAt(time.Date(2026, 10, 19, 9, 30, 0, 0, time.UTC)) {
		t.Error("occurrence before the series start must not fire")
	}
}

func TestMaintenanceWindowActiveAt_WeeklyAndOvernight(t *testing.T) {
	// Monday 20 Oct 2026, 23:00-01:00, Mondays only.
	start := time.Date(2026, 10, 19, 23, 0, 0, 0, time.UTC)
	window := maintenanceWindow(start, start.Add(2*time.Hour), MaintenanceWeekly, "mon")

	if !window.ActiveAt(time.Date(2026, 10, 19, 23, 30, 0, 0, time.UTC)) {
		t.Error("Monday occurrence should be active")
	}
	// Tuesday 00:30 is the tail of Monday's window even though Tuesday is not selected.
	if !window.ActiveAt(time.Date(2026, 10, 20, 0, 30, 0, 0, time.UTC)) {
		t.Error("overnight tail of the Monday occurrence should be active")
	}
	if window.ActiveAt(time.Date(2026, 10, 20, 23, 30, 0, 0, time.UTC)) {
		t.Error("Tuesday occurrence must not fire (only Monday is selected)")
	}
	if !window.ActiveAt(time.Date(2026, 10, 26, 23, 30, 0, 0, time.UTC)) {
		t.Error("next Monday should fire")
	}
}

func TestMaintenanceWindowActiveAt_Monthly(t *testing.T) {
	// 31 Jan 2026, 09:00-10:00, monthly on the 31st.
	start := time.Date(2026, 1, 31, 9, 0, 0, 0, time.UTC)
	window := maintenanceWindow(start, start.Add(time.Hour), MaintenanceMonthly, "")

	if !window.ActiveAt(time.Date(2026, 3, 31, 9, 30, 0, 0, time.UTC)) {
		t.Error("March 31 occurrence should be active")
	}
	if window.ActiveAt(time.Date(2026, 2, 28, 9, 30, 0, 0, time.UTC)) {
		t.Error("February has no 31st; the window must skip it")
	}
	if window.ActiveAt(time.Date(2026, 4, 30, 9, 30, 0, 0, time.UTC)) {
		t.Error("April 30 is not the 31st")
	}
}

func TestMaintenanceWindowActiveAt_InvalidRuleIsInactive(t *testing.T) {
	start := time.Now().Add(-time.Hour)
	window := maintenanceWindow(start, start.Add(2*time.Hour), "cron", "")
	if window.ActiveAt(time.Now()) {
		t.Error("an unsupported rule must not activate the window")
	}
}

func TestNormalizeRecurrence(t *testing.T) {
	weekly := MaintenanceWindow{Recurring: true, RecurRule: "WEEKLY", RecurDays: "wed, MON,2"}
	if err := weekly.NormalizeRecurrence(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if weekly.RecurRule != MaintenanceWeekly || weekly.RecurDays != "mon,tue,wed" {
		t.Errorf("normalized = %q/%q, want weekly/mon,tue,wed", weekly.RecurRule, weekly.RecurDays)
	}

	noDays := MaintenanceWindow{Recurring: true, RecurRule: "weekly", RecurDays: "nope"}
	if err := noDays.NormalizeRecurrence(); err == nil {
		t.Error("weekly without usable days must be rejected")
	}

	daily := MaintenanceWindow{Recurring: true, RecurRule: "daily", RecurDays: "mon"}
	if err := daily.NormalizeRecurrence(); err != nil {
		t.Fatalf("daily normalize: %v", err)
	}
	if daily.RecurDays != "" {
		t.Errorf("non-weekly days = %q, want empty", daily.RecurDays)
	}

	oneOff := MaintenanceWindow{Recurring: false, RecurRule: "weekly", RecurDays: "mon"}
	if err := oneOff.NormalizeRecurrence(); err != nil {
		t.Fatalf("one-off normalize: %v", err)
	}
	if oneOff.RecurRule != "" || oneOff.RecurDays != "" {
		t.Errorf("one-off recurrence = %q/%q, want empty", oneOff.RecurRule, oneOff.RecurDays)
	}
}

func TestNormalizeRecurDays_NumbersAndNames(t *testing.T) {
	if got, err := NormalizeRecurDays("MO,tu"); err != nil || got != "mon,tue" {
		t.Errorf("two-letter aliases = %q/%v, want mon,tue", got, err)
	}
	got, err := NormalizeRecurDays("7,1,sunday")
	if err != nil {
		t.Fatalf("normalize days: %v", err)
	}
	if got != "mon,sun" {
		t.Errorf("days = %q, want mon,sun", got)
	}
	if !strings.Contains(got, ",") {
		t.Error("expected a comma-joined canonical list")
	}
}
