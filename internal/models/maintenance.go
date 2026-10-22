package models

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Recurrence rules for MaintenanceWindow. A recurring window's StartTime is
// the FIRST occurrence and EndTime defines its duration; later occurrences
// start at the same clock time (in the evaluation location) on the selected
// days. The series never expires — delete the window to stop it.
const (
	MaintenanceDaily   = "daily"
	MaintenanceWeekly  = "weekly"
	MaintenanceMonthly = "monthly"
)

var maintenanceWeekdays = []struct {
	name string
	day  time.Weekday
}{
	{"mon", time.Monday},
	{"tue", time.Tuesday},
	{"wed", time.Wednesday},
	{"thu", time.Thursday},
	{"fri", time.Friday},
	{"sat", time.Saturday},
	{"sun", time.Sunday},
}

var maintenanceWeekdayAliases = map[string]time.Weekday{
	"mo": time.Monday, "mon": time.Monday, "monday": time.Monday,
	"tu": time.Tuesday, "tue": time.Tuesday, "tues": time.Tuesday, "tuesday": time.Tuesday,
	"we": time.Wednesday, "wed": time.Wednesday, "weds": time.Wednesday, "wednesday": time.Wednesday,
	"th": time.Thursday, "thu": time.Thursday, "thur": time.Thursday, "thurs": time.Thursday, "thursday": time.Thursday,
	"fr": time.Friday, "fri": time.Friday, "friday": time.Friday,
	"sa": time.Saturday, "sat": time.Saturday, "saturday": time.Saturday,
	"su": time.Sunday, "sun": time.Sunday, "sunday": time.Sunday,
}

// NormalizeRecurRule canonicalises a rule name.
func NormalizeRecurRule(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case MaintenanceDaily:
		return MaintenanceDaily, nil
	case MaintenanceWeekly:
		return MaintenanceWeekly, nil
	case MaintenanceMonthly:
		return MaintenanceMonthly, nil
	default:
		return "", fmt.Errorf("recur_rule must be daily, weekly or monthly")
	}
}

// ParseRecurDays accepts weekday names ("mon", "monday") and ISO numbers
// (1=Monday … 7=Sunday, plus 0=Sunday) separated by commas. Unknown tokens are
// ignored; validation happens in NormalizeRecurDays.
func ParseRecurDays(raw string) map[time.Weekday]bool {
	out := make(map[time.Weekday]bool)
	for _, part := range strings.Split(raw, ",") {
		token := strings.ToLower(strings.TrimSpace(part))
		if token == "" {
			continue
		}
		if day, ok := maintenanceWeekdayAliases[token]; ok {
			out[day] = true
			continue
		}
		number, err := strconv.Atoi(token)
		if err != nil {
			continue
		}
		switch {
		case number == 0:
			out[time.Sunday] = true
		case number >= 1 && number <= 7:
			// ISO 1=Monday … 6=Saturday, 7=Sunday; time.Weekday is 0=Sunday.
			out[time.Weekday(number%7)] = true
		}
	}
	return out
}

// NormalizeRecurDays canonicalises the selected weekdays to Mon-first
// three-letter names, or errors when none are usable.
func NormalizeRecurDays(raw string) (string, error) {
	days := ParseRecurDays(raw)
	if len(days) == 0 {
		return "", fmt.Errorf("recur_days must name at least one weekday (mon,tue,…)")
	}
	parts := make([]string, 0, len(days))
	for _, entry := range maintenanceWeekdays {
		if days[entry.day] {
			parts = append(parts, entry.name)
		}
	}
	return strings.Join(parts, ","), nil
}

// NormalizeRecurrence validates and canonicalises the recurrence fields.
// A one-off window has them cleared so a later toggle to recurring starts from
// a predictable empty state.
func (w *MaintenanceWindow) NormalizeRecurrence() error {
	if !w.Recurring {
		w.RecurRule = ""
		w.RecurDays = ""
		return nil
	}
	rule, err := NormalizeRecurRule(w.RecurRule)
	if err != nil {
		return err
	}
	w.RecurRule = rule
	if rule != MaintenanceWeekly {
		w.RecurDays = ""
		return nil
	}
	days, err := NormalizeRecurDays(w.RecurDays)
	if err != nil {
		return err
	}
	w.RecurDays = days
	return nil
}

// ActiveAt reports whether the window is active at now. One-off windows use
// their absolute start/end. Recurring windows treat StartTime as the first
// occurrence, EndTime as the duration, and repeat at that clock time on the
// rule's days (weekly uses RecurDays; monthly uses StartTime's day-of-month,
// skipping months that do not have it).
func (w MaintenanceWindow) ActiveAt(now time.Time) bool {
	if !w.Recurring {
		return !now.Before(w.StartTime) && !now.After(w.EndTime)
	}
	duration := w.EndTime.Sub(w.StartTime)
	if duration <= 0 {
		return false
	}

	location := now.Location()
	seriesStart := w.StartTime.In(location)
	rule := strings.ToLower(strings.TrimSpace(w.RecurRule))
	days := ParseRecurDays(w.RecurDays)
	// Occurrences can cross midnight, so check starts far enough back.
	lookback := int(duration/(24*time.Hour)) + 1

	for back := 0; back <= lookback; back++ {
		day := now.AddDate(0, 0, -back)
		candidate := time.Date(
			day.Year(), day.Month(), day.Day(),
			seriesStart.Hour(), seriesStart.Minute(), seriesStart.Second(), seriesStart.Nanosecond(),
			location,
		)
		if candidate.Before(seriesStart) {
			continue
		}
		switch rule {
		case MaintenanceDaily:
			// every day
		case MaintenanceWeekly:
			if !days[day.Weekday()] {
				continue
			}
		case MaintenanceMonthly:
			if day.Day() != seriesStart.Day() {
				continue
			}
		default:
			return false
		}
		if !now.Before(candidate) && !now.After(candidate.Add(duration)) {
			return true
		}
	}
	return false
}
