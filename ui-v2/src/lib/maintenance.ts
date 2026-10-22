export const RECUR_RULES = [
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly (same day of month)' },
] as const;

export const WEEKDAYS = [
  { value: 'mon', label: 'Mon' },
  { value: 'tue', label: 'Tue' },
  { value: 'wed', label: 'Wed' },
  { value: 'thu', label: 'Thu' },
  { value: 'fri', label: 'Fri' },
  { value: 'sat', label: 'Sat' },
  { value: 'sun', label: 'Sun' },
] as const;

const ALIASES: Record<string, string> = {
  mon: 'mon', monday: 'mon',
  tue: 'tue', tues: 'tue', tuesday: 'tue',
  wed: 'wed', weds: 'wed', wednesday: 'wed',
  thu: 'thu', thur: 'thu', thurs: 'thu', thursday: 'thu',
  fri: 'fri', friday: 'fri',
  sat: 'sat', saturday: 'sat',
  sun: 'sun', sunday: 'sun',
};

/** Parse stored/typed weekdays into the canonical Mon-first set. */
export function parseRecurDays(raw: string | undefined): string[] {
  const out = new Set<string>();
  for (const token of String(raw ?? '').split(',')) {
    const value = token.trim().toLowerCase();
    if (!value) continue;
    if (ALIASES[value]) {
      out.add(ALIASES[value]);
      continue;
    }
    const number = Number(value);
    if (Number.isInteger(number) && number >= 0 && number <= 7) {
      // ISO 1=Monday … 7=Sunday; 0 is accepted as Sunday.
      out.add(number === 0 ? 'sun' : WEEKDAYS[number - 1].value);
    }
  }
  return WEEKDAYS.filter((day) => out.has(day.value)).map((day) => day.value);
}

export function normalizeRecurDays(days: Iterable<string>): string {
  return parseRecurDays(Array.from(days).join(',')).join(',');
}

export function weekdayLabel(value: string): string {
  return WEEKDAYS.find((day) => day.value === value)?.label ?? value;
}

export function recurrenceLabel(
  recurring: boolean | undefined,
  rule: string | undefined,
  days: string | undefined,
): string {
  if (!recurring) return 'One-off';
  switch (String(rule ?? '').toLowerCase()) {
    case 'daily':
      return 'Daily';
    case 'weekly': {
      const selected = parseRecurDays(days).map(weekdayLabel);
      return selected.length > 0 ? `Weekly · ${selected.join(', ')}` : 'Weekly';
    }
    case 'monthly':
      return 'Monthly';
    default:
      return 'Recurring';
  }
}

/**
 * Client-side mirror of the server validation: a recurring window needs a
 * supported frequency, and weekly needs at least one day. Null means valid.
 */
export function recurrenceValidation(
  recurring: boolean | undefined,
  rule: string | undefined,
  days: string | undefined,
): string | null {
  if (!recurring) return null;
  const value = String(rule ?? '').toLowerCase();
  if (value !== 'daily' && value !== 'weekly' && value !== 'monthly') {
    return 'Choose a repeat frequency';
  }
  if (value === 'weekly' && parseRecurDays(days).length === 0) {
    return 'Select at least one weekday for a weekly window';
  }
  return null;
}
