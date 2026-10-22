import { describe, expect, it } from 'vitest';
import {
  normalizeRecurDays,
  parseRecurDays,
  recurrenceLabel,
  recurrenceValidation,
} from './maintenance';

describe('parseRecurDays', () => {
  it('accepts names, abbreviations and ISO numbers in canonical order', () => {
    expect(parseRecurDays('wed, MON,2')).toEqual(['mon', 'tue', 'wed']);
    expect(parseRecurDays('7,1,sunday')).toEqual(['mon', 'sun']);
    expect(parseRecurDays('0')).toEqual(['sun']);
  });

  it('drops unknown tokens and deduplicates', () => {
    expect(parseRecurDays('mon,mon,nope,')).toEqual(['mon']);
    expect(parseRecurDays(undefined)).toEqual([]);
  });
});

describe('normalizeRecurDays', () => {
  it('joins the canonical set', () => {
    expect(normalizeRecurDays(['sun', 'mon'])).toBe('mon,sun');
    expect(normalizeRecurDays([])).toBe('');
  });
});

describe('recurrenceLabel', () => {
  it('describes each schedule shape', () => {
    expect(recurrenceLabel(false, 'weekly', 'mon')).toBe('One-off');
    expect(recurrenceLabel(true, 'daily', '')).toBe('Daily');
    expect(recurrenceLabel(true, 'weekly', 'mon,wed')).toBe('Weekly · Mon, Wed');
    expect(recurrenceLabel(true, 'weekly', '')).toBe('Weekly');
    expect(recurrenceLabel(true, 'monthly', '')).toBe('Monthly');
  });
});

describe('recurrenceValidation', () => {
  it('requires a frequency and weekly days', () => {
    expect(recurrenceValidation(false, '', '')).toBeNull();
    expect(recurrenceValidation(true, '', 'mon')).toBe('Choose a repeat frequency');
    expect(recurrenceValidation(true, 'weekly', '')).toBe(
      'Select at least one weekday for a weekly window',
    );
    expect(recurrenceValidation(true, 'weekly', 'mon')).toBeNull();
    expect(recurrenceValidation(true, 'daily', '')).toBeNull();
  });
});
