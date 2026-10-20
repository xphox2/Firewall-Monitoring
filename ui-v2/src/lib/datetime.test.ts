import { describe, expect, it } from 'vitest';
import { fromLocalInput, toLocalInput } from './datetime';

describe('datetime-local conversion', () => {
  it('renders a UTC instant as the matching local wall clock', () => {
    const local = '2026-10-20T14:05';
    const iso = new Date(2026, 9, 20, 14, 5).toISOString();

    expect(toLocalInput(iso)).toBe(local);
    expect(fromLocalInput(local)).toBe(iso);
  });

  it('round-trips without drifting on repeated edits', () => {
    const iso = new Date(2026, 0, 31, 23, 45).toISOString();
    const first = toLocalInput(iso);
    const saved = fromLocalInput(first);
    const second = toLocalInput(saved);

    expect(saved).toBe(iso);
    expect(second).toBe(first);
  });

  it('treats an empty or malformed value as empty rather than inventing one', () => {
    expect(fromLocalInput('')).toBe('');
    expect(fromLocalInput('not-a-date')).toBe('');
    expect(toLocalInput('not-a-date')).toBe('');
  });
});
