import { describe, expect, it } from 'vitest';
import { unwrapEnvelope } from './api';

describe('unwrapEnvelope', () => {
  it('keeps the sibling keys the old unwrap dropped', () => {
    // The backfill status endpoint puts `history`, `resumable` and `hint`
    // BESIDE `data`. The old unwrap returned `data` alone, so the panel
    // could never show them.
    const out = unwrapEnvelope<Record<string, unknown>>({
      success: true,
      data: { status: 'running', rows_scanned: 100 },
      history: [{ id: 1 }],
      resumable: true,
      hint: 'resume where it stopped',
    });
    expect(out.status).toBe('running');
    expect(out.rows_scanned).toBe(100);
    expect(out.history).toEqual([{ id: 1 }]);
    expect(out.resumable).toBe(true);
    expect(out.hint).toBe('resume where it stopped');
  });

  it('keeps the estimate the backfill and restore confirmations need', () => {
    const out = unwrapEnvelope<Record<string, unknown>>({
      success: true,
      data: { id: 7 },
      estimate: { rows: 1000, bytes: 4096 },
    });
    expect(out.id).toBe(7);
    expect(out.estimate).toEqual({ rows: 1000, bytes: 4096 });
  });

  it('drops the envelope keys themselves', () => {
    // `success`, `error` and `message` are the envelope's, not the
    // payload's — they must not leak into the unwrapped object.
    const out = unwrapEnvelope<Record<string, unknown>>({
      success: true,
      error: null,
      message: null,
      data: { a: 1 },
    });
    expect(out).toEqual({ a: 1 });
    expect('success' in out).toBe(false);
    expect('error' in out).toBe(false);
    expect('message' in out).toBe(false);
  });

  it('returns an ARRAY data untouched', () => {
    // The traps and flows endpoints return a bare array. There is nothing
    // to merge into, and the callers expect an array.
    const out = unwrapEnvelope<unknown[]>({ success: true, data: [1, 2, 3] });
    expect(Array.isArray(out)).toBe(true);
    expect(out).toEqual([1, 2, 3]);
  });

  it('returns a scalar data untouched', () => {
    expect(unwrapEnvelope<string>({ success: true, data: 'ok' })).toBe('ok');
    expect(unwrapEnvelope<number>({ success: true, data: 42 })).toBe(42);
  });

  it('returns null data untouched', () => {
    expect(unwrapEnvelope<null>({ success: true, data: null })).toBeNull();
  });
});
