import { describe, expect, it } from 'vitest';
import {
  OVERLAY_DELAY_MS,
  elapsedSeconds,
  formatElapsed,
  gaugePercent,
  gaugeStrokeColour,
  overlayShouldShow,
  particleColourForKind,
} from './motion';

describe('formatElapsed', () => {
  it('shows whole seconds under a minute', () => {
    expect(formatElapsed(0)).toBe('0 s');
    expect(formatElapsed(1)).toBe('1 s');
    expect(formatElapsed(59)).toBe('59 s');
  });

  it('switches to minutes and seconds past a minute', () => {
    expect(formatElapsed(60)).toBe('1 min 0 s');
    expect(formatElapsed(61)).toBe('1 min 1 s');
    expect(formatElapsed(125)).toBe('2 min 5 s');
  });

  it('never renders a negative duration', () => {
    expect(formatElapsed(-5)).toBe('0 s');
  });
});

describe('elapsedSeconds', () => {
  it('counts whole seconds since the load started', () => {
    expect(elapsedSeconds(1000, 1000)).toBe(0);
    expect(elapsedSeconds(1000, 1999)).toBe(0);
    expect(elapsedSeconds(1000, 2000)).toBe(1);
    expect(elapsedSeconds(1000, 65000)).toBe(64);
  });

  it('is zero before the load has started', () => {
    expect(elapsedSeconds(null, 5000)).toBe(0);
  });

  it('never goes backwards', () => {
    expect(elapsedSeconds(5000, 1000)).toBe(0);
  });
});

describe('overlayShouldShow', () => {
  it('stays hidden for a load that answers quickly', () => {
    // The whole point of the delay: a fast load must not flash an overlay.
    expect(overlayShouldShow(true, 1000, 1000)).toBe(false);
    expect(overlayShouldShow(true, 1000, 1000 + OVERLAY_DELAY_MS - 1)).toBe(false);
  });

  it('appears once the delay has passed', () => {
    expect(overlayShouldShow(true, 1000, 1000 + OVERLAY_DELAY_MS)).toBe(true);
    expect(overlayShouldShow(true, 1000, 5000)).toBe(true);
  });

  it('never shows for an inactive load', () => {
    expect(overlayShouldShow(false, 1000, 99999)).toBe(false);
  });

  it('never shows before the load has started', () => {
    expect(overlayShouldShow(true, null, 99999)).toBe(false);
  });
});

describe('gaugePercent', () => {
  it('scales the value against the maximum', () => {
    expect(gaugePercent(50, 100)).toBe(50);
    expect(gaugePercent(1, 4)).toBe(25);
  });

  it('clamps above the maximum', () => {
    expect(gaugePercent(150, 100)).toBe(100);
  });

  it('is zero when the maximum is not positive', () => {
    // A zero maximum would divide by zero; V1 guarded it the same way.
    expect(gaugePercent(10, 0)).toBe(0);
    expect(gaugePercent(10, -5)).toBe(0);
  });
});

describe('gaugeStrokeColour', () => {
  it('is green below the warning threshold', () => {
    expect(gaugeStrokeColour(0)).toBe('var(--fwmon-sig-ok)');
    expect(gaugeStrokeColour(69.9)).toBe('var(--fwmon-sig-ok)');
  });

  it('is amber from 70% and critical from 90%', () => {
    expect(gaugeStrokeColour(70)).toBe('var(--fwmon-sig-warn)');
    expect(gaugeStrokeColour(89.9)).toBe('var(--fwmon-sig-warn)');
    expect(gaugeStrokeColour(90)).toBe('var(--fwmon-sig-crit)');
    expect(gaugeStrokeColour(100)).toBe('var(--fwmon-sig-crit)');
  });
});

describe('particleColourForKind', () => {
  it('gives tunnels the accent and declared links the healthy green', () => {
    expect(particleColourForKind('tunnel')).toBe('var(--fwmon-accent)');
    expect(particleColourForKind('connection')).toBe('var(--fwmon-sig-ok)');
  });

  it('falls back to the link colour for an unknown kind', () => {
    expect(particleColourForKind('')).toBe('var(--fwmon-sig-ok)');
  });
});
