/**
 * <input type="datetime-local"> speaks LOCAL wall-clock time, while the API
 * stores UTC. Slicing toISOString() handed the control a UTC value that the
 * browser then labelled as local, and the save round-trip shifted it again.
 */
export function toLocalInput(value?: string): string {
  const d = value ? new Date(value) : new Date();
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(
    d.getMinutes(),
  )}`;
}

export function fromLocalInput(value?: string): string {
  if (!value) return '';
  const d = new Date(value); // no timezone suffix => parsed as local
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}
