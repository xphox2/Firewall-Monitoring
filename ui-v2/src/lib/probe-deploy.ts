/**
 * The collector's deploy information.
 *
 * The legacy console had a "Deploy Info" modal that showed the environment
 * block an operator pastes into the collector's environment. The block is
 * COMPOSED ON THE CLIENT — the server has no "deploy env" endpoint — so it
 * is built here, where it can be tested.
 */

/** The server's redaction mask for a stored secret. */
export const SECRET_MASK = '********';

/**
 * Whether a registration key is a REAL key.
 *
 * After the create-time show-once reveal, every later GET returns the mask
 * for a probe that has a key. The mask is truthy, so without this the
 * deploy modal would render `'********'` as if it were a copyable key.
 */
export function isRealRegistrationKey(key: string | undefined | null): boolean {
  return Boolean(key) && key !== SECRET_MASK;
}

export interface ProbeDeployInfo {
  name?: string;
  site_id?: number | null;
  registration_key?: string;
}

/**
 * The environment block for the collector.
 *
 * The four variables the collector reads, one per line, in the legacy
 * console's order.
 */
export function buildProbeEnv(probe: ProbeDeployInfo, serverUrl: string): string {
  const key = isRealRegistrationKey(probe.registration_key)
    ? (probe.registration_key as string)
    : 'MISSING';
  return [
    `PROBE_NAME=${probe.name ?? ''}`,
    `PROBE_SITE_ID=${probe.site_id || 0}`,
    `PROBE_REGISTRATION_KEY=${key}`,
    `PROBE_SERVER_URL=${serverUrl}`,
  ].join('\n');
}

/**
 * The line shown in place of the key when it is not available.
 *
 * The key is shown ONCE, at creation. Every later read returns the mask,
 * so the operator has to be told that — and that an admin can issue a new
 * one.
 */
export const KEY_UNAVAILABLE_NOTICE =
  '(key shown once at creation — an admin can issue a new one with Regenerate Key)';
