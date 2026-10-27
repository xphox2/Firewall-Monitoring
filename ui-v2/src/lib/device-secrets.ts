/**
 * The device's credentials.
 *
 * A credential is stored encrypted and read back MASKED, so the console
 * cannot tell "unchanged" from "empty" by looking at the value: a device
 * that holds one shows the mask, and a device that does not shows an empty
 * string.
 *
 * That distinction matters twice:
 *
 *  - the mask-or-empty rule on the server means an empty value means
 *    "leave unchanged", so a client that loads a device and saves it back
 *    cannot destroy the credential by resending the mask;
 *  - and the console has to know whether there is anything to CLEAR, which
 *    is the one operation the mask-or-empty rule makes impossible.
 */

/** The server's redaction mask for a stored secret. */
export const SECRET_MASK = '********';

/**
 * Whether the device HOLDS a credential for the field.
 *
 * The server masks every credential it holds and leaves an empty string for
 * a field it does not, so a non-empty value means there is one.
 *
 * The obvious mistake here is to treat the mask as "empty" — which is
 * exactly what a value comparison would do — and then the control that
 * clears a credential never appears for the case it exists for: a
 * credential the device ALREADY holds.
 */
export function hasStoredCredential(stored: unknown): boolean {
  return typeof stored === 'string' && stored !== '';
}

/**
 * Whether the value is the mask — so the stored credential is there but
 * its value is not known.
 */
export function isMaskedSecret(stored: unknown, revealed: boolean): boolean {
  return !revealed && stored === SECRET_MASK;
}
