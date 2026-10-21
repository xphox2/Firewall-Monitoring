/**
 * WebAuthn JSON ↔ ArrayBuffer conversion. The server speaks base64url (Go's
 * protocol types); `navigator.credentials.create` speaks ArrayBuffers.
 */

export function b64urlToBuf(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function bufToB64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** True when the browser exposes the WebAuthn credential API. */
export function passkeysSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.create === 'function'
  );
}

export interface CreationOptionsEnvelope {
  publicKey?: Record<string, any>;
}

/**
 * Decodes the server's CredentialCreation JSON into the shape
 * `navigator.credentials.create` expects.
 */
export function decodeCreationOptions(envelope: Record<string, any>): PublicKeyCredentialCreationOptions {
  const pk = (envelope.publicKey ?? envelope) as Record<string, any>;
  const exclude = Array.isArray(pk.excludeCredentials)
    ? pk.excludeCredentials.map((c: Record<string, any>) => ({
        ...c,
        id: b64urlToBuf(String(c.id)),
      }))
    : pk.excludeCredentials;
  return {
    ...pk,
    challenge: b64urlToBuf(String(pk.challenge)),
    user: {
      ...pk.user,
      id: b64urlToBuf(String(pk.user?.id)),
    },
    ...(exclude ? { excludeCredentials: exclude } : {}),
  } as unknown as PublicKeyCredentialCreationOptions;
}

export interface RegistrationCredentialJSON {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
  };
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

/** Encodes the browser's credential for POST /passkeys/register/finish. */
export function encodeRegistrationCredential(
  credential: PublicKeyCredential,
): RegistrationCredentialJSON {
  const response = credential.response as AuthenticatorAttestationResponse & {
    getTransports?: () => string[];
  };
  return {
    id: bufToB64url(credential.rawId),
    rawId: bufToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufToB64url(response.clientDataJSON),
      attestationObject: bufToB64url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}
