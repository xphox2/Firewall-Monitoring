import { describe, expect, it } from 'vitest';
import {
  b64urlToBuf,
  bufToB64url,
  decodeCreationOptions,
  encodeRegistrationCredential,
  passkeysSupported,
} from './webauthn';

describe('base64url', () => {
  it('round-trips bytes that need + and / in standard base64', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 0x00, 0x3e, 0x3f]);
    expect(bufToB64url(bytes.buffer)).toBe('-__-AD4_');
    expect(new Uint8Array(b64urlToBuf('-__-AD4_'))).toEqual(bytes);
  });

  it('accepts padded and unpadded input', () => {
    expect(new Uint8Array(b64urlToBuf('AQID'))).toEqual(new Uint8Array([1, 2, 3]));
    expect(new Uint8Array(b64urlToBuf('AQIDBA=='))).toEqual(new Uint8Array([1, 2, 3, 4]));
  });
});

describe('decodeCreationOptions', () => {
  it('decodes challenge, user.id and exclusion ids but keeps the rest', () => {
    const options = decodeCreationOptions({
      publicKey: {
        challenge: 'AQID',
        rp: { id: 'example.test', name: 'Firewall-Mon' },
        user: { id: 'BAUG', name: 'admin', displayName: 'admin' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        excludeCredentials: [{ type: 'public-key', id: 'BwgJ', transports: ['usb'] }],
        timeout: 60000,
        authenticatorSelection: { userVerification: 'required' },
      },
    });
    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(new Uint8Array(options.user.id as ArrayBuffer)).toEqual(new Uint8Array([4, 5, 6]));
    expect(new Uint8Array(options.excludeCredentials?.[0]?.id as ArrayBuffer)).toEqual(
      new Uint8Array([7, 8, 9]),
    );
    expect(options.rp.name).toBe('Firewall-Mon');
    expect(options.pubKeyCredParams[0]?.alg).toBe(-7);
  });
});

describe('encodeRegistrationCredential', () => {
  it('base64url-encodes the raw id and both response buffers', () => {
    const credential = {
      rawId: new Uint8Array([1, 2, 3]).buffer,
      type: 'public-key',
      response: {
        clientDataJSON: new Uint8Array([4, 5]).buffer,
        attestationObject: new Uint8Array([6, 7, 8]).buffer,
        getTransports: () => ['internal', 'hybrid'],
      },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    } as unknown as PublicKeyCredential;

    expect(encodeRegistrationCredential(credential)).toEqual({
      id: 'AQID',
      rawId: 'AQID',
      type: 'public-key',
      response: {
        clientDataJSON: 'BAU',
        attestationObject: 'BgcI',
        transports: ['internal', 'hybrid'],
      },
      clientExtensionResults: { credProps: { rk: true } },
    });
  });
});

describe('passkeysSupported', () => {
  it('is false without a browser credential API', () => {
    expect(passkeysSupported()).toBe(false);
  });
});
