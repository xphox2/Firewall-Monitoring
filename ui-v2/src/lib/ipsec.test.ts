import { describe, expect, it } from 'vitest';
import {
  DPD_DEFAULT,
  MSS_CLAMP_DEFAULT,
  PSK_MASK,
  buildIntent,
  canonNet,
  changeCustomCrypto,
  childLifetimeFor,
  defaultIdentity,
  disabledPathsFrom,
  findingScope,
  identityError,
  pathKey,
  pruneDisabledPaths,
  profileCrypto,
  restoreCrypto,
  switchEndDevice,
  type CustomCrypto,
  type EndForm,
  type IntentForm,
  type Profile,
} from './ipsec';

const PROFILES: Profile[] = [
  {
    name: 'modern',
    label: 'Modern',
    ike_version: 'ikev2',
    ike: { enc: 'aes256gcm16', integ: '', prf: 'prfsha384', dh: '20' },
    esp: { enc: 'aes256gcm16', integ: '', pfs: '20' },
    ike_lifetime_secs: 86400,
    child_lifetime_secs: 3600,
  },
  {
    name: 'compatible',
    label: 'Compatible',
    ike_version: 'ikev2',
    ike: { enc: 'aes256cbc', integ: 'sha256', prf: 'prfsha256', dh: '14' },
    esp: { enc: 'aes256cbc', integ: 'sha256', pfs: '14' },
    ike_lifetime_secs: 86400,
    child_lifetime_secs: 3600,
  },
];

const END: EndForm = {
  deviceId: 1,
  vendor: 'fortigate',
  peerIp: '203.0.113.9',
  dynamic: false,
  egressIface: 'port1',
  lanIfaces: ['port3'],
  localId: { type: 'fqdn', value: 'fwm-abc' },
  protectedSubnets: ['192.168.113.0/24'],
  gateway: '',
};

function form(overrides: Partial<IntentForm> = {}): IntentForm {
  return {
    mode: 'route-based',
    profile: 'modern',
    custom: {
      ike_version: 'ikev2',
      ike: { enc: 'aes256cbc', integ: 'sha256', prf: 'prfsha256', dh: '14' },
      esp: { enc: 'aes256cbc', integ: 'sha256', pfs: '14' },
    },
    profiles: PROFILES,
    psk: '',
    ends: [END, { ...END, deviceId: 2, vendor: 'opnsense', peerIp: '198.51.100.7' }],
    disabledPaths: {},
    ...overrides,
  };
}

describe('canonNet', () => {
  it('masks the host bits', () => {
    expect(canonNet('192.168.113.7/24')).toBe('192.168.113.0/24');
    expect(canonNet('10.1.2.3/16')).toBe('10.1.0.0/16');
  });

  it('handles a /32 and a /0', () => {
    expect(canonNet('203.0.113.9/32')).toBe('203.0.113.9/32');
    expect(canonNet('203.0.113.9/0')).toBe('0.0.0.0/0');
  });

  it('rejects anything that is not a dotted quad with a prefix', () => {
    // The server compares these EXACTLY and a key it does not recognise is a
    // SILENT FAIL-OPEN, so a non-empty wrong key is worse than none.
    expect(canonNet('')).toBe('');
    expect(canonNet('192.168.113.0')).toBe('');
    expect(canonNet('2001:db8::/32')).toBe('');
    expect(canonNet('192.168.113.0/33')).toBe('');
    expect(canonNet('999.1.1.1/24')).toBe('');
  });

  it('rejects a leading zero, because the server rejects it too', () => {
    // Go's IPv4 parser rejects 192.168.001.001 outright. Normalising it here
    // would produce a key the server can never match - the silent fail-open.
    expect(canonNet('192.168.001.001/24')).toBe('');
    expect(canonNet('10.0.0.01/8')).toBe('');
    // A plain zero is fine.
    expect(canonNet('10.0.0.0/8')).toBe('10.0.0.0/8');
  });
});

describe('pathKey', () => {
  it('is canonical and ordered by END, not sorted', () => {
    // A is the FIRST end. The server does not sort, so the key is not
    // symmetric: swapping the ends gives a different key.
    expect(pathKey('192.168.113.7/24', '192.168.150.0/24')).toBe(
      '192.168.113.0/24|192.168.150.0/24',
    );
    expect(pathKey('192.168.150.0/24', '192.168.113.0/24')).toBe(
      '192.168.150.0/24|192.168.113.0/24',
    );
  });

  it('is empty when either side is not canonical', () => {
    expect(pathKey('bad', '192.168.150.0/24')).toBe('');
    expect(pathKey('192.168.113.0/24', 'bad')).toBe('');
  });
});

describe('disabledPathsFrom', () => {
  it('keeps only the disabled, canonical keys', () => {
    const out = disabledPathsFrom({
      '192.168.113.0/24|192.168.150.0/24': true,
      '10.0.0.0/8|10.1.0.0/16': false,
    });
    expect(out).toEqual(['192.168.113.0/24|192.168.150.0/24']);
  });

  it('drops a key that names no network', () => {
    expect(disabledPathsFrom({ nonsense: true })).toEqual([]);
  });

  it('CANONICALISES a key that arrives with host bits', () => {
    // This is the silent fail-open: the server compares the stored key
    // EXACTLY against its own canonical form, so a key carrying host bits
    // would never match and the path would stay ENABLED.
    expect(disabledPathsFrom({ '10.0.0.1/8|192.168.150.0/24': true })).toEqual([
      '10.0.0.0/8|192.168.150.0/24',
    ]);
  });

  it('drops a key whose subnet cannot be canonicalised', () => {
    // Nothing to send, so nothing that could fail open.
    expect(disabledPathsFrom({ '2001:db8::/32|192.168.150.0/24': true })).toEqual([]);
  });
});

describe('pruneDisabledPaths', () => {
  it('drops a key that names a subnet no longer listed', () => {
    const out = pruneDisabledPaths(
      {
        '192.168.113.0/24|192.168.150.0/24': true,
        '10.9.0.0/16|10.8.0.0/16': true,
      },
      [
        { protectedSubnets: ['192.168.113.0/24'] },
        { protectedSubnets: ['192.168.150.0/24'] },
      ],
    );
    expect(out).toEqual({ '192.168.113.0/24|192.168.150.0/24': true });
  });
});

describe('findingScope', () => {
  it('reads end 0 as end A', () => {
    // `end` is a POINTER on the server: 0 is the FIRST end, and a plain
    // `if (finding.end)` would drop it, because 0 is falsy.
    expect(findingScope({ severity: 'warn', code: 'x', message: 'm', end: 0 })).toBe('A');
    expect(findingScope({ severity: 'warn', code: 'x', message: 'm', end: 1 })).toBe('B');
  });

  it('reads an absent end as tunnel-wide', () => {
    expect(findingScope({ severity: 'warn', code: 'x', message: 'm' })).toBe('tunnel');
    expect(findingScope({ severity: 'warn', code: 'x', message: 'm', end: null })).toBe('tunnel');
  });
});

describe('restoreCrypto', () => {
  it('recognises a stored preset', () => {
    const modern = profileCrypto(PROFILES[0]);
    expect(restoreCrypto(modern, PROFILES)).toEqual({ profile: 'modern', custom: false });
  });

  it('reports the preset by its own name', () => {
    // The mapping must not assume there are only two presets: a third one
    // would be silently mislabelled "modern" on an edit, and the save would
    // write the wrong crypto.
    const third: Profile = {
      name: 'legacy',
      label: 'Legacy',
      ike_version: 'ikev1',
      ike: { enc: '3des', integ: 'sha1', prf: 'prfsha1', dh: '2' },
      esp: { enc: '3des', integ: 'sha1', pfs: '2' },
      ike_lifetime_secs: 28800,
      child_lifetime_secs: 3600,
    };
    expect(restoreCrypto(profileCrypto(third), [...PROFILES, third])).toEqual({
      profile: 'legacy',
      custom: false,
    });
  });

  it('falls back to Custom when the stored crypto matches no preset', () => {
    // Showing a preset that does not match what is stored would silently
    // rewrite the crypto on save.
    expect(
      restoreCrypto(
        { ike_version: 'ikev1', ike: { enc: 'x', integ: '', prf: '', dh: '' }, esp: { enc: 'x', integ: '', pfs: '' } },
        PROFILES,
      ),
    ).toEqual({ profile: 'custom', custom: true });
  });
});

describe('defaultIdentity', () => {
  it('uses the peer IP for an ip identity', () => {
    expect(defaultIdentity('ip', 'abc', '203.0.113.9')).toEqual({ type: 'ip', value: '203.0.113.9' });
  });

  it('uses the device UUID for a name identity', () => {
    expect(defaultIdentity('fqdn', 'abc', '203.0.113.9')).toEqual({ type: 'fqdn', value: 'fwm-abc' });
  });
});

describe('identityError', () => {
  it('requires a value — the server blocks an empty one', () => {
    expect(identityError({ type: 'fqdn', value: '' })).toBeTruthy();
  });

  it('requires a dotted quad for an ip identity', () => {
    expect(identityError({ type: 'ip', value: 'not-an-ip' })).toBeTruthy();
    expect(identityError({ type: 'ip', value: '203.0.113.9' })).toBeNull();
  });
});

describe('childLifetimeFor', () => {
  it('gives the non-initiator the longer child lifetime', () => {
    expect(childLifetimeFor(3600, true)).toBe(3600);
    expect(childLifetimeFor(3600, false)).toBe(7200);
  });
});

describe('buildIntent', () => {
  it('always sends enabled, dpd and mss_clamp', () => {
    // `enabled` omitted is FALSE, which would save the tunnel DISABLED, and
    // the other two raise spurious warnings.
    const intent = buildIntent(form());
    expect(intent.enabled).toBe(true);
    expect(intent.dpd).toEqual(DPD_DEFAULT);
    expect(intent.ends[0].mss_clamp).toBe(MSS_CLAMP_DEFAULT);
    expect(intent.ends[1].mss_clamp).toBe(MSS_CLAMP_DEFAULT);
  });

  it('takes the mode from the form, not a hardcoded default', () => {
    // OPNsense supports policy-based only, so a hardcoded "route-based"
    // would be wrong for every OPNsense pair.
    expect(buildIntent(form({ mode: 'policy-based' })).mode).toBe('policy-based');
  });

  it('uses the preset crypto for a preset', () => {
    const intent = buildIntent(form({ profile: 'compatible' }));
    expect(intent.ike_version).toBe('ikev2');
    expect(intent.ike.enc).toBe('aes256cbc');
    expect(intent.ike.integ).toBe('sha256');
  });

  it('uses the custom crypto for Custom', () => {
    const intent = buildIntent(form({ profile: 'custom' }));
    expect(intent.ike.enc).toBe('aes256cbc');
    expect(intent.ike.integ).toBe('sha256');
  });

  it('omits the PSK when it is blank, so the server generates one', () => {
    expect('psk' in buildIntent(form({ psk: '' }))).toBe(false);
  });

  it('sends the mask back unchanged on an edit', () => {
    expect(buildIntent(form({ psk: PSK_MASK })).psk).toBe(PSK_MASK);
  });

  it('never sends the derived fields', () => {
    const intent = buildIntent(form());
    expect('name' in intent).toBe(false);
    expect('vti_subnet' in intent).toBe(false);
    expect('reqid' in intent).toBe(false);
    expect((intent.ends[0] as unknown as Record<string, unknown>).inner_ip).toBeUndefined();
  });

  it('gives the two ends different child lifetimes', () => {
    const intent = buildIntent(form());
    expect(intent.ends[0].child_lifetime_secs).toBe(3600);
    expect(intent.ends[1].child_lifetime_secs).toBe(7200);
  });

  it('carries the disabled paths as canonical keys', () => {
    const intent = buildIntent(
      form({ disabledPaths: { '192.168.113.0/24|192.168.150.0/24': true } }),
    );
    expect(intent.disabled_paths).toEqual(['192.168.113.0/24|192.168.150.0/24']);
  });

  it('canonicalises a disabled path that carries host bits', () => {
    // The end-to-end version of the silent fail-open: the key the console
    // sends has to be the key the server computes, or the path stays
    // enabled.
    const intent = buildIntent(
      form({ disabledPaths: { '10.0.0.1/8|192.168.150.0/24': true } }),
    );
    expect(intent.disabled_paths).toEqual(['10.0.0.0/8|192.168.150.0/24']);
  });
});

const EMPTY_CUSTOM: CustomCrypto = {
  ike_version: 'ikev2',
  ike: { enc: '', integ: '', prf: '', dh: '' },
  esp: { enc: '', integ: '', pfs: '' },
};

describe('changeCustomCrypto', () => {
  // The wizard once filled in only the IKE half, so ESP and the PRF stayed
  // empty and the server blocked every Custom tunnel (encryption_unsupported).
  it('builds a complete proposal from the controls the form offers', () => {
    let c = EMPTY_CUSTOM;
    c = changeCustomCrypto(c, 'enc', 'aes256');
    c = changeCustomCrypto(c, 'integ', 'sha256');
    c = changeCustomCrypto(c, 'prf', 'prfsha256');
    c = changeCustomCrypto(c, 'dh', '14');
    c = changeCustomCrypto(c, 'pfs', true);
    expect(c.ike).toEqual({ enc: 'aes256', integ: 'sha256', prf: 'prfsha256', dh: '14' });
    expect(c.esp).toEqual({ enc: 'aes256', integ: 'sha256', pfs: '14' });
  });

  it('drops integrity for an AEAD cipher in both phases', () => {
    let c = changeCustomCrypto(EMPTY_CUSTOM, 'integ', 'sha256');
    c = changeCustomCrypto(c, 'enc', 'aes256gcm16');
    expect(c.ike.integ).toBe('');
    expect(c.esp.integ).toBe('');
    expect(c.esp.enc).toBe('aes256gcm16');
  });

  it('keeps PFS on the DH group as the group changes, and off when off', () => {
    let c = changeCustomCrypto(EMPTY_CUSTOM, 'dh', '19');
    c = changeCustomCrypto(c, 'pfs', true);
    c = changeCustomCrypto(c, 'dh', '20');
    expect(c.esp.pfs).toBe('20');
    c = changeCustomCrypto(c, 'pfs', false);
    c = changeCustomCrypto(c, 'dh', '21');
    expect(c.esp.pfs).toBe('');
  });

  it('leaves a stored ESP alone until the cipher is touched', () => {
    // An edited Custom tunnel whose ESP differs from its IKE keeps it.
    const stored: CustomCrypto = {
      ike_version: 'ikev2',
      ike: { enc: 'aes256', integ: 'sha256', prf: 'prfsha256', dh: '14' },
      esp: { enc: 'aes128', integ: 'sha1', pfs: '' },
    };
    const c = changeCustomCrypto(stored, 'prf', 'prfsha384');
    expect(c.esp).toEqual(stored.esp);
    expect(stored.ike.prf).toBe('prfsha256');
  });
});

describe('switchEndDevice', () => {
  it('clears the previous device\'s facts so the new device\'s hints refill them', () => {
    const next = switchEndDevice(END, 2);
    expect(next.deviceId).toBe(2);
    expect(next.peerIp).toBe('');
    expect(next.egressIface).toBe('');
    expect(next.lanIfaces).toEqual([]);
    expect(next.protectedSubnets).toEqual([]);
    // The identity's TYPE is the operator's choice and survives; its value
    // was derived from the old device's UUID and does not.
    expect(next.localId).toEqual({ type: 'fqdn', value: '' });
  });

  it('is a no-op when the same device is picked again', () => {
    expect(switchEndDevice(END, END.deviceId)).toBe(END);
  });
});
