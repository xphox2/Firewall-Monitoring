import { describe, expect, it } from 'vitest';
import {
  EMPTY_FLOW_FILTERS,
  bucketToMs,
  buildFlowQuery,
  bytesToBpsPoints,
  exportFlowsCsv,
  isLikelyAddress,
  isValidDstPort,
} from './flows';

describe('buildFlowQuery', () => {
  it('always sends the window and only the filters that are set', () => {
    const q = new URLSearchParams(buildFlowQuery(EMPTY_FLOW_FILTERS, 24));
    expect(q.get('hours')).toBe('24');
    expect(q.has('device_id')).toBe(false);
    expect(q.has('protocol')).toBe(false);
    expect(q.has('limit')).toBe(false);
  });

  it('encodes every filter plus paging', () => {
    const q = new URLSearchParams(
      buildFlowQuery(
        {
          deviceId: '7',
          probeId: '3',
          siteId: '2',
          protocol: '6',
          src: ' 203.0.113.5 ',
          dst: '198.51.100.9',
          dstPort: '443',
          servicePort: '500',
          appCategory: '1',
          direction: '2',
          dstCountry: 'us',
          dstAsn: '64500',
          flowSource: '0',
          firewallEvent: '3',
        },
        168,
        { limit: 200, offset: 400 },
      ),
    );
    expect(q.get('hours')).toBe('168');
    expect(q.get('device_id')).toBe('7');
    expect(q.get('protocol')).toBe('6');
    expect(q.get('src_addr')).toBe('203.0.113.5');
    expect(q.get('dst_addr')).toBe('198.51.100.9');
    expect(q.get('dst_port')).toBe('443');
    expect(q.get('flow_source')).toBe('0');
    expect(q.get('firewall_event')).toBe('3');
    expect(q.get('probe_id')).toBe('3');
    expect(q.get('site_id')).toBe('2');
    expect(q.get('service_port')).toBe('500');
    expect(q.get('app_category')).toBe('1');
    expect(q.get('direction')).toBe('2');
    // The country is upper-cased: the server stores it upper-case.
    expect(q.get('dst_country')).toBe('US');
    expect(q.get('dst_asn')).toBe('64500');
    expect(q.get('limit')).toBe('200');
    expect(q.get('offset')).toBe('400');
  });

  it('drops filters the server would silently ignore', () => {
    const q = new URLSearchParams(
      buildFlowQuery(
        {
          ...EMPTY_FLOW_FILTERS,
          src: 'not an ip',
          dst: '198.51.100.9/33/extra',
          dstPort: '443x',
        },
        24,
      ),
    );
    expect(q.has('src_addr')).toBe(false);
    expect(q.has('dst_addr')).toBe(false);
    expect(q.has('dst_port')).toBe(false);
  });

  it('keeps valid CIDR and port filters', () => {
    const q = new URLSearchParams(
      buildFlowQuery({ ...EMPTY_FLOW_FILTERS, src: '2001:db8::/32', dstPort: '65535' }, 24),
    );
    expect(q.get('src_addr')).toBe('2001:db8::/32');
    expect(q.get('dst_port')).toBe('65535');
  });

  it('never emits a negative offset', () => {
    expect(
      new URLSearchParams(buildFlowQuery(EMPTY_FLOW_FILTERS, 1, { offset: -5 })).get('offset'),
    ).toBe('0');
  });
});

describe('filter validators', () => {
  it('accepts empty, IPv4/IPv6/CIDR but rejects junk', () => {
    expect(isLikelyAddress('')).toBe(true);
    expect(isLikelyAddress('203.0.113.5')).toBe(true);
    expect(isLikelyAddress('2001:db8::/48')).toBe(true);
    expect(isLikelyAddress('not an ip')).toBe(false);
    expect(isLikelyAddress('1.2.3.4/8/9')).toBe(false);
    expect(isLikelyAddress('1.2.3.4/33')).toBe(false);
    expect(isLikelyAddress('2001:db8::/129')).toBe(false);
    expect(isLikelyAddress('999.1.1.1')).toBe(false);
    expect(isLikelyAddress('AS64500')).toBe(false);
  });

  it('accepts ports 1..65535 only', () => {
    expect(isValidDstPort('')).toBe(true);
    expect(isValidDstPort('443')).toBe(true);
    expect(isValidDstPort('65535')).toBe(true);
    expect(isValidDstPort('0')).toBe(false);
    expect(isValidDstPort('65536')).toBe(false);
    expect(isValidDstPort('443x')).toBe(false);
  });
});

describe('bucketToMs', () => {
  it('parses the dialect bucket format as UTC', () => {
    expect(bucketToMs('2026-10-20 14:00')).toBe(Date.parse('2026-10-20T14:00:00Z'));
    expect(bucketToMs('2026-10-20 14:00:00')).toBe(Date.parse('2026-10-20T14:00:00Z'));
  });

  it('parses date-only day buckets as UTC midnight', () => {
    expect(bucketToMs('2026-10-20')).toBe(Date.parse('2026-10-20T00:00:00Z'));
  });

  it('leaves an explicit timezone alone', () => {
    expect(bucketToMs('2026-10-20T14:00:00Z')).toBe(Date.parse('2026-10-20T14:00:00Z'));
    expect(bucketToMs('2026-10-20T14:00:00+02:00')).toBe(
      Date.parse('2026-10-20T14:00:00+02:00'),
    );
  });

  it('returns null for junk', () => {
    expect(bucketToMs('')).toBeNull();
    expect(bucketToMs('not-a-time')).toBeNull();
  });
});

describe('bytesToBpsPoints', () => {
  it('converts bytes per bucket to bits per second', () => {
    const { timestamps, values } = bytesToBpsPoints(
      [
        { bucket: '2026-10-20 14:00', count: 1_000_000 },
        { bucket: '2026-10-20 14:05', count: 2_000_000 },
      ],
      300,
    );
    expect(timestamps).toHaveLength(2);
    expect(values[0]).toBeCloseTo((1_000_000 * 8) / 300);
    expect(values[1]).toBeCloseTo((2_000_000 * 8) / 300);
  });

  it('sorts points and skips unparseable buckets', () => {
    const { timestamps } = bytesToBpsPoints(
      [
        { bucket: '2026-10-20 14:05', count: 5 },
        { bucket: 'nonsense', count: 5 },
        { bucket: '2026-10-20 14:00', count: 5 },
      ],
      60,
    );
    expect(timestamps).toEqual([
      Date.parse('2026-10-20T14:00:00Z'),
      Date.parse('2026-10-20T14:05:00Z'),
    ]);
  });

  it('yields zero bps when the bucket width is unknown', () => {
    const { values } = bytesToBpsPoints([{ bucket: '2026-10-20 14:00', count: 999 }], 0);
    expect(values).toEqual([0]);
  });
});

describe('exportFlowsCsv', () => {
  it('writes a header and quotes separators, quotes and newlines', () => {
    const csv = exportFlowsCsv([
      {
        timestamp: '2026-10-20T14:00:00Z',
        src_addr: '203.0.113.5',
        dst_addr: '198.51.100.9',
        dst_port: 443,
      },
      { src_addr: 'a,b', dst_addr: 'say "hi"', app_category: 'line1\nline2' },
    ]);
    const lines = csv.split('\r\n');
    expect(lines[0]).toContain('src_addr,src_port,dst_addr,dst_port');
    expect(lines[1]).toContain('203.0.113.5');
    expect(lines[2]).toContain('"a,b"');
    expect(lines[2]).toContain('"say ""hi"""');
    expect(csv).toContain('"line1\nline2"');
  });

  it('neutralises spreadsheet formula injection', () => {
    const csv = exportFlowsCsv([
      { src_addr: '=HYPERLINK("http://x")', dst_addr: '+1', app_category: '\t@SUM(A1)' },
    ]);
    expect(csv).toContain("'=HYPERLINK");
    expect(csv).toContain("'+1");
    expect(csv).toContain("'\t@SUM(A1)");
  });
});


describe('buildFlowQuery — the new filters', () => {
  it('OMITS a service port that is not a port', () => {
    const base = { ...EMPTY_FLOW_FILTERS };
    expect(new URLSearchParams(buildFlowQuery({ ...base, servicePort: '0' }, 24)).has('service_port')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, servicePort: '65536' }, 24)).has('service_port')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, servicePort: '443' }, 24)).get('service_port')).toBe('443');
  });

  it('OMITS a direction that is not the server\'s numeric id', () => {
    const base = { ...EMPTY_FLOW_FILTERS };
    expect(new URLSearchParams(buildFlowQuery({ ...base, direction: 'outbound' }, 24)).has('direction')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, direction: '2' }, 24)).get('direction')).toBe('2');
  });

  it('OMITS a country that is not an ISO alpha-2 code', () => {
    const base = { ...EMPTY_FLOW_FILTERS };
    expect(new URLSearchParams(buildFlowQuery({ ...base, dstCountry: 'USA' }, 24)).has('dst_country')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, dstCountry: 'us' }, 24)).get('dst_country')).toBe('US');
  });

  it('OMITS an ASN that is not a number', () => {
    const base = { ...EMPTY_FLOW_FILTERS };
    expect(new URLSearchParams(buildFlowQuery({ ...base, dstAsn: 'AS64500' }, 24)).has('dst_asn')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, dstAsn: '64500' }, 24)).get('dst_asn')).toBe('64500');
  });
});


describe('buildFlowQuery — the app category is a numeric id', () => {
  it('OMITS a category NAME — the server parses it with ParseUint', () => {
    // The handler does `strconv.ParseUint(cat, 10, 8)`, so "web" is
    // silently dropped and the filter never applies. A control that accepts
    // a name is a control that does nothing.
    const base = { ...EMPTY_FLOW_FILTERS };
    const q = new URLSearchParams(buildFlowQuery({ ...base, appCategory: 'web' }, 24));
    expect(q.has('app_category')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, appCategory: '1' }, 24)).get('app_category')).toBe('1');
  });

  it('OMITS a direction that is not one of the five ids', () => {
    // The ids are 0..4 (classify.Direction). 5 is not a direction.
    const base = { ...EMPTY_FLOW_FILTERS };
    expect(new URLSearchParams(buildFlowQuery({ ...base, direction: '5' }, 24)).has('direction')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, direction: '4' }, 24)).get('direction')).toBe('4');
  });

  it('OMITS an ASN above the uint32 ceiling', () => {
    const base = { ...EMPTY_FLOW_FILTERS };
    expect(new URLSearchParams(buildFlowQuery({ ...base, dstAsn: '4294967296' }, 24)).has('dst_asn')).toBe(false);
    expect(new URLSearchParams(buildFlowQuery({ ...base, dstAsn: '4294967295' }, 24)).get('dst_asn')).toBe('4294967295');
  });
});
