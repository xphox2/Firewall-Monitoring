import { describe, expect, it } from 'vitest';
import {
  EVENT_MAX_PAGE_SIZE,
  EVENT_PAGE_SIZE,
  buildNetEventQuery,
  buildSecEventQuery,
  isIpOrCidr,
} from './event-filters';

describe('isIpOrCidr', () => {
  it('accepts a dotted quad and a CIDR', () => {
    expect(isIpOrCidr('192.168.1.1')).toBe(true);
    expect(isIpOrCidr('192.168.1.0/24')).toBe(true);
    expect(isIpOrCidr('2001:db8::1')).toBe(true);
    expect(isIpOrCidr('2001:db8::/32')).toBe(true);
  });

  it('rejects anything else', () => {
    // A malformed address is a 400, not a no-match, so it is never sent.
    expect(isIpOrCidr('')).toBe(false);
    expect(isIpOrCidr('not-an-ip')).toBe(false);
    expect(isIpOrCidr('192.168.1.256')).toBe(false);
    expect(isIpOrCidr('192.168.1.0/33')).toBe(false);
    expect(isIpOrCidr('192.168.001.001')).toBe(false);
  });

  it('rejects an address with a PORT', () => {
    // An operator types "10.0.0.1:443" out of habit. It is neither an
    // address nor a prefix, so the server would answer 400 and take the
    // whole stream down with it.
    //
    // (A bare IPv6 ending in a number IS a valid address — "2001:db8::1:443"
    // expands to eight groups — so only the IPv4 form can be rejected here.)
    expect(isIpOrCidr('10.0.0.1:443')).toBe(false);
    expect(isIpOrCidr('192.168.1.1:8080')).toBe(false);
  });

  it('rejects a malformed IPv6 address', () => {
    // A loose "contains a colon" test would let all of these through.
    expect(isIpOrCidr('foo:bar')).toBe(false);
    expect(isIpOrCidr('2001:db8:')).toBe(false);
    expect(isIpOrCidr(':db8::1')).toBe(false);
    expect(isIpOrCidr('2001:db8::1::2')).toBe(false);
    expect(isIpOrCidr('2001:db8::gggg')).toBe(false);
    expect(isIpOrCidr('1:2:3:4:5:6:7:8:9')).toBe(false);
  });

  it('accepts a well-formed IPv6 address', () => {
    expect(isIpOrCidr('2001:db8::1')).toBe(true);
    expect(isIpOrCidr('::1')).toBe(true);
    expect(isIpOrCidr('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(true);
    expect(isIpOrCidr('::ffff:192.0.2.1')).toBe(true);
    expect(isIpOrCidr('2001:db8::/32')).toBe(true);
  });

  it('rejects an IPv6 prefix that is too long', () => {
    expect(isIpOrCidr('2001:db8::/129')).toBe(false);
  });
});

describe('buildNetEventQuery', () => {
  it('sends every filter the server accepts', () => {
    const params = buildNetEventQuery(
      {
        deviceId: '7',
        probeId: '3',
        siteId: '2',
        activity: '5',
        action: '2',
        ruleKey: 'allow-web',
        srcIp: '192.168.1.10',
        dstIp: '203.0.113.0/24',
      },
      24,
      100,
      0,
    );
    expect(params.get('hours')).toBe('24');
    expect(params.get('limit')).toBe('100');
    expect(params.get('offset')).toBe('0');
    expect(params.get('device_id')).toBe('7');
    expect(params.get('probe_id')).toBe('3');
    expect(params.get('site_id')).toBe('2');
    expect(params.get('activity')).toBe('5');
    expect(params.get('action')).toBe('2');
    expect(params.get('rule_key')).toBe('allow-web');
    expect(params.get('src_ip')).toBe('192.168.1.10');
    expect(params.get('dst_ip')).toBe('203.0.113.0/24');
  });

  it('OMITS a filter that is not set', () => {
    const params = buildNetEventQuery({}, 24, 100, 0);
    for (const name of ['device_id', 'probe_id', 'site_id', 'activity', 'action', 'rule_key', 'src_ip', 'dst_ip']) {
      expect(params.has(name)).toBe(false);
    }
  });

  it('OMITS a numeric filter that does not parse', () => {
    // The server rejects a non-numeric numeric filter with a 400
    // (AUDIT-251), so a half-typed value must not be sent.
    const params = buildNetEventQuery(
      { deviceId: 'abc', probeId: '', siteId: '1.5', activity: 'x', action: '2' },
      24,
      100,
      0,
    );
    expect(params.has('device_id')).toBe(false);
    expect(params.has('probe_id')).toBe(false);
    expect(params.has('site_id')).toBe(false);
    expect(params.has('activity')).toBe(false);
    expect(params.get('action')).toBe('2');
  });

  it('OMITS an address that is not an address', () => {
    const params = buildNetEventQuery({ srcIp: 'nope', dstIp: '' }, 24, 100, 0);
    expect(params.has('src_ip')).toBe(false);
    expect(params.has('dst_ip')).toBe(false);
  });

  it('OMITS a destination with a port — the server would answer 400', () => {
    // An operator types "10.0.0.1:443". It is not an address, so the
    // server refuses the WHOLE request and the stream goes blank.
    const params = buildNetEventQuery({ dstIp: '10.0.0.1:443' }, 24, 100, 0);
    expect(params.has('dst_ip')).toBe(false);
  });

  it('OMITS a malformed IPv6 destination', () => {
    const params = buildNetEventQuery({ dstIp: '2001:db8::1::2' }, 24, 100, 0);
    expect(params.has('dst_ip')).toBe(false);
  });

  it('trims a text filter', () => {
    const params = buildNetEventQuery({ ruleKey: '  allow-web  ' }, 24, 100, 0);
    expect(params.get('rule_key')).toBe('allow-web');
  });
});

describe('buildSecEventQuery', () => {
  it('sends every filter the server accepts', () => {
    const params = buildSecEventQuery(
      {
        deviceId: '7',
        probeId: '3',
        class: '4',
        activity: '1',
        action: '2',
        severity: '9',
        adminUser: 'root',
        sigName: 'login-failed',
        tunnelName: 'fwm-t1',
        wanName: 'wan1',
      },
      24,
      50,
      100,
    );
    expect(params.get('hours')).toBe('24');
    expect(params.get('limit')).toBe('50');
    expect(params.get('offset')).toBe('100');
    expect(params.get('device_id')).toBe('7');
    expect(params.get('probe_id')).toBe('3');
    expect(params.get('class')).toBe('4');
    expect(params.get('activity')).toBe('1');
    expect(params.get('action')).toBe('2');
    expect(params.get('severity')).toBe('9');
    expect(params.get('admin_user')).toBe('root');
    expect(params.get('sig_name')).toBe('login-failed');
    expect(params.get('tunnel_name')).toBe('fwm-t1');
    expect(params.get('wan_name')).toBe('wan1');
  });

  it('does NOT send a site_id — the endpoint has no such parameter', () => {
    // The security events are filtered by device or probe, not by site.
    const params = buildSecEventQuery({ siteId: '2' }, 24, 50, 0);
    expect(params.has('site_id')).toBe(false);
  });

  it('OMITS a numeric filter that does not parse', () => {
    const params = buildSecEventQuery({ severity: 'high', class: 'x' }, 24, 50, 0);
    expect(params.has('severity')).toBe(false);
    expect(params.has('class')).toBe(false);
  });
});

describe('the page size', () => {
  it('is inside the server ceiling', () => {
    // `httputil.ParsePagination` clamps `limit` to 500.
    expect(EVENT_PAGE_SIZE).toBeLessThanOrEqual(EVENT_MAX_PAGE_SIZE);
    expect(EVENT_MAX_PAGE_SIZE).toBe(500);
  });
});
