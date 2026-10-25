package snmp

// D-18: the trap receiver used to hand every datagram to gosnmp's full BER
// decoder (all varbinds, OIDs, values) and only then rate-limit and compare
// the community, so an unauthenticated flood paid the whole decode cost per
// packet. The receiver now reads the socket itself and runs this cheap header
// check first: SNMPv1/v2c messages carry the community as the second field of
// the outer SEQUENCE, so it can be compared without decoding the PDU.

// berTLV splits one BER TLV off the front of b. It accepts only definite
// lengths whose value fits in b (short form, or long form of at most 4
// length octets), which is all a well-formed SNMP header uses.
func berTLV(b []byte) (tag byte, value, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, false
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		i += n
	}
	if l < 0 || l > len(b)-i {
		return 0, nil, nil, false
	}
	return tag, b[i : i+l], b[i+l:], true
}

// trapCommunity returns the community of an SNMPv1/v2c message by walking
// only the header: SEQUENCE { INTEGER version, OCTET STRING community, ... }.
// It reports false for anything else — malformed headers and SNMPv3, which
// has no community and which this receiver does not accept.
func trapCommunity(msg []byte) ([]byte, bool) {
	tag, seq, _, ok := berTLV(msg)
	if !ok || tag != 0x30 {
		return nil, false
	}
	tag, ver, seq, ok := berTLV(seq)
	if !ok || tag != 0x02 || len(ver) != 1 || (ver[0] != 0 && ver[0] != 1) {
		return nil, false
	}
	tag, community, _, ok := berTLV(seq)
	if !ok || tag != 0x04 {
		return nil, false
	}
	return community, true
}

// D-18 global cap on authenticated datagrams reaching the full decoder, the
// alert pipeline and the DB. The per-source limiter alone admits up to
// maxRateLimitedIPs × defaultTrapRatePerSec (100k/s) from many sources; this
// bounds the total. 500/s with a 1000 burst is far above any real fleet's
// trap rate (a whole-site link-flap storm is tens per second).
const (
	defaultTrapGlobalRatePerSec = 500.0
	defaultTrapGlobalBurst      = 1000.0
)
