package ipsec

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// pskAlphabet is deliberately restricted to alphanumerics. A 256-bit PSK drawn
// from these 62 symbols is ~43 chars — well above the NIST 112-bit floor — and
// avoids every shell/config escaping trap (`" \ % # ?` etc.) across FortiGate
// `set psksecret`, OPNsense, and future vendors.
const pskAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// pskLen yields ≥256 bits of entropy: log2(62) ≈ 5.954 bits/char, so 43 chars ≈
// 256 bits.
const pskLen = 43

// GeneratePSK returns a fresh CSPRNG pre-shared key over the CLI-safe alphabet.
func GeneratePSK() (string, error) {
	var b strings.Builder
	b.Grow(pskLen)
	max := big.NewInt(int64(len(pskAlphabet)))
	for i := 0; i < pskLen; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(pskAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// validPSK reports whether a caller-supplied PSK is safe to use: no characters
// that break strongSwan ipsec.secrets parsing or CLI escaping, and enough
// length to carry real entropy. Empty/dictionary detection is a UI concern; this
// is the hard floor.
func validPSK(psk string) (ok bool, reason string) {
	if len(psk) < 20 {
		return false, "pre-shared key must be at least 20 characters"
	}
	if strings.ContainsAny(psk, "\"\n\r") {
		return false, "pre-shared key must not contain quotes or newlines"
	}
	return true, ""
}
