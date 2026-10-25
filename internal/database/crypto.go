package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"firewall-mon/internal/models"
)

// Field-encryption wire formats. Both are AES-256-GCM with a random 12-byte
// nonce prepended to the ciphertext, base64 (std) encoded after the prefix.
// They differ only in how the AES key is derived from the configured secret
// (ENCRYPTION_KEY, or the JWT_SECRET_KEY fallback, or an
// ENCRYPTION_KEY_HISTORY entry):
//
//   - "{enc}"  (v1, legacy): key = sha256(secret). Every value written before
//     D-11 carries this prefix. It is DECRYPT-ONLY now — nothing new is ever
//     written in this format except the key-check canary (crypto_canary.go).
//   - "{enc2}" (v2): key = HKDF-SHA256(secret, salt=nil,
//     info="fwmon-field-encryption-v2"). Every new encryption uses it (D-11):
//     the domain-separated derivation means the AES key is never a plain hash
//     of the secret that (on the JWT fallback) also signs login tokens.
//
// Decrypt picks the derivation by prefix and tries it with EVERY key in the
// chain (current + ENCRYPTION_KEY_HISTORY), so pre-D-11 rows stay readable
// with zero operator action and key rotation keeps working for both formats.
// Old {enc} rows are deliberately NOT re-encrypted at startup: they migrate to
// {enc2} only when re-saved, so rolling back to an older binary loses nothing
// that was not re-saved since the upgrade.
//
// ROLLBACK HAZARD: a binary older than D-11 does not know "{enc2}". Its
// decryptField sees no "{enc}" prefix ("{enc2}" differs from "{enc}" at the
// 5th byte), treats the value as legacy plaintext and would hand the raw
// "{enc2}<base64>" string to SNMP/SSH/SMTP/IRC as the credential. After a
// rollback, every secret saved under the new binary must be re-entered.
//
// NOTE "{enc2}" does NOT start with "{enc}" — any "is this already
// encrypted?" check must use IsEncryptedValue, never a bare HasPrefix on one
// prefix.
const (
	encPrefix  = "{enc}"
	enc2Prefix = "{enc2}"

	// encV2Info is the HKDF info (context) label of the v2 derivation.
	// Changing it makes every {enc2} value unreadable — never edit it; add a
	// v3 prefix instead.
	encV2Info = "fwmon-field-encryption-v2"
)

// errNoEncryptionKey is returned when a secret would have to be stored but no
// encryption key is configured. D-12: we refuse rather than store plaintext.
var errNoEncryptionKey = errors.New("field encryption: no encryption key configured (ENCRYPTION_KEY / JWT_SECRET_KEY); refusing to store a secret in plaintext")

// randReader is the nonce source. A package variable only so tests can force
// the rand-failure path; production never reassigns it.
var randReader io.Reader = rand.Reader

// IsEncryptedValue reports whether s carries a field-encryption prefix of any
// version ("{enc}" or "{enc2}"). It is the one place that answers "is this
// value already ciphertext?" for double-encrypt guards, backfills and handler
// checks.
func IsEncryptedValue(s string) bool {
	return strings.HasPrefix(s, enc2Prefix) || strings.HasPrefix(s, encPrefix)
}

// deriveLegacyKey is the pre-D-11 (v1, "{enc}") derivation: sha256(secret).
// Decrypt-only (plus the canary); it must never change, or every {enc} row
// becomes unreadable.
func deriveLegacyKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// deriveKeyV2 is the D-11 (v2, "{enc2}") derivation: HKDF-SHA256 with a fixed
// info label. hkdf.Key only fails for an out-of-range length, which 32 is not;
// a nil return still fails closed (encrypt refuses, decrypt skips the key).
func deriveKeyV2(secret string) []byte {
	k, err := hkdf.Key(sha256.New, []byte(secret), nil, encV2Info, 32)
	if err != nil {
		log.Printf("ERROR: field encryption: HKDF key derivation failed: %v", err)
		return nil
	}
	return k
}

// fieldKey is the key material derived from ONE configured secret: the legacy
// v1 key (decrypts "{enc}") and the v2 key (encrypts, decrypts "{enc2}").
type fieldKey struct {
	v1 []byte
	v2 []byte
}

// deriveFieldKey derives both keys from secret. An empty secret yields the
// zero fieldKey (no key).
func deriveFieldKey(secret string) fieldKey {
	if secret == "" {
		return fieldKey{}
	}
	return fieldKey{v1: deriveLegacyKey(secret), v2: deriveKeyV2(secret)}
}

func (k fieldKey) empty() bool { return len(k.v1) == 0 && len(k.v2) == 0 }

// keyChain holds the current encryption key plus any number of legacy keys
// retained only for decryption of older ciphertext. Each entry carries both
// derivations (fieldKey), so {enc} and {enc2} values written under any
// chain key decrypt.
//
// AUDIT-009: pre-AUDIT the encryption layer held a single key. The first time
// an operator rotated the JWT secret (deliberately or accidentally) every
// {enc}<base64> value in the DB became unreadable forever. The chain lets an
// operator set `ENCRYPTION_KEY=newkey` AND `ENCRYPTION_KEY_HISTORY=oldkey1,oldkey2`
// — new writes use newkey; reads try newkey first and fall back through the
// history until one decrypts (or all fail and decryptField returns "" per
// the AUDIT-027 fail-closed contract).
//
// To complete a rotation: after enough time has passed that every encrypted
// row has been re-saved through the admin UI (or after running a one-shot
// re-encryption migration — `cmd/keyrotate` is a planned follow-up), the
// operator drops the old key from ENCRYPTION_KEY_HISTORY.
type keyChain struct {
	current fieldKey   // used for encrypt; tried FIRST on decrypt
	legacy  []fieldKey // tried IN ORDER after current on decrypt
}

// newKeyChain derives the chain from the raw configured secrets. Empty
// entries are skipped.
func newKeyChain(current string, history []string) keyChain {
	kc := keyChain{current: deriveFieldKey(current)}
	for _, h := range history {
		if h != "" {
			kc.legacy = append(kc.legacy, deriveFieldKey(h))
		}
	}
	return kc
}

// all returns every non-empty chain entry for decrypt attempts, current first.
func (k keyChain) all() []fieldKey {
	out := make([]fieldKey, 0, 1+len(k.legacy))
	if !k.current.empty() {
		out = append(out, k.current)
	}
	for _, lk := range k.legacy {
		if !lk.empty() {
			out = append(out, lk)
		}
	}
	return out
}

// hasAny reports whether the chain has at least one key. Used to distinguish
// "no key configured" from "all keys failed" in decryptFieldWithChain.
func (k keyChain) hasAny() bool {
	return len(k.all()) > 0
}

// seal AES-256-GCM-encrypts plaintext under key and returns prefix +
// base64(nonce||ciphertext). Every failure is an error — never a fallback to
// the plaintext (D-12).
func seal(plaintext string, key []byte, prefix string) (string, error) {
	if len(key) == 0 {
		return "", errNoEncryptionKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("field encryption: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("field encryption: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return "", fmt.Errorf("field encryption: nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// encryptField encrypts plaintext in the current format ("{enc2}", HKDF key).
// "" stays "" and an already-encrypted value ({enc} or {enc2}) is returned
// unchanged (no double encryption). D-12: a missing key or any cipher/rand
// failure is an error; the plaintext is never returned in place of
// ciphertext.
func encryptField(plaintext string, key fieldKey) (string, error) {
	if plaintext == "" || IsEncryptedValue(plaintext) {
		return plaintext, nil
	}
	return seal(plaintext, key.v2, enc2Prefix)
}

// encryptFieldLegacy writes the v1 "{enc}" format (sha256 key). Production
// uses it ONLY for the key-check canary, so a rollback to a pre-D-11 binary
// still verifies its key instead of crash-looping the poller/trap daemons on
// an {enc2} canary it cannot parse. Tests use it to build legacy rows.
func encryptFieldLegacy(plaintext string, key fieldKey) (string, error) {
	if plaintext == "" || IsEncryptedValue(plaintext) {
		return plaintext, nil
	}
	return seal(plaintext, key.v1, encPrefix)
}

// decryptField decrypts an encrypted string with a single key entry. Kept
// for tests; callers use decryptFieldWithChain.
func decryptField(ciphertext string, key fieldKey) string {
	return decryptFieldWithChain(ciphertext, keyChain{current: key})
}

// decryptFieldWithChain decrypts an "{enc}"- or "{enc2}"-prefixed string,
// trying each key in the chain (current first, then legacy keys in order)
// with the derivation the prefix names. Returns the plaintext on the first
// successful decrypt.
//
// Behavior:
//   - No encryption prefix → legacy plaintext, returned unchanged (idempotent
//     for callers that decrypt unconditionally).
//   - Has a prefix but decryption fails with ALL keys (no key in chain, bad
//     base64, AES setup error, GCM auth failure on every key, short
//     ciphertext) → returns "" and logs at error level.
//
// AUDIT-027: any decrypt failure must return "" rather than the ciphertext
// — see crypto.go header comment for the v0.10.226 bug class this closes.
//
// AUDIT-009: the chain support means rotating the encryption key no longer
// renders every encrypted row unreadable. See keyChain doc for the operator
// workflow.
func decryptFieldWithChain(ciphertext string, keys keyChain) string {
	var encoded string
	var pick func(fieldKey) []byte
	legacy := false
	switch {
	case strings.HasPrefix(ciphertext, enc2Prefix):
		encoded = ciphertext[len(enc2Prefix):]
		pick = func(k fieldKey) []byte { return k.v2 }
	case strings.HasPrefix(ciphertext, encPrefix):
		encoded = ciphertext[len(encPrefix):]
		pick = func(k fieldKey) []byte { return k.v1 }
		legacy = true
	default:
		return ciphertext
	}
	// From here on the field IS marked as encrypted — any failure must
	// resolve to "" so the broken ciphertext never reaches a caller.
	var candidates [][]byte
	for _, k := range keys.all() {
		if b := pick(k); len(b) > 0 {
			candidates = append(candidates, b)
		}
	}
	if len(candidates) == 0 {
		log.Printf("ERROR: decryptField: encrypted field present but no key available (JWT_SECRET_KEY / ENCRYPTION_KEY missing?) — returning empty")
		return ""
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("ERROR: decryptField: base64 decode failed (%v) — returning empty", err)
		return ""
	}

	var lastErr error
	for _, key := range candidates {
		block, err := aes.NewCipher(key)
		if err != nil {
			lastErr = err
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			lastErr = err
			continue
		}
		nonceSize := gcm.NonceSize()
		if len(data) < nonceSize {
			// Ciphertext is too short for ANY 32-byte AES-256-GCM key; no
			// point trying further keys.
			log.Printf("ERROR: decryptField: ciphertext shorter than nonce (got %d, want >= %d) — returning empty", len(data), nonceSize)
			return ""
		}
		nonce, encrypted := data[:nonceSize], data[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
		if err != nil {
			// Wrong key for THIS ciphertext; try the next one.
			lastErr = err
			continue
		}
		// Rollback round trip: a pre-D-11 binary sees an {enc2} value as
		// plaintext (no "{enc}" prefix) and its startup backfill wraps it as
		// {enc}({enc2}…). Unwrap that one level so re-upgrading recovers the
		// secret. Safe: EncryptField never encrypts a value that already
		// carries a prefix, so no genuine secret decrypts to "{enc2}…".
		if legacy && strings.HasPrefix(string(plaintext), enc2Prefix) {
			return decryptFieldWithChain(string(plaintext), keys)
		}
		return string(plaintext)
	}

	log.Printf("ERROR: decryptField: GCM auth failed with all %d key(s) in chain (current + %d legacy) — returning empty: %v", len(candidates), max0(len(candidates)-1), lastErr)
	return ""
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// EncryptField encrypts a single string value for database storage ("{enc2}"
// format). "" and already-encrypted values pass through unchanged.
//
// D-12: on a missing key or any cipher failure it returns an error and the
// caller must abort the write — a secret is never stored as plaintext. The
// only keyless passthrough is the SQLite test harness (NewDatabaseForTesting
// sets keylessPassthrough); a production Database always has a key (config
// requires JWT_SECRET_KEY).
func (d *Database) EncryptField(plaintext string) (string, error) {
	if plaintext == "" || IsEncryptedValue(plaintext) {
		return plaintext, nil
	}
	if len(d.encKeys.current.v2) == 0 && d.keylessPassthrough {
		return plaintext, nil
	}
	return encryptField(plaintext, d.encKeys.current)
}

// encryptInPlace encrypts every field or none: all ciphertexts are computed
// first and assigned only when every one succeeded, so a failure never leaves
// a struct half-encrypted.
func (d *Database) encryptInPlace(fields ...*string) error {
	out := make([]string, len(fields))
	for i, f := range fields {
		v, err := d.EncryptField(*f)
		if err != nil {
			return err
		}
		out[i] = v
	}
	for i, f := range fields {
		*f = out[i]
	}
	return nil
}

// EncryptDeviceSecrets encrypts SNMP/SSH/API credential fields on a device.
// On error the device is left unchanged and must not be written.
func (d *Database) EncryptDeviceSecrets(dev *models.Device) error {
	return d.encryptInPlace(&dev.SNMPCommunity, &dev.SNMPV3AuthPass, &dev.SNMPV3PrivPass, &dev.SSHPassword, &dev.APIToken)
}

// DecryptDeviceSecrets decrypts SNMP credential fields on a device.
func (d *Database) DecryptDeviceSecrets(dev *models.Device) {
	dev.SNMPCommunity = decryptFieldWithChain(dev.SNMPCommunity, d.encKeys)
	dev.SNMPV3AuthPass = decryptFieldWithChain(dev.SNMPV3AuthPass, d.encKeys)
	dev.SNMPV3PrivPass = decryptFieldWithChain(dev.SNMPV3PrivPass, d.encKeys)
	dev.SSHPassword = decryptFieldWithChain(dev.SSHPassword, d.encKeys)
	dev.APIToken = decryptFieldWithChain(dev.APIToken, d.encKeys)
}

// DecryptField decrypts a single string value from database storage.
func (d *Database) DecryptField(ciphertext string) string {
	return decryptFieldWithChain(ciphertext, d.encKeys)
}

// EncryptIRCServerSecrets encrypts IRC credential fields on a server. On
// error the server is left unchanged and must not be written.
func (d *Database) EncryptIRCServerSecrets(s *models.IRCServer) error {
	return d.encryptInPlace(&s.ServerPassword, &s.NickServPassword, &s.SASLPassword)
}

// DecryptIRCServerSecrets decrypts IRC credential fields on a server.
func (d *Database) DecryptIRCServerSecrets(s *models.IRCServer) {
	s.ServerPassword = decryptFieldWithChain(s.ServerPassword, d.encKeys)
	s.NickServPassword = decryptFieldWithChain(s.NickServPassword, d.encKeys)
	s.SASLPassword = decryptFieldWithChain(s.SASLPassword, d.encKeys)
}

// EncryptIRCChannelSecrets encrypts IRC channel credential fields. On error
// the channel is left unchanged and must not be written.
func (d *Database) EncryptIRCChannelSecrets(ch *models.IRCChannel) error {
	return d.encryptInPlace(&ch.ChanServPass, &ch.ChanOperPass, &ch.ChannelKey)
}

// DecryptIRCChannelSecrets decrypts IRC channel credential fields.
func (d *Database) DecryptIRCChannelSecrets(ch *models.IRCChannel) {
	ch.ChanServPass = decryptFieldWithChain(ch.ChanServPass, d.encKeys)
	ch.ChanOperPass = decryptFieldWithChain(ch.ChanOperPass, d.encKeys)
	ch.ChannelKey = decryptFieldWithChain(ch.ChannelKey, d.encKeys)
}

// SecretSettingKeys is the source of truth for which system_settings rows
// hold secret values that must be encrypted at rest and masked in API
// responses. It lives here (rather than in the API handlers, which alias it
// as settingsSecretKeys) so the startup plaintext-encryption backfill in
// migrateEncryptSecrets genuinely shares one list with the handlers' three
// consumers: masking on read, the masked-write skip, and encrypt-on-write.
// v0.10.226 introduced the list; the 2026-07-04 audit (LC-37/LC-38)
// centralized it after the handler-local copy let encrypt-on-write drift
// out of sync with it.
var SecretSettingKeys = map[string]bool{
	"smtp_password":         true,
	"webhook_secret":        true,
	"pagerduty_routing_key": true,
	"opsgenie_api_key":      true,
	// The raw archive's bucket secret (A-10). Written only by the
	// re-authenticated archive settings route, never by the settings page.
	ArchiveSecretSettingKey: true,
}

// backfillColumns encrypts the plaintext (non-empty, not yet encrypted)
// values among cols and returns the column→ciphertext updates to write. Any
// encryption failure skips the whole row (nil, logged): the backfill must
// never write a value it could not encrypt (D-12). The log names the row and
// column only — never the value.
func (d *Database) backfillColumns(row string, cols map[string]string) map[string]interface{} {
	updates := map[string]interface{}{}
	for col, v := range cols {
		if v == "" || IsEncryptedValue(v) {
			continue
		}
		ct, err := encryptField(v, d.encKeys.current)
		if err != nil {
			log.Printf("ERROR: encrypt-secrets backfill: skipping %s (column %s left as-is): %v", row, col, err)
			return nil
		}
		updates[col] = ct
	}
	return updates
}

// migrateEncryptSecrets encrypts any plaintext credentials in the database.
// Idempotent — already encrypted values ({enc} or {enc2}) are skipped; it
// never re-encrypts {enc} rows to {enc2} (rollback safety, see the header).
func (d *Database) migrateEncryptSecrets() {
	if len(d.encKeys.current.v2) == 0 {
		return
	}

	var devices []models.Device
	d.db.Find(&devices)
	for _, dev := range devices {
		if u := d.backfillColumns(fmt.Sprintf("device %d", dev.ID), map[string]string{
			"snmp_community":   dev.SNMPCommunity,
			"snmpv3_auth_pass": dev.SNMPV3AuthPass,
			"snmpv3_priv_pass": dev.SNMPV3PrivPass,
		}); len(u) > 0 {
			d.db.Model(&dev).Updates(u)
		}
	}

	// Encrypt IRC server credentials
	var servers []models.IRCServer
	d.db.Find(&servers)
	for _, srv := range servers {
		if u := d.backfillColumns(fmt.Sprintf("irc server %d", srv.ID), map[string]string{
			"server_password":   srv.ServerPassword,
			"nickserv_password": srv.NickServPassword,
			"sasl_password":     srv.SASLPassword,
		}); len(u) > 0 {
			d.db.Model(&srv).Updates(u)
		}
	}

	// Encrypt IRC channel credentials
	var channels []models.IRCChannel
	d.db.Find(&channels)
	for _, ch := range channels {
		if u := d.backfillColumns(fmt.Sprintf("irc channel %d", ch.ID), map[string]string{
			"chanserv_password": ch.ChanServPass,
			"chan_oper_pass":    ch.ChanOperPass,
			"channel_key":       ch.ChannelKey,
		}); len(u) > 0 {
			d.db.Model(&ch).Updates(u)
		}
	}

	// Encrypt secret system_settings rows. LC-38 (2026-07-04 audit): the
	// incident-channel secrets added in v0.11.x (webhook_secret,
	// pagerduty_routing_key, opsgenie_api_key) were persisted plaintext
	// because UpdateSettings only encrypted inside its smtp_password case.
	// The write path is fixed; this backfill upgrades rows that predate the
	// fix. Idempotent via the encrypted-prefix skip, like the loops above.
	keys := make([]string, 0, len(SecretSettingKeys))
	for k := range SecretSettingKeys {
		keys = append(keys, k)
	}
	var secretSettings []models.SystemSetting
	d.db.Where("key IN ?", keys).Find(&secretSettings)
	for _, s := range secretSettings {
		// Rows corrupted by the pre-fix mask writeback (LC-37) hold the
		// literal redaction mask (httputil.RedactedMask), not a real secret.
		// Encrypting the mask would only disguise the corruption — leave it
		// plaintext so the operator can spot it and re-enter the credential.
		if s.Value == "********" {
			continue
		}
		u := d.backfillColumns("setting "+s.Key, map[string]string{"value": s.Value})
		if len(u) == 0 {
			continue
		}
		u["is_secret"] = true
		d.db.Model(&models.SystemSetting{}).Where("key = ?", s.Key).Updates(u)
	}
}
