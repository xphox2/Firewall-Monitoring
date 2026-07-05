package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log"
	"strings"

	"firewall-mon/internal/models"
)

const encPrefix = "{enc}"

// deriveKey creates a 32-byte AES-256 key from the JWT secret.
func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// keyChain holds the current encryption key plus any number of legacy keys
// retained only for decryption of older ciphertext.
//
// AUDIT-009: pre-AUDIT the encryption layer held a single key. The first time
// an operator rotated the JWT secret (deliberately or accidentally) every
// {enc}<base64> value in the DB became unreadable forever. The chain lets an
// operator set `ENCRYPTION_KEY=newkey` AND `ENCRYPTION_KEY_HISTORY=oldkey1,oldkey2`
// — new writes use newkey; reads try newkey first and fall back through the
// history until one decrypts (or all fail and decryptField returns "" per
// the AUDIT-027 fail-closed contract).
//
// To complete a rotation: after enough time has passed that every {enc} row
// has been re-saved through the admin UI (or after running a one-shot
// re-encryption migration — `cmd/keyrotate` is a planned follow-up), the
// operator drops the old key from ENCRYPTION_KEY_HISTORY.
type keyChain struct {
	current []byte   // used for encrypt; tried FIRST on decrypt
	legacy  [][]byte // tried IN ORDER after current on decrypt
}

// all returns every candidate key for decrypt attempts, current first.
func (k keyChain) all() [][]byte {
	out := make([][]byte, 0, 1+len(k.legacy))
	if len(k.current) > 0 {
		out = append(out, k.current)
	}
	for _, lk := range k.legacy {
		if len(lk) > 0 {
			out = append(out, lk)
		}
	}
	return out
}

// hasAny reports whether the chain has at least one key. Used to distinguish
// "no key configured" from "all keys failed" in decryptFieldWithChain.
func (k keyChain) hasAny() bool {
	if len(k.current) > 0 {
		return true
	}
	for _, lk := range k.legacy {
		if len(lk) > 0 {
			return true
		}
	}
	return false
}

// encryptField encrypts a plaintext string using AES-256-GCM.
// Returns "{enc}" + base64-encoded ciphertext. Returns plaintext unchanged
// if empty or if key is not available.
func encryptField(plaintext string, key []byte) string {
	if plaintext == "" || len(key) == 0 {
		return plaintext
	}
	// Already encrypted — don't double-encrypt
	if strings.HasPrefix(plaintext, encPrefix) {
		return plaintext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return plaintext
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return plaintext
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plaintext
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ciphertext)
}

// decryptField decrypts a "{enc}"-prefixed string with a single key. Kept
// for backward compatibility with tests; new callers should use
// decryptFieldWithChain.
func decryptField(ciphertext string, key []byte) string {
	return decryptFieldWithChain(ciphertext, keyChain{current: key})
}

// decryptFieldWithChain decrypts a "{enc}"-prefixed string trying each key
// in the chain (current first, then legacy keys in order). Returns the
// plaintext on first successful decrypt.
//
// Behavior:
//   - No "{enc}" prefix → legacy plaintext, returned unchanged (idempotent
//     for callers that decrypt unconditionally).
//   - Has "{enc}" prefix but decryption fails with ALL keys (no key in
//     chain, bad base64, AES setup error, GCM auth failure on every key,
//     short ciphertext) → returns "" and logs at error level.
//
// AUDIT-027: any decrypt failure must return "" rather than the ciphertext
// — see crypto.go header comment for the v0.10.226 bug class this closes.
//
// AUDIT-009: the chain support means rotating the encryption key no longer
// renders every {enc} row unreadable. See keyChain doc for the operator
// workflow.
func decryptFieldWithChain(ciphertext string, keys keyChain) string {
	if !strings.HasPrefix(ciphertext, encPrefix) {
		return ciphertext
	}
	// From here on the field IS marked as encrypted — any failure must
	// resolve to "" so the broken ciphertext never reaches a caller.
	if !keys.hasAny() {
		log.Printf("ERROR: decryptField: encrypted field present but no key available (JWT_SECRET_KEY / ENCRYPTION_KEY missing?) — returning empty")
		return ""
	}

	encoded := ciphertext[len(encPrefix):]
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("ERROR: decryptField: base64 decode failed (%v) — returning empty", err)
		return ""
	}

	candidates := keys.all()
	var lastErr error
	for i, key := range candidates {
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
			_ = i // i kept for future log-on-success-via-legacy-key wiring
			continue
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

// EncryptField encrypts a single string value for database storage.
func (d *Database) EncryptField(plaintext string) string {
	return encryptField(plaintext, d.encKeys.current)
}

// EncryptDeviceSecrets encrypts SNMP credential fields on a device.
func (d *Database) EncryptDeviceSecrets(dev *models.Device) {
	dev.SNMPCommunity = encryptField(dev.SNMPCommunity, d.encKeys.current)
	dev.SNMPV3AuthPass = encryptField(dev.SNMPV3AuthPass, d.encKeys.current)
	dev.SNMPV3PrivPass = encryptField(dev.SNMPV3PrivPass, d.encKeys.current)
	dev.SSHPassword = encryptField(dev.SSHPassword, d.encKeys.current)
}

// DecryptDeviceSecrets decrypts SNMP credential fields on a device.
func (d *Database) DecryptDeviceSecrets(dev *models.Device) {
	dev.SNMPCommunity = decryptFieldWithChain(dev.SNMPCommunity, d.encKeys)
	dev.SNMPV3AuthPass = decryptFieldWithChain(dev.SNMPV3AuthPass, d.encKeys)
	dev.SNMPV3PrivPass = decryptFieldWithChain(dev.SNMPV3PrivPass, d.encKeys)
	dev.SSHPassword = decryptFieldWithChain(dev.SSHPassword, d.encKeys)
}

// DecryptField decrypts a single string value from database storage.
func (d *Database) DecryptField(ciphertext string) string {
	return decryptFieldWithChain(ciphertext, d.encKeys)
}

// EncryptIRCServerSecrets encrypts IRC credential fields on a server.
func (d *Database) EncryptIRCServerSecrets(s *models.IRCServer) {
	s.ServerPassword = encryptField(s.ServerPassword, d.encKeys.current)
	s.NickServPassword = encryptField(s.NickServPassword, d.encKeys.current)
	s.SASLPassword = encryptField(s.SASLPassword, d.encKeys.current)
}

// DecryptIRCServerSecrets decrypts IRC credential fields on a server.
func (d *Database) DecryptIRCServerSecrets(s *models.IRCServer) {
	s.ServerPassword = decryptFieldWithChain(s.ServerPassword, d.encKeys)
	s.NickServPassword = decryptFieldWithChain(s.NickServPassword, d.encKeys)
	s.SASLPassword = decryptFieldWithChain(s.SASLPassword, d.encKeys)
}

// EncryptIRCChannelSecrets encrypts IRC channel credential fields.
func (d *Database) EncryptIRCChannelSecrets(ch *models.IRCChannel) {
	ch.ChanServPass = encryptField(ch.ChanServPass, d.encKeys.current)
	ch.ChanOperPass = encryptField(ch.ChanOperPass, d.encKeys.current)
	ch.ChannelKey = encryptField(ch.ChannelKey, d.encKeys.current)
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
}

// migrateEncryptSecrets encrypts any plaintext SNMP credentials in the database.
// This is idempotent — already encrypted values (with {enc} prefix) are skipped.
func (d *Database) migrateEncryptSecrets() {
	if len(d.encKeys.current) == 0 {
		return
	}

	var devices []models.Device
	d.db.Find(&devices)

	for _, dev := range devices {
		changed := false
		if dev.SNMPCommunity != "" && !strings.HasPrefix(dev.SNMPCommunity, encPrefix) {
			dev.SNMPCommunity = encryptField(dev.SNMPCommunity, d.encKeys.current)
			changed = true
		}
		if dev.SNMPV3AuthPass != "" && !strings.HasPrefix(dev.SNMPV3AuthPass, encPrefix) {
			dev.SNMPV3AuthPass = encryptField(dev.SNMPV3AuthPass, d.encKeys.current)
			changed = true
		}
		if dev.SNMPV3PrivPass != "" && !strings.HasPrefix(dev.SNMPV3PrivPass, encPrefix) {
			dev.SNMPV3PrivPass = encryptField(dev.SNMPV3PrivPass, d.encKeys.current)
			changed = true
		}
		if changed {
			d.db.Model(&dev).Updates(map[string]interface{}{
				"snmp_community":   dev.SNMPCommunity,
				"snmpv3_auth_pass": dev.SNMPV3AuthPass,
				"snmpv3_priv_pass": dev.SNMPV3PrivPass,
			})
		}
	}

	// Encrypt IRC server credentials
	var servers []models.IRCServer
	d.db.Find(&servers)
	for _, srv := range servers {
		changed := false
		if srv.ServerPassword != "" && !strings.HasPrefix(srv.ServerPassword, encPrefix) {
			srv.ServerPassword = encryptField(srv.ServerPassword, d.encKeys.current)
			changed = true
		}
		if srv.NickServPassword != "" && !strings.HasPrefix(srv.NickServPassword, encPrefix) {
			srv.NickServPassword = encryptField(srv.NickServPassword, d.encKeys.current)
			changed = true
		}
		if srv.SASLPassword != "" && !strings.HasPrefix(srv.SASLPassword, encPrefix) {
			srv.SASLPassword = encryptField(srv.SASLPassword, d.encKeys.current)
			changed = true
		}
		if changed {
			d.db.Model(&srv).Updates(map[string]interface{}{
				"server_password":   srv.ServerPassword,
				"nickserv_password": srv.NickServPassword,
				"sasl_password":     srv.SASLPassword,
			})
		}
	}

	// Encrypt IRC channel credentials
	var channels []models.IRCChannel
	d.db.Find(&channels)
	for _, ch := range channels {
		changed := false
		if ch.ChanServPass != "" && !strings.HasPrefix(ch.ChanServPass, encPrefix) {
			ch.ChanServPass = encryptField(ch.ChanServPass, d.encKeys.current)
			changed = true
		}
		if ch.ChanOperPass != "" && !strings.HasPrefix(ch.ChanOperPass, encPrefix) {
			ch.ChanOperPass = encryptField(ch.ChanOperPass, d.encKeys.current)
			changed = true
		}
		if ch.ChannelKey != "" && !strings.HasPrefix(ch.ChannelKey, encPrefix) {
			ch.ChannelKey = encryptField(ch.ChannelKey, d.encKeys.current)
			changed = true
		}
		if changed {
			d.db.Model(&ch).Updates(map[string]interface{}{
				"chanserv_password": ch.ChanServPass,
				"chan_oper_pass":    ch.ChanOperPass,
				"channel_key":       ch.ChannelKey,
			})
		}
	}

	// Encrypt secret system_settings rows. LC-38 (2026-07-04 audit): the
	// incident-channel secrets added in v0.11.x (webhook_secret,
	// pagerduty_routing_key, opsgenie_api_key) were persisted plaintext
	// because UpdateSettings only encrypted inside its smtp_password case.
	// The write path is fixed; this backfill upgrades rows that predate the
	// fix. Idempotent via the {enc}-prefix skip, like the loops above.
	keys := make([]string, 0, len(SecretSettingKeys))
	for k := range SecretSettingKeys {
		keys = append(keys, k)
	}
	var secretSettings []models.SystemSetting
	d.db.Where("key IN ?", keys).Find(&secretSettings)
	for _, s := range secretSettings {
		if s.Value == "" || strings.HasPrefix(s.Value, encPrefix) {
			continue
		}
		// Rows corrupted by the pre-fix mask writeback (LC-37) hold the
		// literal redaction mask (httputil.RedactedMask), not a real secret.
		// Encrypting the mask would only disguise the corruption — leave it
		// plaintext so the operator can spot it and re-enter the credential.
		if s.Value == "********" {
			continue
		}
		d.db.Model(&models.SystemSetting{}).Where("key = ?", s.Key).
			Updates(map[string]interface{}{
				"value":     encryptField(s.Value, d.encKeys.current),
				"is_secret": true,
			})
	}
}
