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

// decryptField decrypts a "{enc}"-prefixed string and returns the plaintext.
//
// Behavior:
//   - No "{enc}" prefix → legacy plaintext, returned unchanged (idempotent
//     for callers that decrypt unconditionally).
//   - Has "{enc}" prefix but decryption fails for ANY reason (no key, bad
//     base64, AES setup error, GCM auth failure, short ciphertext) → returns
//     "" and logs at error level.
//
// AUDIT-027: returning the raw ciphertext on failure is the v0.10.226 bug
// class — any caller that uses the value as a credential then transmits the
// ciphertext bytes to a remote server (Postfix logged the literal
// "{enc}<base64>" string in that incident). Returning "" guarantees the
// failure is loud and the secret never leaves the process.
func decryptField(ciphertext string, key []byte) string {
	if !strings.HasPrefix(ciphertext, encPrefix) {
		return ciphertext
	}
	// From here on the field IS marked as encrypted — any failure must
	// resolve to "" so the broken ciphertext never reaches a caller.
	if len(key) == 0 {
		log.Printf("ERROR: decryptField: encrypted field present but no key available (JWT_SECRET_KEY / ENCRYPTION_KEY missing?) — returning empty")
		return ""
	}

	encoded := ciphertext[len(encPrefix):]
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Printf("ERROR: decryptField: base64 decode failed (%v) — returning empty", err)
		return ""
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("ERROR: decryptField: AES cipher init failed (%v) — returning empty", err)
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("ERROR: decryptField: GCM init failed (%v) — returning empty", err)
		return ""
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		log.Printf("ERROR: decryptField: ciphertext shorter than nonce (got %d, want >= %d) — returning empty", len(data), nonceSize)
		return ""
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		log.Printf("ERROR: decryptField: GCM auth failed (wrong key, key rotation, or tampered data) — returning empty: %v", err)
		return ""
	}

	return string(plaintext)
}

// EncryptField encrypts a single string value for database storage.
func (d *Database) EncryptField(plaintext string) string {
	return encryptField(plaintext, d.encKey)
}

// EncryptDeviceSecrets encrypts SNMP credential fields on a device.
func (d *Database) EncryptDeviceSecrets(dev *models.Device) {
	dev.SNMPCommunity = encryptField(dev.SNMPCommunity, d.encKey)
	dev.SNMPV3AuthPass = encryptField(dev.SNMPV3AuthPass, d.encKey)
	dev.SNMPV3PrivPass = encryptField(dev.SNMPV3PrivPass, d.encKey)
	dev.SSHPassword = encryptField(dev.SSHPassword, d.encKey)
}

// DecryptDeviceSecrets decrypts SNMP credential fields on a device.
func (d *Database) DecryptDeviceSecrets(dev *models.Device) {
	dev.SNMPCommunity = decryptField(dev.SNMPCommunity, d.encKey)
	dev.SNMPV3AuthPass = decryptField(dev.SNMPV3AuthPass, d.encKey)
	dev.SNMPV3PrivPass = decryptField(dev.SNMPV3PrivPass, d.encKey)
	dev.SSHPassword = decryptField(dev.SSHPassword, d.encKey)
}

// DecryptField decrypts a single string value from database storage.
func (d *Database) DecryptField(ciphertext string) string {
	return decryptField(ciphertext, d.encKey)
}

// EncryptIRCServerSecrets encrypts IRC credential fields on a server.
func (d *Database) EncryptIRCServerSecrets(s *models.IRCServer) {
	s.ServerPassword = encryptField(s.ServerPassword, d.encKey)
	s.NickServPassword = encryptField(s.NickServPassword, d.encKey)
	s.SASLPassword = encryptField(s.SASLPassword, d.encKey)
}

// DecryptIRCServerSecrets decrypts IRC credential fields on a server.
func (d *Database) DecryptIRCServerSecrets(s *models.IRCServer) {
	s.ServerPassword = decryptField(s.ServerPassword, d.encKey)
	s.NickServPassword = decryptField(s.NickServPassword, d.encKey)
	s.SASLPassword = decryptField(s.SASLPassword, d.encKey)
}

// EncryptIRCChannelSecrets encrypts IRC channel credential fields.
func (d *Database) EncryptIRCChannelSecrets(ch *models.IRCChannel) {
	ch.ChanServPass = encryptField(ch.ChanServPass, d.encKey)
	ch.ChanOperPass = encryptField(ch.ChanOperPass, d.encKey)
	ch.ChannelKey = encryptField(ch.ChannelKey, d.encKey)
}

// DecryptIRCChannelSecrets decrypts IRC channel credential fields.
func (d *Database) DecryptIRCChannelSecrets(ch *models.IRCChannel) {
	ch.ChanServPass = decryptField(ch.ChanServPass, d.encKey)
	ch.ChanOperPass = decryptField(ch.ChanOperPass, d.encKey)
	ch.ChannelKey = decryptField(ch.ChannelKey, d.encKey)
}

// migrateEncryptSecrets encrypts any plaintext SNMP credentials in the database.
// This is idempotent — already encrypted values (with {enc} prefix) are skipped.
func (d *Database) migrateEncryptSecrets() {
	if len(d.encKey) == 0 {
		return
	}

	var devices []models.Device
	d.db.Find(&devices)

	for _, dev := range devices {
		changed := false
		if dev.SNMPCommunity != "" && !strings.HasPrefix(dev.SNMPCommunity, encPrefix) {
			dev.SNMPCommunity = encryptField(dev.SNMPCommunity, d.encKey)
			changed = true
		}
		if dev.SNMPV3AuthPass != "" && !strings.HasPrefix(dev.SNMPV3AuthPass, encPrefix) {
			dev.SNMPV3AuthPass = encryptField(dev.SNMPV3AuthPass, d.encKey)
			changed = true
		}
		if dev.SNMPV3PrivPass != "" && !strings.HasPrefix(dev.SNMPV3PrivPass, encPrefix) {
			dev.SNMPV3PrivPass = encryptField(dev.SNMPV3PrivPass, d.encKey)
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
			srv.ServerPassword = encryptField(srv.ServerPassword, d.encKey)
			changed = true
		}
		if srv.NickServPassword != "" && !strings.HasPrefix(srv.NickServPassword, encPrefix) {
			srv.NickServPassword = encryptField(srv.NickServPassword, d.encKey)
			changed = true
		}
		if srv.SASLPassword != "" && !strings.HasPrefix(srv.SASLPassword, encPrefix) {
			srv.SASLPassword = encryptField(srv.SASLPassword, d.encKey)
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
			ch.ChanServPass = encryptField(ch.ChanServPass, d.encKey)
			changed = true
		}
		if ch.ChanOperPass != "" && !strings.HasPrefix(ch.ChanOperPass, encPrefix) {
			ch.ChanOperPass = encryptField(ch.ChanOperPass, d.encKey)
			changed = true
		}
		if ch.ChannelKey != "" && !strings.HasPrefix(ch.ChannelKey, encPrefix) {
			ch.ChannelKey = encryptField(ch.ChannelKey, d.encKey)
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
}
