package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
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

// decryptField decrypts a "{enc}"-prefixed string. Returns the value unchanged
// if it is not encrypted (legacy plaintext) or if the key is not available.
func decryptField(ciphertext string, key []byte) string {
	if !strings.HasPrefix(ciphertext, encPrefix) {
		return ciphertext
	}
	if len(key) == 0 {
		return ciphertext
	}

	encoded := ciphertext[len(encPrefix):]
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ciphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return ciphertext
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ciphertext
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ciphertext
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return ciphertext
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
}

// DecryptDeviceSecrets decrypts SNMP credential fields on a device.
func (d *Database) DecryptDeviceSecrets(dev *models.Device) {
	dev.SNMPCommunity = decryptField(dev.SNMPCommunity, d.encKey)
	dev.SNMPV3AuthPass = decryptField(dev.SNMPV3AuthPass, d.encKey)
	dev.SNMPV3PrivPass = decryptField(dev.SNMPV3PrivPass, d.encKey)
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
				"snmp_community":  dev.SNMPCommunity,
				"snmpv3_auth_pass": dev.SNMPV3AuthPass,
				"snmpv3_priv_pass": dev.SNMPV3PrivPass,
			})
		}
	}
}
