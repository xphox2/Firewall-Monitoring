package database

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"firewall-mon/internal/models"
)

// D-12 (fail-closed field encryption) and D-11 (HKDF {enc2}) at the Database
// layer. Synthetic data only (RFC 5737, fw-example-NN).

// keylessProdDB is a keyless Database WITHOUT the test harness's plaintext
// passthrough — what a production Database with no key would be.
func keylessProdDB(t *testing.T) *Database {
	t.Helper()
	d := NewDatabaseForTesting(t)
	d.RequireEncryptionKeyForTesting()
	return d
}

// rawColumn reads one column straight from the table (no decryption).
func rawColumn(t *testing.T, d *Database, table, col string, id uint) string {
	t.Helper()
	var v string
	if err := d.db.Table(table).Where("id = ?", id).Pluck(col, &v).Error; err != nil {
		t.Fatalf("read %s.%s: %v", table, col, err)
	}
	return v
}

func TestEncryptField_KeylessNonTestDatabaseFails(t *testing.T) {
	d := keylessProdDB(t)
	got, err := d.EncryptField("plain-secret")
	if err == nil || got != "" {
		t.Fatalf("keyless EncryptField = (%q, %v), want (\"\", error): a secret must never be stored plaintext", got, err)
	}
	// "" and already-encrypted values need no key and still pass through.
	if got, err := d.EncryptField(""); err != nil || got != "" {
		t.Fatalf("EncryptField(\"\") = (%q, %v)", got, err)
	}
	for _, ct := range []string{"{enc}AAAA", "{enc2}AAAA"} {
		if got, err := d.EncryptField(ct); err != nil || got != ct {
			t.Fatalf("EncryptField(%q) = (%q, %v), want unchanged", ct, got, err)
		}
	}
}

func TestEncryptField_TestHarnessKeylessPassthrough(t *testing.T) {
	d := NewDatabaseForTesting(t)
	if got, err := d.EncryptField("plain"); err != nil || got != "plain" {
		t.Fatalf("harness passthrough = (%q, %v), want (\"plain\", nil)", got, err)
	}
}

func TestCreateDevice_KeylessFailsAndStoresNothing(t *testing.T) {
	d := keylessProdDB(t)
	dev := &models.Device{Name: "fw-example-01", IPAddress: "192.0.2.10", SNMPCommunity: "plain-community"}
	if err := d.CreateDevice(dev); err == nil {
		t.Fatal("CreateDevice with no key succeeded; want an error")
	}
	var n int64
	d.db.Model(&models.Device{}).Count(&n)
	if n != 0 {
		t.Fatalf("CreateDevice stored %d row(s) despite the encryption failure", n)
	}
	if dev.SNMPCommunity != "plain-community" {
		t.Fatalf("device struct mutated on failure: %q", dev.SNMPCommunity)
	}
}

func TestUpdateDevice_EncryptsAndFailsClosed(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.SetEncryptionKeyForTesting("update-device-key")
	dev := &models.Device{Name: "fw-example-02", IPAddress: "192.0.2.11", SNMPCommunity: "first-community"}
	if err := d.CreateDevice(dev); err != nil {
		t.Fatal(err)
	}
	loaded, err := d.GetDevice(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.SSHPassword = "new-ssh-password"
	if err := d.UpdateDevice(loaded); err != nil {
		t.Fatal(err)
	}
	for col, plain := range map[string]string{"snmp_community": "first-community", "ssh_password": "new-ssh-password"} {
		raw := rawColumn(t, d, "devices", col, dev.ID)
		if !strings.HasPrefix(raw, enc2Prefix) || strings.Contains(raw, plain) {
			t.Fatalf("UpdateDevice stored %s as %q, want {enc2} ciphertext", col, raw)
		}
	}
	if loaded.SSHPassword != "new-ssh-password" {
		t.Fatalf("caller's device not decrypted back: %q", loaded.SSHPassword)
	}

	// Same row, key gone (non-test keyless): the update must fail and leave
	// the stored ciphertext untouched.
	before := rawColumn(t, d, "devices", "ssh_password", dev.ID)
	d.encKeys = keyChain{}
	d.RequireEncryptionKeyForTesting()
	loaded.SSHPassword = "would-be-plaintext"
	if err := d.UpdateDevice(loaded); err == nil {
		t.Fatal("keyless UpdateDevice succeeded; want an error")
	}
	if after := rawColumn(t, d, "devices", "ssh_password", dev.ID); after != before {
		t.Fatalf("keyless UpdateDevice rewrote ssh_password to %q", after)
	}
}

// failAfterReader serves real randomness for the first n reads, then fails —
// so a multi-field encrypt fails part-way through.
type failAfterReader struct{ n int }

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return failingReader{}.Read(p)
	}
	r.n--
	return rand.Read(p)
}

func TestEncryptSecrets_AllOrNothing(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.SetEncryptionKeyForTesting("k")
	orig := randReader
	t.Cleanup(func() { randReader = orig })

	// The first field encrypts, the second fails: the struct must come back
	// untouched, not half-encrypted.
	randReader = &failAfterReader{n: 1}
	srv := models.IRCServer{ServerPassword: "a", NickServPassword: "b", SASLPassword: "c"}
	if err := d.EncryptIRCServerSecrets(&srv); err == nil {
		t.Fatal("EncryptIRCServerSecrets with failing rand: want error")
	}
	if srv.ServerPassword != "a" || srv.NickServPassword != "b" || srv.SASLPassword != "c" {
		t.Fatalf("server half-encrypted on failure: %+v", srv)
	}

	randReader = failingReader{}
	ch := models.IRCChannel{ChanServPass: "a", ChannelKey: "k"}
	if err := d.EncryptIRCChannelSecrets(&ch); err == nil {
		t.Fatal("EncryptIRCChannelSecrets with failing rand: want error")
	}
	dev := models.Device{SNMPCommunity: "c", APIToken: "t"}
	if err := d.EncryptDeviceSecrets(&dev); err == nil {
		t.Fatal("EncryptDeviceSecrets with failing rand: want error")
	}
}

func TestIPSecAndProbeAndArchive_KeylessFailClosed(t *testing.T) {
	d := keylessProdDB(t)

	m, err := IPSecIntentToModel(sampleIntent())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CreateIPSecTunnel(m); err == nil {
		t.Fatal("CreateIPSecTunnel with no key succeeded")
	}
	var n int64
	d.db.Model(&models.IPSecTunnel{}).Count(&n)
	if n != 0 {
		t.Fatalf("ipsec tunnel stored despite encryption failure (%d rows)", n)
	}

	if err := d.EnqueueProbeCommand(&models.ProbeCommand{ProbeID: 1, Type: "noop", Payload: `{"psk":"x"}`}); err == nil {
		t.Fatal("EnqueueProbeCommand with no key succeeded")
	}
	d.db.Model(&models.ProbeCommand{}).Count(&n)
	if n != 0 {
		t.Fatalf("probe command stored despite encryption failure (%d rows)", n)
	}

	err = d.SaveArchiveSettings(context.Background(), map[string]string{"ARCHIVE_S3_SECRET_ACCESS_KEY": "fake-ui-secret"}, nil, nil, time.Now())
	if err == nil {
		t.Fatal("SaveArchiveSettings with no key succeeded")
	}
	var leaked int64
	d.db.Model(&models.SystemSetting{}).Where("value LIKE ?", "%fake-ui-secret%").Count(&leaked)
	if leaked != 0 {
		t.Fatal("archive secret stored as plaintext")
	}
}

// TestMigrateEncryptSecrets_SkipsOnEncryptFailure — the startup backfill
// must leave a row alone (logged) when encryption fails, never write a
// blank or plaintext replacement.
func TestMigrateEncryptSecrets_SkipsOnEncryptFailure(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.SetEncryptionKeyForTesting("backfill-fail-key")
	dev := models.Device{Name: "fw-example-03", IPAddress: "192.0.2.12", SNMPCommunity: "legacy-plain-community"}
	if err := d.db.Create(&dev).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.db.Create(&models.SystemSetting{Key: "webhook_secret", Value: "legacy-wh"}).Error; err != nil {
		t.Fatal(err)
	}

	orig := randReader
	randReader = failingReader{}
	d.migrateEncryptSecrets()
	randReader = orig

	if got := rawColumn(t, d, "devices", "snmp_community", dev.ID); got != "legacy-plain-community" {
		t.Fatalf("backfill rewrote snmp_community on failure to %q", got)
	}
	var s models.SystemSetting
	d.db.Where("key = ?", "webhook_secret").First(&s)
	if s.Value != "legacy-wh" {
		t.Fatalf("backfill rewrote webhook_secret on failure to %q", s.Value)
	}

	// Once encryption works again the next startup upgrades them to {enc2}.
	d.migrateEncryptSecrets()
	if got := rawColumn(t, d, "devices", "snmp_community", dev.ID); !strings.HasPrefix(got, enc2Prefix) {
		t.Fatalf("backfill did not encrypt snmp_community: %q", got)
	}
}

// TestMigrateEncryptSecrets_LeavesEnc2Alone — an {enc2} value is already
// encrypted: the backfill must not wrap it again ("{enc2}" does not start
// with "{enc}", so a legacy-only prefix check would double-encrypt it).
func TestMigrateEncryptSecrets_LeavesEnc2Alone(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.SetEncryptionKeyForTesting("backfill-enc2-key")
	ct := mustEncrypt(t, "community", d.encKeys.current)
	ircCT := mustEncrypt(t, "irc-pass", d.encKeys.current)
	dev := models.Device{Name: "fw-example-04", IPAddress: "192.0.2.13", SNMPCommunity: ct}
	if err := d.db.Create(&dev).Error; err != nil {
		t.Fatal(err)
	}
	// The SQLite harness does not migrate the IRC tables.
	if err := d.db.AutoMigrate(&models.IRCServer{}); err != nil {
		t.Fatal(err)
	}
	srv := models.IRCServer{Name: "irc-example", ServerHost: "198.51.100.7", ServerPassword: ircCT}
	if err := d.db.Create(&srv).Error; err != nil {
		t.Fatal(err)
	}
	d.migrateEncryptSecrets()
	if got := rawColumn(t, d, "devices", "snmp_community", dev.ID); got != ct {
		t.Fatalf("backfill re-encrypted an {enc2} value: %q", got)
	}
	if got := rawColumn(t, d, "irc_servers", "server_password", srv.ID); got != ircCT {
		t.Fatalf("backfill re-encrypted an {enc2} IRC value: %q", got)
	}
}

// TestDevice_NewSecretsAreEnc2AndLegacyRowsRead — end to end through the
// Database API: a new device secret lands as {enc2}; a row written by a
// pre-D-11 binary ({enc}, sha256 key) under a key now in
// ENCRYPTION_KEY_HISTORY still decrypts on read.
func TestDevice_NewSecretsAreEnc2AndLegacyRowsRead(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.encKeys = newKeyChain("current-key", []string{"retired-key"})

	fresh := &models.Device{Name: "fw-example-05", IPAddress: "192.0.2.14", SNMPCommunity: "fresh-community"}
	if err := d.CreateDevice(fresh); err != nil {
		t.Fatal(err)
	}
	if raw := rawColumn(t, d, "devices", "snmp_community", fresh.ID); !strings.HasPrefix(raw, enc2Prefix) {
		t.Fatalf("new device secret stored as %q, want {enc2}", raw)
	}

	old := models.Device{Name: "fw-example-06", IPAddress: "192.0.2.15",
		SNMPCommunity: legacyEncryptIndependently(t, "old-community", "retired-key"),
		SSHPassword:   legacyEncryptIndependently(t, "old-ssh", "current-key")}
	if err := d.db.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	got, err := d.GetDevice(old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SNMPCommunity != "old-community" || got.SSHPassword != "old-ssh" {
		t.Fatalf("legacy rows unreadable: community=%q ssh=%q", got.SNMPCommunity, got.SSHPassword)
	}
}

// TestVerifyEncryptionKey_CanaryIsLegacyFormat — the canary stays {enc} so a
// rollback to a pre-D-11 binary still verifies the key; and a canary written
// by a pre-D-11 binary verifies under the new one.
func TestVerifyEncryptionKey_CanaryIsLegacyFormat(t *testing.T) {
	d := NewDatabaseForTesting(t)
	d.SetEncryptionKeyForTesting("canary-key")
	if err := d.VerifyEncryptionKey(); err != nil {
		t.Fatal(err)
	}
	var s models.SystemSetting
	d.db.Where("key = ?", encKeyCanaryKey).First(&s)
	if !strings.HasPrefix(s.Value, encPrefix) {
		t.Fatalf("canary stored as %q, want the legacy {enc} format", s.Value)
	}

	old := NewDatabaseForTesting(t)
	old.SetEncryptionKeyForTesting("canary-key")
	if err := old.db.Create(&models.SystemSetting{Key: encKeyCanaryKey,
		Value: legacyEncryptIndependently(t, encKeyCanaryPlaintext, "canary-key")}).Error; err != nil {
		t.Fatal(err)
	}
	if err := old.VerifyEncryptionKey(); err != nil {
		t.Fatalf("pre-D-11 canary does not verify: %v", err)
	}
}
