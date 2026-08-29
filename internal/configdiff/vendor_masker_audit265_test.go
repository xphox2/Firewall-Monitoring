package configdiff

import "testing"

// AUDIT-265: paloaltoNormalizer and ciscoASANormalizer advertised volatile
// patterns (phash/secret/key/Type6…) but did NOT implement LineMasker, so
// prepareDiffInput fell back to unmasked lines and the re-salted/re-nonced
// values churned as false red/green deltas on every diff. These tests pin that
// the volatile churn now folds to a `volatile` row (no Added/Removed) while a
// genuine change to a non-volatile line still diffs.

// --- PAN-OS ------------------------------------------------------------------

const panMaskA = `<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>fw-edge</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
  <mgt-config>
    <users>
      <entry name="admin">
        <phash>$5$aaaaaaaa$firstsaltedhashvalue0000</phash>
      </entry>
    </users>
  </mgt-config>
</config>`

// panMaskB: ONLY the phash body is re-salted (same password, new salt).
const panMaskB = `<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>fw-edge</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
  <mgt-config>
    <users>
      <entry name="admin">
        <phash>$5$bbbbbbbb$secondsaltedhashvalue111</phash>
      </entry>
    </users>
  </mgt-config>
</config>`

// panMaskC: re-salted phash AND a genuine non-volatile change (hostname).
const panMaskC = `<config version="10.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>fw-core</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
  <mgt-config>
    <users>
      <entry name="admin">
        <phash>$5$cccccccc$thirdsaltedhashvalue2222</phash>
      </entry>
    </users>
  </mgt-config>
</config>`

func TestPaloAltoLineMaskerFoldsVolatile_AUDIT265(t *testing.T) {
	t.Parallel()

	// Sanity: the vendor now IS a LineMasker (the whole point of the fix).
	if _, ok := Lookup("paloalto").(LineMasker); !ok {
		t.Fatal("paloaltoNormalizer does not implement LineMasker (AUDIT-265)")
	}

	// Re-salted phash only: no delta, folded to a volatile row.
	d := DiffLines("paloalto", []byte(panMaskA), []byte(panMaskB))
	_, del, ins, vol := countOps(d)
	if d.Added != 0 || d.Removed != 0 || del != 0 || ins != 0 {
		t.Fatalf("re-salted phash produced a false delta: Added=%d Removed=%d ins=%d del=%d\nrows=%+v", d.Added, d.Removed, ins, del, d.Rows)
	}
	if vol < 1 {
		t.Fatalf("expected the phash line to fold to a volatile row, got vol=%d\nrows=%+v", vol, d.Rows)
	}

	// A genuine non-volatile change still diffs despite the phash also re-salting.
	d2 := DiffLines("paloalto", []byte(panMaskA), []byte(panMaskC))
	if d2.Added == 0 && d2.Removed == 0 {
		t.Fatalf("real hostname change was swallowed: Added=%d Removed=%d\nrows=%+v", d2.Added, d2.Removed, d2.Rows)
	}
}

// --- Cisco ASA ---------------------------------------------------------------

const asaMaskA = `: Saved
hostname asa-fw
enable secret 6 AAAAnonce1BLOBBLOBBLOB
username admin password 6 XXXXnonce1BLOB privilege 15
username bob password 5 $1$stab$deterministichash
`

// asaMaskB: Type 6 secrets re-nonced (same secret); Type 5 unchanged.
const asaMaskB = `: Saved
hostname asa-fw
enable secret 6 BBBBnonce2BLOBBLOBBLOB
username admin password 6 YYYYnonce2BLOB privilege 15
username bob password 5 $1$stab$deterministichash
`

// asaMaskC: Type 6 re-nonced AND a genuine Type 5 password rotation (a real,
// non-volatile change that MUST still diff).
const asaMaskC = `: Saved
hostname asa-fw
enable secret 6 CCCCnonce3BLOBBLOBBLOB
username admin password 6 ZZZZnonce3BLOB privilege 15
username bob password 5 $1$stab$ROTATEDhashvalue99
`

func TestCiscoASALineMaskerFoldsVolatile_AUDIT265(t *testing.T) {
	t.Parallel()

	if _, ok := Lookup("cisco_asa").(LineMasker); !ok {
		t.Fatal("ciscoASANormalizer does not implement LineMasker (AUDIT-265)")
	}

	// Type 6 re-nonce only: no delta, folded to volatile rows.
	d := DiffLines("cisco_asa", []byte(asaMaskA), []byte(asaMaskB))
	_, del, ins, vol := countOps(d)
	if d.Added != 0 || d.Removed != 0 || del != 0 || ins != 0 {
		t.Fatalf("Type 6 re-nonce produced a false delta: Added=%d Removed=%d ins=%d del=%d\nrows=%+v", d.Added, d.Removed, ins, del, d.Rows)
	}
	if vol < 2 {
		t.Fatalf("expected the two Type 6 lines to fold to volatile rows, got vol=%d\nrows=%+v", vol, d.Rows)
	}

	// A genuine Type 5 rotation still diffs even though Type 6 also re-nonced.
	d2 := DiffLines("cisco_asa", []byte(asaMaskA), []byte(asaMaskC))
	if d2.Added == 0 && d2.Removed == 0 {
		t.Fatalf("real Type 5 rotation was swallowed: Added=%d Removed=%d\nrows=%+v", d2.Added, d2.Removed, d2.Rows)
	}
}
