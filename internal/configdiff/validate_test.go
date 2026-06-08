package configdiff

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateFortiGateBackup_RealConfigPasses(t *testing.T) {
	t.Parallel()
	// fortigateUnchangedA from normalize_test.go is real-shape FortiOS config
	// text. We pad it past the 1KB floor since the test fixture is compact.
	cfg := fortigateUnchangedA + strings.Repeat("\nconfig system replacemsg-image\n    edit \"foo\"\n    next\nend\n", 30)
	if err := ValidateFortiGateBackup([]byte(cfg)); err != nil {
		t.Errorf("real-shape config rejected: %v", err)
	}
}

func TestValidateFortiGateBackup_Empty(t *testing.T) {
	t.Parallel()
	if err := ValidateFortiGateBackup(nil); !errors.Is(err, ErrEmptyBackup) {
		t.Errorf("nil bytes: got %v, want ErrEmptyBackup", err)
	}
	if err := ValidateFortiGateBackup([]byte{}); !errors.Is(err, ErrEmptyBackup) {
		t.Errorf("empty bytes: got %v, want ErrEmptyBackup", err)
	}
}

func TestValidateFortiGateBackup_Truncated(t *testing.T) {
	t.Parallel()
	short := strings.Repeat("config system global\nset hostname \"X\"\nend\n", 10)
	if err := ValidateFortiGateBackup([]byte(short)); !errors.Is(err, ErrBackupTooSmall) {
		t.Errorf("sub-min-size: got %v, want ErrBackupTooSmall", err)
	}
}

func TestValidateFortiGateBackup_MissingVersionHeader(t *testing.T) {
	t.Parallel()
	cfg := strings.Repeat("config system global\n    set hostname \"X\"\nend\n", 50)
	if err := ValidateFortiGateBackup([]byte(cfg)); !errors.Is(err, ErrMissingVersionHeader) {
		t.Errorf("missing header: got %v, want ErrMissingVersionHeader", err)
	}
}

func TestValidateFortiGateBackup_MissingSystemGlobal(t *testing.T) {
	t.Parallel()
	cfg := "#config-version=fake\n" + strings.Repeat("config firewall policy\n    edit 1\n    next\nend\n", 50)
	if err := ValidateFortiGateBackup([]byte(cfg)); !errors.Is(err, ErrMissingSystemGlobal) {
		t.Errorf("missing system global: got %v, want ErrMissingSystemGlobal", err)
	}
}

func TestValidateFortiGateBackup_TooFewBlocks(t *testing.T) {
	t.Parallel()
	cfg := "#config-version=fake\n" +
		strings.Repeat("# padding line that fills space without adding config blocks\n", 30) +
		"config system global\n    set hostname \"X\"\nend\n"
	if err := ValidateFortiGateBackup([]byte(cfg)); !errors.Is(err, ErrTooFewConfigBlocks) {
		t.Errorf("too few blocks: got %v, want ErrTooFewConfigBlocks", err)
	}
}

func TestValidateFortiGateBackup_UnbalancedBlocks(t *testing.T) {
	t.Parallel()
	// 10 `config X` blocks, only 2 `end`s — clear truncation.
	cfg := "#config-version=fake\nconfig system global\n    set hostname \"X\"\n"
	for i := 0; i < 10; i++ {
		cfg += "\nconfig firewall policy\n    edit 1\n    next\n"
	}
	cfg += "\nend\n\nend\n"
	cfg += strings.Repeat("\n# pad\n", 200)
	if err := ValidateFortiGateBackup([]byte(cfg)); !errors.Is(err, ErrUnbalancedConfigBlocks) {
		t.Errorf("unbalanced: got %v, want ErrUnbalancedConfigBlocks", err)
	}
}

func TestValidateFortiGateBackup_BinaryCorruption(t *testing.T) {
	t.Parallel()
	// Real-shape config (with valid headers) but lots of binary bytes mixed
	// into the BODY. Skip the first 200 bytes so the #config-version= /
	// system-global checks pass, then corrupt frequently to exceed the
	// non-printable ratio threshold.
	cfg := []byte(fortigateUnchangedA + strings.Repeat("\nconfig system replacemsg-image\n    edit \"foo\"\n    next\nend\n", 30))
	for i := 200; i < len(cfg); i += 20 {
		cfg[i] = 0x01
	}
	if err := ValidateFortiGateBackup(cfg); !errors.Is(err, ErrBinaryCorruption) {
		t.Errorf("binary corruption: got %v, want ErrBinaryCorruption", err)
	}
}

func TestValidateFortiGateBackup_AllowsSparseNonPrintable(t *testing.T) {
	t.Parallel()
	// A handful of stray non-printable bytes (well under 1%) — should pass.
	cfg := []byte(fortigateUnchangedA + strings.Repeat("\nconfig system replacemsg-image\n    edit \"foo\"\n    next\nend\n", 30))
	if len(cfg) > 200 {
		cfg[50] = 0x02
		cfg[150] = 0x03
	}
	if err := ValidateFortiGateBackup(cfg); err != nil {
		t.Errorf("sparse non-printables should pass: %v", err)
	}
}
