package configdiff

import (
	"fmt"
	"strings"
	"testing"
)

// buildFortiFullConfig synthesizes a `show full-configuration` capture: a CLI
// prompt on line 1, no indentation, and a `config system global` block padded
// with the ~150+ default settings such a dump emits (only a couple are
// non-default). It shares the same admin/password core as fortiShowBackup so the
// two represent the same device captured two different ways.
func buildFortiFullConfig() string {
	var b strings.Builder
	b.WriteString("FW-HOME # #config-version=FGT60F-7.4.12-FW-build2902-260505:opmode=1:vdom=0:user=backup\n")
	b.WriteString("#conf_file_ver=376277789922848\n")
	b.WriteString("config system global\n")
	b.WriteString("set admin-port 81\n")
	b.WriteString("set hostname \"FW-HOME\"\n")
	for i := range 150 {
		fmt.Fprintf(&b, "set default-setting-%d enable\n", i)
	}
	b.WriteString("end\n")
	b.WriteString("config system admin\n")
	b.WriteString("edit \"admin\"\n")
	b.WriteString("set accprofile \"super_admin\"\n")
	b.WriteString("set password ENC ZZZZdifferentivsameplaintext==\n")
	b.WriteString("next\n")
	b.WriteString("end\n")
	return b.String()
}

// These fixtures are synthetic but reproduce the exact volatility patterns found
// in real FortiGate FGT60F-7.4.12 backups (tasks/config_1_30* during the
// v0.10.439 investigation). Real backups are NOT committed because they carry
// cert private keys and IPsec PSK seeds.

// fortiShowBackup is a plain `show` backup: indented, non-default settings only,
// includes the per-admin gui-dashboard block with volatile last-updated stamps.
const fortiShowBackup = `#config-version=FGT60F-7.4.12-FW-build2902-260505:opmode=0:vdom=0:user=backup
#conf_file_ver=376277789922848
config system global
    set admin-port 81
    set hostname "FW-HOME"
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC AAAAabc123randomivblob==
        config gui-dashboard
            edit 30
                set name "Status"
                set last-updated 1759401219
                config widget
                    edit 1
                        set width 1
                        set last-updated 1759401219
                    next
                end
            next
        end
    next
end`

// fortiConsoleFullConfig is the SAME logical device captured via console
// `show full-configuration`: a CLI prompt is echoed onto line 1, opmode differs
// in the header, there is no indentation, and FortiOS omits gui-dashboard while
// emitting every default. It must still normalize to the same non-default core.
const fortiConsoleFullConfig = `FW-HOME # #config-version=FGT60F-7.4.12-FW-build2902-260505:opmode=1:vdom=0:user=backup
#conf_file_ver=376277789922848
config system global
set admin-concurrent enable
set admin-console-timeout 0
set admin-hsts-max-age 63072000
set admin-https-redirect enable
set admin-lockout-duration 60
set admin-lockout-threshold 3
set admin-port 81
set admin-ssh-grace-time 120
set admin-ssh-port 22
set admin-telnet enable
set admintimeout 60
set anti-replay strict
set arp-max-entry 131072
set av-failopen pass
set cfg-save automatic
set gui-theme jade
set hostname "FW-HOME"
set timezone 04
end
config system admin
edit "admin"
set accprofile "super_admin"
set password ENC ZZZZdifferentivsameplaintext==
next
end`

func TestFortinet_GuiDashboardStripped(t *testing.T) {
	out, _ := Normalize("fortigate", []byte(fortiShowBackup))
	s := string(out)
	if strings.Contains(s, "set last-updated 1759401219") {
		t.Error("volatile last-updated timestamp survived normalization")
	}
	if strings.Contains(s, `set name "Status"`) {
		t.Error("gui-dashboard widget content survived; block should be collapsed")
	}
	if !strings.Contains(s, "<volatile-gui-dashboard>") {
		t.Error("gui-dashboard block was not replaced with its marker")
	}
	// Content outside the block must remain.
	if !strings.Contains(s, `set hostname "FW-HOME"`) {
		t.Error("non-dashboard config was wrongly stripped")
	}
}

func TestFortinet_PromptPrefixStripped(t *testing.T) {
	out, _ := Normalize("fortigate", []byte(fortiConsoleFullConfig))
	s := string(out)
	if strings.Contains(s, "FW-HOME #") {
		t.Error("console prompt prefix survived normalization")
	}
	// With the prompt stripped, the config-version header must normalize.
	if !strings.Contains(s, "#config-version=<volatile-version>") {
		t.Error("config-version header did not normalize after prompt strip")
	}
}

func TestFortinet_EncIsVolatile(t *testing.T) {
	// Same plaintext password, different random IV — must not look like a change.
	a, _ := Normalize("fortigate", []byte(fortiShowBackup))
	b, _ := Normalize("fortigate", []byte(fortiConsoleFullConfig))
	if !strings.Contains(string(a), "set password ENC <volatile-enc>") ||
		!strings.Contains(string(b), "set password ENC <volatile-enc>") {
		t.Error("ENC password blob was not masked on both sides")
	}
}

func TestNormalize_Deterministic(t *testing.T) {
	want := HashNormalized("fortigate", []byte(fortiShowBackup))
	for range 5 {
		if got := HashNormalized("fortigate", []byte(fortiShowBackup)); got != want {
			t.Fatalf("normalization is not deterministic: got %s want %s", got, want)
		}
	}
}

func TestAnalyze_CaptureModeMismatchDetected(t *testing.T) {
	rep := Analyze("fortigate", []byte(buildFortiFullConfig()), []byte(fortiShowBackup))
	if !rep.CaptureModeMismatch {
		t.Errorf("expected capture-mode mismatch to be flagged; reason=%q lines A=%d B=%d",
			rep.CaptureModeReason, rep.NormLinesA, rep.NormLinesB)
	}
	if rep.CaptureModeReason == "" {
		t.Error("capture-mode mismatch flagged but reason is empty")
	}
}

func TestFortinet_CaptureModeClassification(t *testing.T) {
	d, ok := Lookup("fortigate").(CaptureModeDetector)
	if !ok {
		t.Fatal("fortigate normalizer should implement CaptureModeDetector")
	}
	if m := d.CaptureMode([]byte(buildFortiFullConfig())); m != "full-configuration" {
		t.Errorf("full-config classified as %q, want full-configuration", m)
	}
	if m := d.CaptureMode([]byte(fortiShowBackup)); m != "show" {
		t.Errorf("show backup classified as %q, want show", m)
	}
	if m := d.CaptureMode([]byte("config firewall policy\nend")); m != "" {
		t.Errorf("config with no global block classified as %q, want empty", m)
	}
}

func TestAnalyze_IdenticalConfigsMatch(t *testing.T) {
	rep := Analyze("fortigate", []byte(fortiShowBackup), []byte(fortiShowBackup))
	if !rep.Match {
		t.Errorf("identical configs should match; only-in-A=%v only-in-B=%v", rep.OnlyInA, rep.OnlyInB)
	}
	if rep.CaptureModeMismatch {
		t.Error("identical configs must not be flagged as capture-mode mismatch")
	}
	if len(rep.OnlyInA) != 0 || len(rep.OnlyInB) != 0 {
		t.Errorf("identical configs should have no residual diff; A=%v B=%v", rep.OnlyInA, rep.OnlyInB)
	}
}

func TestAnalyze_RealEditIsNotCaptureMode(t *testing.T) {
	// A one-line change between two same-mode backups: must surface as a real
	// diff, NOT be excused as a capture-mode mismatch.
	edited := strings.Replace(fortiShowBackup, `set admin-port 81`, `set admin-port 8443`, 1)
	rep := Analyze("fortigate", []byte(fortiShowBackup), []byte(edited))
	if rep.Match {
		t.Error("a real port change should not hash-match")
	}
	if rep.CaptureModeMismatch {
		t.Error("a one-line edit must not be misclassified as capture-mode mismatch")
	}
	if len(rep.OnlyInB) != 1 || rep.OnlyInB[0] != "set admin-port 8443" {
		t.Errorf("expected exactly the changed line in B, got %v", rep.OnlyInB)
	}
}
