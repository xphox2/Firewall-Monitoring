package local

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stubStatFS makes StatFS report fi for every path.
func stubStatFS(t *testing.T, f func(path string) (FSInfo, error)) {
	t.Helper()
	orig := StatFS
	StatFS = f
	t.Cleanup(func() { StatFS = orig })
}

func checkNamed(r *Report, name string) *Check {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			return &r.Checks[i]
		}
	}
	return nil
}

// TestProbe_WritableDirectory: a writable directory under the root passes
// every check (write, fsync, rename without overwrite, read back, read-only
// files on a local filesystem) and nothing is left in it.
func TestProbe_WritableDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "staging")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// The type is stubbed: a CI runner's /tmp may be tmpfs, which the probe
	// refuses (TestProbe_Refusals); TestStatFS_Real asks the kernel.
	stubStatFS(t, func(string) (FSInfo, error) {
		return FSInfo{Type: "ext4", FreeBytes: 1 << 40, TotalBytes: 1 << 41}, nil
	})
	r := Probe(ctx, root, dir, 0)
	if !r.OK {
		t.Fatalf("probe failed: %+v", r.Checks)
	}
	if c := checkNamed(r, "write"); c == nil || !c.OK || !strings.Contains(c.Detail, "a second commit onto the same name refused") {
		t.Fatalf("write check %+v", c)
	}
	if c := checkNamed(r, "read-only files"); c != nil {
		t.Fatalf("chmod 0444 is effective on a local filesystem, got %+v", c)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the probe left %v behind", ents)
	}
	if r.FSType != "ext4" || !strings.Contains(checkNamed(r, "filesystem").Detail, "1024.0 GiB free") {
		t.Fatalf("filesystem check %+v", checkNamed(r, "filesystem"))
	}
}

// TestProbe_Refusals: outside the root (by a link), the container's writable
// layer (overlay) or memory (tmpfs), and below the free-space floor fail; a
// network share passes with a warning.
func TestProbe_Refusals(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	if r := Probe(ctx, root, filepath.Join(root, "out"), 0); r.OK || !strings.Contains(r.Checks[0].Detail, "outside ARCHIVE_ALLOWED_ROOT") {
		t.Fatalf("a link out of the root: %+v", r.Checks)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("the probe wrote outside the root: %v", ents)
	}
	for _, c := range []struct {
		fs      FSInfo
		minFree uint64
		ok      bool
		name    string
		want    string
	}{
		{FSInfo{Type: "overlay", FreeBytes: 1 << 40, TotalBytes: 1 << 41}, 0, false, "filesystem", "writable layer"},
		{FSInfo{Type: "tmpfs", FreeBytes: 1 << 40, TotalBytes: 1 << 41}, 0, false, "filesystem", "memory"},
		{FSInfo{Type: "ext4", FreeBytes: 1 << 20, TotalBytes: 1 << 41}, 2 << 30, false, "free space", "below"},
		{FSInfo{Type: "nfs", FreeBytes: 1 << 40, TotalBytes: 1 << 41}, 0, true, "filesystem", "network share"},
		{FSInfo{Type: "cifs", FreeBytes: 1 << 40, TotalBytes: 1 << 41}, 0, true, "filesystem", "_netdev"},
	} {
		stubStatFS(t, func(string) (FSInfo, error) { return c.fs, nil })
		r := Probe(ctx, root, root, c.minFree)
		got := checkNamed(r, c.name)
		if r.OK != c.ok || got == nil || !strings.Contains(got.Detail, c.want) || c.ok && !got.Warn {
			t.Errorf("%s: ok %v, %s check %+v", c.fs.Type, r.OK, c.name, got)
		}
	}
}

// TestLinuxFSName: the statfs magic numbers of the filesystems an archive
// goes on (NFS, both SMB clients, ext4, XFS, ZFS) and the container's own.
func TestLinuxFSName(t *testing.T) {
	for magic, want := range map[int64]string{
		0x6969: "nfs", 0xFF534D42: "cifs", 0xFE534D42: "cifs", 0xEF53: "ext4", 0x58465342: "xfs", 0x2FC12FC1: "zfs",
		0x794C7630: "overlay", 0x01021994: "tmpfs", 0x12345678: "unknown",
	} {
		if got := linuxFSName(magic); got != want {
			t.Errorf("linuxFSName(%#x) = %q, want %q", magic, got, want)
		}
	}
	if !(FSInfo{Type: "nfs"}).Network() || !(FSInfo{Type: "cifs"}).Network() || (FSInfo{Type: "ext4"}).Network() {
		t.Error("Network() misclassifies")
	}
}

// TestStatFS_Real: the running kernel's answer for a temporary directory —
// a type, a device two sibling directories share, sizes.
func TestStatFS_Real(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("filesystem information is Linux and macOS only")
	}
	a, b := t.TempDir(), t.TempDir()
	fa, err := StatFS(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := StatFS(b)
	if err != nil {
		t.Fatal(err)
	}
	if fa.Type == "" || fa.TotalBytes == 0 || !SameFS(&fa, &fb) {
		t.Fatalf("StatFS: %+v / %+v", fa, fb)
	}
}

// TestIsMountPoint: from the mount table (with its octal escapes) where
// there is one, else by the device of the directory and its parent.
func TestIsMountPoint(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "arch ive")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(dir)
	table := filepath.Join(root, "mountinfo")
	line := "36 35 98:0 /mnt/fwmon-archive " + strings.ReplaceAll(real, " ", `\040`) + " rw,noatime master:1 - ext4 /dev/sdb1 rw\n"
	if err := os.WriteFile(table, []byte("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"+line), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := mountinfoPath
	t.Cleanup(func() { mountinfoPath = orig })
	mountinfoPath = table
	if ok, err := isMountPoint(dir); !ok || err != nil {
		t.Fatalf("listed in the mount table: %v %v", ok, err)
	}
	if ok, err := isMountPoint(root); ok || err != nil {
		t.Fatalf("not listed: %v %v", ok, err)
	}
	// No mount table: the device decides.
	mountinfoPath = filepath.Join(root, "absent")
	stubStatFS(t, func(p string) (FSInfo, error) {
		if p == real {
			return FSInfo{Device: 2}, nil
		}
		return FSInfo{Device: 1}, nil
	})
	if ok, err := isMountPoint(dir); !ok || err != nil {
		t.Fatalf("another device than its parent: %v %v", ok, err)
	}
	stubStatFS(t, func(string) (FSInfo, error) { return FSInfo{Device: 1}, nil })
	if ok, err := isMountPoint(dir); ok || err != nil {
		t.Fatalf("the parent's device: %v %v", ok, err)
	}
}
