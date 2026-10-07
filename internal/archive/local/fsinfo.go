package local

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// FSInfo is what statfs and stat say about the filesystem holding a path.
type FSInfo struct {
	// Type is the filesystem's name as the kernel reports it, normalised:
	// nfs, cifs (SMB, any dialect), ext4 (ext2/3/4 share a magic), xfs,
	// zfs, btrfs, tmpfs, overlay, fuse, apfs, ... or "unknown".
	Type string
	// Device identifies the filesystem (st_dev): two paths with the same
	// Device are on the same filesystem.
	Device uint64
	// FreeBytes is the space an unprivileged writer may use (f_bavail);
	// TotalBytes the filesystem's size.
	FreeBytes, TotalBytes uint64
}

// Network reports whether the filesystem is a network share (NFS, SMB, or a
// FUSE mount that may be one, e.g. sshfs).
func (f FSInfo) Network() bool {
	switch f.Type {
	case "nfs", "cifs", "smbfs", "smb", "fuse", "9p", "afs", "ceph", "glusterfs":
		return true
	}
	return false
}

// linuxFSMagic names the filesystems an archive is likely to be put on, by
// their statfs f_type (linux/magic.h; ZFS's from the OpenZFS sources).
var linuxFSMagic = map[int64]string{
	0x6969:     "nfs",
	0xFF534D42: "cifs", // CIFS_MAGIC_NUMBER
	0xFE534D42: "cifs", // SMB2_MAGIC_NUMBER (the smb3 client)
	0x517B:     "smb",
	0xEF53:     "ext4", // ext2, ext3 and ext4 share it
	0x58465342: "xfs",
	0x2FC12FC1: "zfs",
	0x9123683E: "btrfs",
	0x01021994: "tmpfs",
	0x794C7630: "overlay",
	0x65735546: "fuse",
	0x01021997: "9p",
	0x5346544E: "ntfs",
	0x4D44:     "vfat",
	0x00C36400: "ceph",
	0xF2F52010: "f2fs",
}

// linuxFSName names a Linux statfs f_type ("unknown" when it is not one of
// linuxFSMagic).
func linuxFSName(magic int64) string {
	if name, ok := linuxFSMagic[magic]; ok {
		return name
	}
	return "unknown"
}

// StatFS reports the filesystem holding path; a variable so tests stand in
// for the kernel (every filesystem type, any device numbering).
var StatFS = statFS

// IsMountPoint reports whether dir is a mount point (a bind mount in a
// container is one); a variable so tests can stand in for it.
var IsMountPoint = isMountPoint

// mountinfoPath is the kernel's mount table of this process (Linux); a
// variable so tests can give another.
var mountinfoPath = "/proc/self/mountinfo"

// isMountPoint reads /proc/self/mountinfo where there is one (a bind mount
// of a directory of the same filesystem keeps its device number, so the
// device test alone misses it), else compares dir's device with its
// parent's.
func isMountPoint(dir string) (bool, error) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false, err
	}
	if f, err := os.Open(mountinfoPath); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			// "<id> <parent> <maj:min> <root> <mount point> ..."
			fields := strings.Fields(sc.Text())
			if len(fields) >= 5 && unescapeMountinfo(fields[4]) == real {
				return true, nil
			}
		}
		if err := sc.Err(); err == nil {
			return false, nil
		}
	}
	if real == "/" {
		return true, nil
	}
	me, err := StatFS(real)
	if err != nil {
		return false, err
	}
	parent, err := StatFS(filepath.Dir(real))
	if err != nil {
		return false, err
	}
	return me.Device != parent.Device, nil
}

// unescapeMountinfo undoes the octal escapes of /proc/self/mountinfo
// (space \040, tab \011, newline \012, backslash \134).
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}
