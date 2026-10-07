//go:build darwin

package local

import (
	"strings"

	"golang.org/x/sys/unix"
)

func statFS(path string) (FSInfo, error) {
	var sf unix.Statfs_t
	if err := unix.Statfs(path, &sf); err != nil {
		return FSInfo{}, err
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return FSInfo{}, err
	}
	name := unix.ByteSliceToString(sf.Fstypename[:])
	switch name {
	case "smbfs":
		name = "cifs"
	case "":
		name = "unknown"
	}
	bsize := uint64(sf.Bsize)
	return FSInfo{Type: strings.ToLower(name), Device: uint64(st.Dev), // #nosec G115 -- a device number, compared only
		FreeBytes: sf.Bavail * bsize, TotalBytes: sf.Blocks * bsize}, nil
}
