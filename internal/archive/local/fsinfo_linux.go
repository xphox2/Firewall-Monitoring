//go:build linux

package local

import (
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
	name := linuxFSName(int64(sf.Type)) // #nosec G115 -- f_type is a magic number, compared only
	bsize := uint64(sf.Bsize)           // #nosec G115 -- a block size is positive
	return FSInfo{Type: name, Device: uint64(st.Dev), FreeBytes: sf.Bavail * bsize, TotalBytes: sf.Blocks * bsize}, nil
}
