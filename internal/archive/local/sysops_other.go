//go:build !linux && !darwin

package local

import (
	"io/fs"
	"os"
)

// openLeafSys has no openat here: the root still keeps the open inside the
// archive, but a link to a file inside it is followed.
func (f *fsys) openLeafSys(p string, flag int, perm fs.FileMode) (*os.File, error) {
	r, err := f.rel(p)
	if err != nil {
		return nil, err
	}
	return f.root.OpenFile(r, flag, perm)
}

func renameNoReplaceSys(*fsys, string, string) error { return errNoReplaceUnsupported }

func openUncachedSys(f *fsys, p string) (*os.File, bool, error) {
	fh, err := f.openLeaf(p, os.O_RDONLY, 0)
	return fh, false, err
}

func deviceOfSys(string) (uint64, error) { return 0, nil }
