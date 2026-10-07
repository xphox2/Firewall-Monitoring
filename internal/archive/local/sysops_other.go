//go:build !linux && !darwin

package local

import "os"

const oNoFollow = 0

func renameNoReplaceSys(string, string) error { return errNoReplaceUnsupported }

func openUncachedSys(p string) (*os.File, bool, error) {
	f, err := os.Open(p) // #nosec G304 -- an object below the archive's directory
	return f, false, err
}

func deviceOfSys(string) (uint64, error) { return 0, nil }
