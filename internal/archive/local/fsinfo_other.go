//go:build !linux && !darwin

package local

import "errors"

// The server ships for Linux (the container); other systems build, without
// filesystem detection.
func statFS(string) (FSInfo, error) {
	return FSInfo{}, errors.New("filesystem information is not available on this system")
}
