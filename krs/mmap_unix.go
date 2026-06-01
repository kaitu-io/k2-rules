//go:build !windows

package krs

import (
	"fmt"
	"os"
	"syscall"
)

// mmapReadOnly maps path read-only and returns the bytes plus an unmap closer.
// The file descriptor is closed immediately; the mapping persists until the
// closer runs. Empty files map to a nil slice with a no-op closer. The returned
// closer is NOT idempotent — call it exactly once (Open/Close owns lifecycle).
func mmapReadOnly(path string) (data []byte, closeFn func() error, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	n := fi.Size()
	if n == 0 {
		return nil, func() error { return nil }, nil
	}
	if n > 1<<31-1 {
		return nil, nil, fmt.Errorf("krs: file too large to mmap: %d bytes", n)
	}
	data, err = syscall.Mmap(int(f.Fd()), 0, int(n), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, fmt.Errorf("krs: mmap %s: %w", path, err)
	}
	return data, func() error { return syscall.Munmap(data) }, nil
}
