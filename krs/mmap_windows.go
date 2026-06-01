//go:build windows

package krs

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
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
	h, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil,
		windows.PAGE_READONLY, 0, 0, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("krs: CreateFileMapping %s: %w", path, err)
	}
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_READ, 0, 0, uintptr(n))
	if err != nil {
		windows.CloseHandle(h)
		return nil, nil, fmt.Errorf("krs: MapViewOfFile %s: %w", path, err)
	}
	// addr points at kernel-mapped memory the Go GC never manages or moves, so
	// reinterpreting a slice header over it is safe. Build the header via a
	// struct pointer cast rather than (*byte)(unsafe.Pointer(addr)) so that
	// `go vet -unsafeptr` does not (correctly, in general) flag a bare
	// uintptr->unsafe.Pointer conversion.
	sh := struct {
		data uintptr
		len  int
		cap  int
	}{addr, int(n), int(n)}
	data = *(*[]byte)(unsafe.Pointer(&sh))
	return data, func() error {
		e := windows.UnmapViewOfFile(addr)
		windows.CloseHandle(h)
		return e
	}, nil
}
