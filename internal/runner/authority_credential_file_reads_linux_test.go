//go:build linux

package runner

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func assertNoCredentialFilesOpened(t *testing.T, paths []string, open func() error) error {
	t.Helper()
	inotify, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(inotify)
	for _, path := range paths {
		watch, err := unix.InotifyAddWatch(inotify, path, unix.IN_OPEN|unix.IN_ACCESS)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.InotifyRmWatch(inotify, uint32(watch))
	}
	// Self-check each invocation so a silent observer failure cannot make an
	// unopened result look proven.
	if _, err := os.ReadFile(paths[0]); err != nil {
		t.Fatal(err)
	}
	var events [4096]byte
	n, err := unix.Read(inotify, events[:])
	if err != nil || n == 0 {
		t.Fatalf("inotify self-check missed deliberate read: n=%d err=%v", n, err)
	}
	for {
		n, err = unix.Read(inotify, events[:])
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			break
		}
		if err != nil {
			t.Fatalf("drain inotify self-check: n=%d err=%v", n, err)
		}
	}

	openErr := open()
	n, err = unix.Read(inotify, events[:])
	if err != unix.EAGAIN && err != unix.EWOULDBLOCK {
		if err != nil {
			t.Fatalf("read inotify events: n=%d err=%v", n, err)
		}
		if n > 0 {
			t.Fatalf("rejected authority opened/read watched credential file: %d inotify bytes", n)
		}
	}
	return openErr
}
