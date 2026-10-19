//go:build !linux

package runner

import "testing"

func assertNoCredentialFilesOpened(t *testing.T, _ []string, open func() error) error {
	t.Log("file-open observation is Linux-only; sentinel and API-contact assertions remain active")
	return open()
}
