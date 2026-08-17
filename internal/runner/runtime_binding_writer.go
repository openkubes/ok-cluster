package runner

import (
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const RuntimeBindingPersistenceReceiptFormat = "ok147-runtime-binding-persistence-receipt/v1"

type RuntimeBindingPersistenceReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	PrivateMaterialDigest     string `json:"privateMaterialDigest"`
	FileSize                  int    `json:"fileSize,omitempty"`
	FileMode                  string `json:"fileMode,omitempty"`
	KubernetesMutationAllowed bool   `json:"kubernetesMutationAllowed"`
}

type RuntimeBindingWriter struct {
	mu       sync.Mutex
	used     bool
	material VerifiedRuntimeBindingMaterial
	path     string
}

// OpenRuntimeBindingWriter validates one absolute path below an existing
// private directory. It performs no write.
func OpenRuntimeBindingWriter(material VerifiedRuntimeBindingMaterial, path string) (*RuntimeBindingWriter, error) {
	if err := verifyRuntimeBindingMaterial(material); err != nil {
		return nil, err
	}
	if err := validateRuntimeBindingOutputPath(path); err != nil {
		return nil, err
	}
	return &RuntimeBindingWriter{material: material, path: path}, nil
}

func validateRuntimeBindingOutputPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return errors.New("runtime binding output path is invalid")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("runtime binding output directory is not private")
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("runtime binding output must be absent")
	}
	return nil
}

// Write creates exactly one 0600 file with O_EXCL, syncs it, and re-verifies
// the bytes. It has no overwrite, retry, rename, cleanup or delete path.
func (writer *RuntimeBindingWriter) Write() (RuntimeBindingPersistenceReceipt, error) {
	receipt := RuntimeBindingPersistenceReceipt{Format: RuntimeBindingPersistenceReceiptFormat, State: "PREWRITE", KubernetesMutationAllowed: false}
	if writer == nil {
		return receipt, errors.New("runtime binding writer is required")
	}
	writer.mu.Lock()
	if writer.used {
		writer.mu.Unlock()
		return receipt, errors.New("runtime binding writer is single-use")
	}
	writer.used = true
	writer.mu.Unlock()
	raw, err := writer.material.Bytes()
	if err != nil {
		return receipt, err
	}
	receipt.PrivateMaterialDigest = digest.SHA256(raw)
	file, err := os.OpenFile(writer.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		receipt.State = "STOPPED_ZERO_WRITE"
		return receipt, errors.New("create exclusive runtime binding output")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return receipt, errors.New("write private runtime binding")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return receipt, errors.New("sync private runtime binding")
	}
	if err := file.Close(); err != nil {
		return receipt, errors.New("close private runtime binding")
	}
	info, err := os.Lstat(writer.path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(raw)) {
		return receipt, errors.New("private runtime binding metadata differs after write")
	}
	stored, err := readBoundedRegular(writer.path, int64(len(raw)))
	if err != nil || digest.SHA256(stored) != receipt.PrivateMaterialDigest {
		return receipt, errors.New("private runtime binding differs after write")
	}
	receipt.State, receipt.FileSize, receipt.FileMode = "WRITTEN_VERIFIED", len(raw), "0600"
	return receipt, nil
}
