package stageauthority

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const MaterializationReceiptFormat = "ok147-bounded-stage-authority-materialization-receipt/v1"

var materializedFiles = []struct {
	name    string
	maximum int64
}{
	{name: "policy.json", maximum: maximumPolicyBytes},
	{name: "authority.key", maximum: maximumCredentialBytes},
	{name: "client-token", maximum: maximumCredentialBytes},
	{name: "tls.crt", maximum: 128 * 1024},
	{name: "tls.key", maximum: 128 * 1024},
}

type MaterializationConfig struct {
	SourceDirectory      string
	DestinationDirectory string
	StateDirectory       string
	ExpectedPolicyDigest string
	ExpectedKeyID        string
}

type MaterializationReceipt struct {
	Format            string `json:"format"`
	State             string `json:"state"`
	PolicyDigest      string `json:"policyDigest,omitempty"`
	KeyID             string `json:"keyId,omitempty"`
	TLSIdentityDigest string `json:"tlsIdentityDigest,omitempty"`
	FileCount         int    `json:"fileCount,omitempty"`
	FileMode          string `json:"fileMode,omitempty"`
	MutationAllowed   bool   `json:"mutationAllowed"`
}

// Materialize copies exactly five projected Secret entries into a private
// empty directory as regular 0600 files. It preserves partial state and never
// overwrites or cleans up a destination after the first write.
func Materialize(config MaterializationConfig) (MaterializationReceipt, error) {
	receipt := MaterializationReceipt{Format: MaterializationReceiptFormat, State: "PREWRITE", MutationAllowed: false}
	if !digestPattern.MatchString(config.ExpectedPolicyDigest) || !digestPattern.MatchString(config.ExpectedKeyID) ||
		!safeAbsoluteDirectory(config.SourceDirectory, false) || !safeAbsolutePath(config.DestinationDirectory) || !safeAbsolutePath(config.StateDirectory) ||
		directoriesOverlap(config.SourceDirectory, config.DestinationDirectory) || directoriesOverlap(config.SourceDirectory, config.StateDirectory) ||
		directoriesOverlap(config.DestinationDirectory, config.StateDirectory) {
		return receipt, errors.New("bounded stage authority materialization binding is invalid")
	}
	if err := ensurePrivateDirectory(config.DestinationDirectory, true); err != nil {
		return receipt, errors.New("bounded stage authority destination is not private")
	}
	if err := ensurePrivateDirectory(config.StateDirectory, false); err != nil {
		return receipt, errors.New("bounded stage authority state directory is not private")
	}
	entries, err := os.ReadDir(config.DestinationDirectory)
	if err != nil || len(entries) != 0 {
		return receipt, errors.New("bounded stage authority destination is not empty")
	}
	files := make(map[string][]byte, len(materializedFiles))
	for _, expected := range materializedFiles {
		raw, err := readProjectedFile(config.SourceDirectory, expected.name, expected.maximum)
		if err != nil {
			return receipt, errors.New("read bounded stage authority projected material")
		}
		files[expected.name] = raw
	}
	_, policyDigest, err := verifyPolicy(files["policy.json"])
	if err != nil || policyDigest != config.ExpectedPolicyDigest {
		return receipt, errors.New("bounded stage authority projected policy differs")
	}
	_, keyID, err := parsePrivateKey(files["authority.key"])
	if err != nil || keyID != config.ExpectedKeyID {
		return receipt, errors.New("bounded stage authority projected key differs")
	}
	token := strings.TrimSuffix(string(files["client-token"]), "\n")
	if !validBearerToken([]byte(token)) {
		return receipt, errors.New("bounded stage authority projected token is invalid")
	}
	certificate, err := tls.X509KeyPair(files["tls.crt"], files["tls.key"])
	if err != nil || len(certificate.Certificate) == 0 {
		return receipt, errors.New("bounded stage authority projected TLS identity is invalid")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	for _, expected := range materializedFiles {
		destination := filepath.Join(config.DestinationDirectory, expected.name)
		file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return receipt, errors.New("create bounded stage authority private material")
		}
		if _, err := file.Write(files[expected.name]); err != nil {
			_ = file.Close()
			return receipt, errors.New("write bounded stage authority private material")
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return receipt, errors.New("sync bounded stage authority private material")
		}
		if err := file.Close(); err != nil {
			return receipt, errors.New("close bounded stage authority private material")
		}
	}
	for _, expected := range materializedFiles {
		info, err := os.Lstat(filepath.Join(config.DestinationDirectory, expected.name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(files[expected.name])) {
			return receipt, errors.New("bounded stage authority private material differs after write")
		}
	}
	receipt.State, receipt.PolicyDigest, receipt.KeyID = "WRITTEN_VERIFIED", policyDigest, keyID
	receipt.TLSIdentityDigest = digestBytes(certificate.Certificate[0])
	receipt.FileCount, receipt.FileMode = len(materializedFiles), "0600"
	return receipt, nil
}

func safeAbsoluteDirectory(path string, private bool) bool {
	if !safeAbsolutePath(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && (!private || info.Mode().Perm()&0o077 == 0)
}

func safeAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(os.PathSeparator)
}

func ensurePrivateDirectory(path string, requireEmpty bool) error {
	if !safeAbsolutePath(path) {
		return errors.New("private directory path is invalid")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		parentInfo, parentErr := os.Lstat(filepath.Dir(path))
		if parentErr != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("private directory parent is invalid")
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("private directory metadata is invalid")
	}
	if requireEmpty {
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) != 0 {
			return errors.New("private directory is not empty")
		}
	}
	return nil
}

func directoriesOverlap(left, right string) bool {
	separator := string(os.PathSeparator)
	return left == right || strings.HasPrefix(left+separator, right+separator) || strings.HasPrefix(right+separator, left+separator)
}

func readProjectedFile(root, name string, maximum int64) ([]byte, error) {
	if filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return nil, errors.New("projected file name is invalid")
	}
	path := filepath.Join(root, name)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == resolvedRoot || !strings.HasPrefix(resolved, resolvedRoot+string(os.PathSeparator)) {
		return nil, errors.New("projected file escapes source directory")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("projected file metadata is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || len(raw) > int(maximum) {
		return nil, errors.New("projected file exceeds accepted size")
	}
	return raw, nil
}

func digestBytes(raw []byte) string {
	return digest.SHA256(raw)
}
