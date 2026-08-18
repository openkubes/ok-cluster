package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	PostRuntimeExecutionBundleFormat         = "ok147-post-runtime-execution-bundle/v1"
	PostRuntimeExecutionBundleReceiptFormat  = "ok147-post-runtime-execution-bundle-receipt/v1"
	postRuntimeExecutionBundleIndexName      = "bundle-index.json"
	postRuntimeExecutionManifestRelativePath = "activation/post-runtime-manifest.json"
	maximumPostRuntimeExecutionBundleBytes   = 900 * 1024
	maximumPostRuntimeExecutionBundleFiles   = 40
)

var postRuntimeExecutionBundleFiles = []string{
	"activation/post-runtime-manifest.json",
	"credentials/authorization-ca.crt",
	"credentials/authorization-token",
	"credentials/gitops-ca.crt",
	"credentials/gitops-token",
	"credentials/ledger-ca.crt",
	"credentials/ledger-token",
	"credentials/management-ca.crt",
	"credentials/management-token",
	"credentials/workload-ca.crt",
	"credentials/workload-token",
	"input/01-provider-prerequisites.json",
	"input/02-cluster-lifecycle.json",
	"input/03-lifecycle-observation.json",
	"input/04-enablement.json",
	"input/05-network-observation.json",
	"input/06-runtime-binding.json",
	"input/07-target-access.json",
	"input/aggregate-profile.json",
	"input/authorization-authority.pub",
	"input/network-profile.json",
	"input/platform-applications.yaml",
	"input/platform-capability.json",
	"input/platform-profile.json",
	"input/receipt-prefix.json",
	"input/runtime-binding-receipt.json",
	"input/runtime-binding.json",
	"input/stage-authority.pub",
	"input/staged-plan.json",
	"input/target-access.yaml",
	"input/target-credential-grant.json",
	"input/target-credential-policy.json",
	"input/target-registration.yaml",
	"input/workload-authority.json",
}

type postRuntimeExecutionBundleIndexFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type postRuntimeExecutionBundleIndex struct {
	Format         string                                `json:"format"`
	ManifestDigest string                                `json:"manifestDigest"`
	Files          []postRuntimeExecutionBundleIndexFile `json:"files"`
}

type PostRuntimeExecutionBundleMaterializationConfig struct {
	SourceDirectory      string
	DestinationDirectory string
	ExpectedBundleDigest string
}

type PostRuntimeExecutionBundleReceipt struct {
	Format                    string `json:"format"`
	State                     string `json:"state"`
	BundleDigest              string `json:"bundleDigest,omitempty"`
	ManifestDigest            string `json:"manifestDigest,omitempty"`
	FileCount                 int    `json:"fileCount,omitempty"`
	TotalBytes                int    `json:"totalBytes,omitempty"`
	KubernetesMutationAllowed bool   `json:"kubernetesMutationAllowed"`
}

// MaterializePostRuntimeExecutionBundle converts one immutable projected
// Secret into regular 0600 files below one new 0700 workspace. It permits the
// Kubernetes projection symlinks only while resolving files below the bound
// source root; no link is copied into the workspace.
func MaterializePostRuntimeExecutionBundle(config PostRuntimeExecutionBundleMaterializationConfig) (PostRuntimeExecutionBundleReceipt, error) {
	receipt := PostRuntimeExecutionBundleReceipt{
		Format: PostRuntimeExecutionBundleReceiptFormat, State: "STOPPED_ZERO_WRITE",
		KubernetesMutationAllowed: false,
	}
	if !absoluteCleanDirectory(config.SourceDirectory) || !absoluteCleanDirectory(config.DestinationDirectory) ||
		!stageReceiptPrefixDigestPattern.MatchString(config.ExpectedBundleDigest) || directoriesOverlap(config.SourceDirectory, config.DestinationDirectory) {
		return receipt, errors.New("post-runtime bundle materialization configuration is invalid")
	}
	if _, err := os.Lstat(config.DestinationDirectory); err == nil || !errors.Is(err, os.ErrNotExist) {
		return receipt, errors.New("post-runtime bundle destination must be absent")
	}
	indexRaw, err := readProjectedPostRuntimeBundleFile(config.SourceDirectory, postRuntimeExecutionBundleIndexName, 64*1024)
	if err != nil {
		return receipt, errors.New("read post-runtime bundle index")
	}
	var index postRuntimeExecutionBundleIndex
	if err := jsonstrict.Decode(indexRaw, &index); err != nil || index.Format != PostRuntimeExecutionBundleFormat ||
		!stageReceiptPrefixDigestPattern.MatchString(index.ManifestDigest) {
		return receipt, errors.New("post-runtime bundle index is invalid")
	}
	indexDigest, err := canonicalPostRuntimeExecutionBundleIndexDigest(index)
	if err != nil || indexDigest != config.ExpectedBundleDigest {
		return receipt, errors.New("post-runtime bundle index differs from expected identity")
	}
	receipt.BundleDigest, receipt.ManifestDigest = indexDigest, index.ManifestDigest
	if err := validatePostRuntimeExecutionBundleFiles(index.Files); err != nil {
		return receipt, err
	}

	contents := make(map[string][]byte, len(index.Files))
	for _, file := range index.Files {
		raw, err := readProjectedPostRuntimeBundleFile(config.SourceDirectory, file.Path, maximumPostRuntimeExecutionBundleBytes)
		if err != nil || digest.SHA256(raw) != file.Digest {
			return receipt, errors.New("post-runtime bundle file differs from bound identity")
		}
		receipt.TotalBytes += len(raw)
		if receipt.TotalBytes > maximumPostRuntimeExecutionBundleBytes {
			return receipt, errors.New("post-runtime bundle exceeds size limit")
		}
		contents[file.Path] = raw
	}

	parentInfo, err := os.Lstat(filepath.Dir(config.DestinationDirectory))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return receipt, errors.New("post-runtime bundle destination parent is invalid")
	}
	if err := os.Mkdir(config.DestinationDirectory, 0o700); err != nil {
		return receipt, errors.New("create post-runtime bundle destination")
	}
	receipt.State = "STOPPED_PARTIAL_OR_UNKNOWN"
	for _, directory := range []string{"activation", "credentials", "input", "work", "work/authorizations", "work/receipts"} {
		if err := os.Mkdir(filepath.Join(config.DestinationDirectory, directory), 0o700); err != nil {
			return receipt, errors.New("create post-runtime bundle directory")
		}
	}
	for _, file := range index.Files {
		if err := writeExclusivePostRuntimeBundleFile(filepath.Join(config.DestinationDirectory, file.Path), contents[file.Path]); err != nil {
			return receipt, err
		}
	}
	manifestPath := filepath.Join(config.DestinationDirectory, postRuntimeExecutionManifestRelativePath)
	_, manifestDigest, err := loadPostRuntimeExecutionManifest(manifestPath)
	if err != nil || manifestDigest != index.ManifestDigest {
		return receipt, errors.New("materialized post-runtime manifest differs from bundle identity")
	}
	receipt.State, receipt.FileCount = "MATERIALIZED_VERIFIED", len(index.Files)
	return receipt, nil
}

func canonicalPostRuntimeExecutionBundleIndexDigest(index postRuntimeExecutionBundleIndex) (string, error) {
	raw, err := json.Marshal(index)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}

func validatePostRuntimeExecutionBundleFiles(files []postRuntimeExecutionBundleIndexFile) error {
	if len(files) != len(postRuntimeExecutionBundleFiles) || len(files) > maximumPostRuntimeExecutionBundleFiles {
		return errors.New("post-runtime bundle file set is incomplete")
	}
	want := append([]string(nil), postRuntimeExecutionBundleFiles...)
	sort.Strings(want)
	for index, file := range files {
		if file.Path != want[index] || !stageReceiptPrefixDigestPattern.MatchString(file.Digest) {
			return errors.New("post-runtime bundle file set differs from schema")
		}
	}
	return nil
}

func readProjectedPostRuntimeBundleFile(root, relative string, maximum int64) ([]byte, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..") {
		return nil, errors.New("projected post-runtime path is invalid")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("projected post-runtime root is invalid")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("resolve projected post-runtime root")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, relative))
	if err != nil {
		return nil, errors.New("resolve projected post-runtime file")
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, errors.New("projected post-runtime file escapes source")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, errors.New("open projected post-runtime file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("projected post-runtime file metadata is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, errors.New("read bounded projected post-runtime file")
	}
	return raw, nil
}

func writeExclusivePostRuntimeBundleFile(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create exclusive post-runtime bundle file")
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return errors.New("write post-runtime bundle file")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync post-runtime bundle file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close post-runtime bundle file")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(raw)) {
		return errors.New("post-runtime bundle file metadata differs")
	}
	stored, err := readBoundedRegular(path, int64(len(raw)))
	if err != nil || !bytes.Equal(stored, raw) {
		return errors.New("post-runtime bundle file differs after write")
	}
	return nil
}

func absoluteCleanDirectory(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) != string(filepath.Separator)
}

func directoriesOverlap(first, second string) bool {
	for _, pair := range [][2]string{{first, second}, {second, first}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
			return true
		}
	}
	return false
}
