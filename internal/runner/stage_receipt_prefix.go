package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	StageReceiptPrefixFormat       = "ok147-stage-receipt-prefix/v1"
	maximumStageReceiptPrefixBytes = 16 * 1024
	maximumStageReceiptPrefixItems = 12
)

var stageReceiptPrefixDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type stageReceiptPrefixDocument struct {
	Format   string                    `json:"format"`
	Receipts []stageReceiptPrefixEntry `json:"receipts"`
}

type stageReceiptPrefixEntry struct {
	File   string `json:"file"`
	Digest string `json:"digest"`
}

// LoadStageReceiptPrefix converts one digest-bound strict manifest into the
// explicit ordered file/digest prefix consumed by LoadSubmissionStageBundle.
// Receipt content remains subject to its normal canonical chain verification.
func LoadStageReceiptPrefix(path, expectedDigest string) ([]StageReceiptSource, error) {
	if path == "" || !stageReceiptPrefixDigestPattern.MatchString(expectedDigest) {
		return nil, errors.New("stage receipt prefix path and digest are required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("inspect stage receipt prefix")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumStageReceiptPrefixBytes {
		return nil, errors.New("stage receipt prefix metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open stage receipt prefix")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumStageReceiptPrefixBytes+1))
	if err != nil || len(raw) > maximumStageReceiptPrefixBytes {
		return nil, errors.New("read bounded stage receipt prefix")
	}
	if digest.SHA256(raw) != expectedDigest {
		return nil, errors.New("stage receipt prefix digest differs from expected identity")
	}
	var document stageReceiptPrefixDocument
	if err := jsonstrict.Decode(raw, &document); err != nil {
		return nil, fmt.Errorf("decode stage receipt prefix: %w", err)
	}
	if document.Format != StageReceiptPrefixFormat {
		return nil, errors.New("stage receipt prefix format is not supported")
	}
	if document.Receipts == nil || len(document.Receipts) > maximumStageReceiptPrefixItems {
		return nil, errors.New("stage receipt prefix must contain an explicit bounded list")
	}
	root := filepath.Dir(path)
	result := make([]StageReceiptSource, 0, len(document.Receipts))
	seen := map[string]struct{}{}
	for _, item := range document.Receipts {
		if item.File == "" || filepath.Base(item.File) != item.File || item.File == "." || !stageReceiptPrefixDigestPattern.MatchString(item.Digest) {
			return nil, errors.New("stage receipt prefix item identity is invalid")
		}
		if _, duplicate := seen[item.File]; duplicate {
			return nil, errors.New("stage receipt prefix repeats a file identity")
		}
		seen[item.File] = struct{}{}
		result = append(result, StageReceiptSource{Path: filepath.Join(root, item.File), Digest: item.Digest})
	}
	return result, nil
}
