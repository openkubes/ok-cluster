package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestLoadStageReceiptPrefixAcceptsExplicitEmptyAndOrderedSources(t *testing.T) {
	root := t.TempDir()
	empty := writeStagePrefix(t, root, "empty.json", map[string]any{"format": StageReceiptPrefixFormat, "receipts": []any{}})
	loaded, err := LoadStageReceiptPrefix(empty, fileSHA(t, empty))
	if err != nil || loaded == nil || len(loaded) != 0 {
		t.Fatalf("explicit empty prefix was not retained: %#v %v", loaded, err)
	}
	one := writeStagePrefix(t, root, "one.json", map[string]any{
		"format":   StageReceiptPrefixFormat,
		"receipts": []map[string]any{{"file": "provider-receipt.json", "digest": prefixSHA("a")}},
	})
	loaded, err = LoadStageReceiptPrefix(one, fileSHA(t, one))
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Path != filepath.Join(root, "provider-receipt.json") || loaded[0].Digest != prefixSHA("a") {
		t.Fatalf("unexpected receipt prefix: %#v", loaded)
	}
}

func TestLoadStageReceiptPrefixFailsClosed(t *testing.T) {
	root := t.TempDir()
	validDocument := map[string]any{"format": StageReceiptPrefixFormat, "receipts": []any{}}
	valid := writeStagePrefix(t, root, "valid.json", validDocument)
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	tooMany := make([]map[string]any, maximumStageReceiptPrefixItems+1)
	for index := range tooMany {
		tooMany[index] = map[string]any{"file": strings.Repeat("x", index+1) + ".json", "digest": prefixSHA("a")}
	}
	tests := map[string]struct {
		path, expected string
	}{
		"wrong digest": {valid, prefixSHA("f")},
		"symlink":      {link, fileSHA(t, valid)},
		"omitted list": {writeStagePrefix(t, root, "nil.json", map[string]any{"format": StageReceiptPrefixFormat}), ""},
		"traversal": {writeStagePrefix(t, root, "traversal.json", map[string]any{
			"format": StageReceiptPrefixFormat, "receipts": []map[string]any{{"file": "../receipt.json", "digest": prefixSHA("a")}},
		}), ""},
		"duplicate": {writeStagePrefix(t, root, "duplicate.json", map[string]any{
			"format": StageReceiptPrefixFormat, "receipts": []map[string]any{{"file": "receipt.json", "digest": prefixSHA("a")}, {"file": "receipt.json", "digest": prefixSHA("b")}},
		}), ""},
		"too many": {writeStagePrefix(t, root, "many.json", map[string]any{"format": StageReceiptPrefixFormat, "receipts": tooMany}), ""},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			expected := test.expected
			if expected == "" {
				expected = fileSHA(t, test.path)
			}
			if _, err := LoadStageReceiptPrefix(test.path, expected); err == nil {
				t.Fatal("unsafe receipt prefix was accepted")
			}
		})
	}
}

func writeStagePrefix(t *testing.T, root, name string, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest.SHA256(raw)
}

func prefixSHA(value string) string { return "sha256:" + strings.Repeat(value, 64) }
