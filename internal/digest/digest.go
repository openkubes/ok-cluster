// Package digest provides the content identities shared by executor packages.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256 returns the lowercase sha256:<hex> identity of data.
func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
