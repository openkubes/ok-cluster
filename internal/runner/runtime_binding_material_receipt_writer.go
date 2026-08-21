package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

// persistRuntimeBindingMaterialReceipt closes the private Stage-6 handoff.
// It verifies the already create-only material against the stage-produced
// receipt, then writes that receipt create-only as a separate 0600 file.
func persistRuntimeBindingMaterialReceipt(receipt RuntimeBindingMaterialReceipt, materialPath, receiptPath, planDigest string) error {
	if materialPath == receiptPath || validateRuntimeBindingOutputPath(receiptPath) != nil ||
		receipt.PlanDigest != planDigest || !stageReceiptPrefixDigestPattern.MatchString(planDigest) {
		return errors.New("runtime binding material receipt destination or plan is invalid")
	}
	materialRaw, err := readBoundedRegular(materialPath, maximumRuntimeBindingMaterialFileBytes)
	if err != nil {
		return errors.New("read runtime binding material for receipt persistence")
	}
	var material RuntimeBindingMaterial
	if err := jsonstrict.Decode(materialRaw, &material); err != nil {
		return errors.New("decode runtime binding material for receipt persistence")
	}
	canonical, err := canonicalRuntimeBinding(material)
	if err != nil || !bytes.Equal(canonical, materialRaw) {
		return errors.New("runtime binding material is not canonical for receipt persistence")
	}
	verified := VerifiedRuntimeBindingMaterial{
		material: material, raw: append([]byte(nil), materialRaw...), receipt: receipt, verified: true,
	}
	if err := verifyRuntimeBindingMaterial(verified); err != nil {
		return errors.New("runtime binding material receipt differs from private material")
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil || len(receiptRaw) == 0 || len(receiptRaw) > maximumRuntimeBindingMaterialFileBytes {
		return errors.New("encode runtime binding material receipt")
	}
	receiptDigest := digest.SHA256(receiptRaw)
	file, err := os.OpenFile(receiptPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create exclusive runtime binding material receipt")
	}
	if _, err := file.Write(receiptRaw); err != nil {
		file.Close()
		return errors.New("write runtime binding material receipt")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync runtime binding material receipt")
	}
	if err := file.Close(); err != nil {
		return errors.New("close runtime binding material receipt")
	}
	info, err := os.Lstat(receiptPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(receiptRaw)) {
		return errors.New("runtime binding material receipt metadata differs after write")
	}
	stored, err := readBoundedRegular(receiptPath, int64(len(receiptRaw)))
	if err != nil || !bytes.Equal(stored, receiptRaw) || digest.SHA256(stored) != receiptDigest {
		return errors.New("runtime binding material receipt differs after write")
	}
	return nil
}
