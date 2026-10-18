package bootstrapauthority

// ValidateRecord checks only the candidate record shape and slot consistency.
// Signature, independent evidence and time checks remain Authority obligations.
// This lets storage adapters reject arbitrary payloads without duplicating the
// authority's private record schemas or accepting old stage-ledger formats.
func ValidateRecord(kind, slot string, raw []byte) error {
	if !validDigest(slot) {
		return ErrStop
	}
	switch kind {
	case "claim":
		var record claimRecord
		if decodeRecord(raw, &record) != nil || record.Domain != "ok147-bootstrap-claim-candidate/v1" || record.SlotDigest != slot || !validDigest(record.AuthorizationDigest) || !validDigest(record.PolicyDigest) || !validDigest(record.KeyID) || record.ClaimedAt.IsZero() {
			return ErrStop
		}
	case "result":
		var record resultRecord
		if decodeRecord(raw, &record) != nil || record.Domain != "ok147-bootstrap-result-record-candidate/v1" || record.Result.SlotDigest != slot || record.ClaimDigest != record.Result.ClaimDigest || !validDigest(record.ClaimDigest) || !validDigest(record.Result.AuthorizationDigest) || !validDigest(record.Result.Result.RequestDigest) || !validDigest(record.Result.KeyID) || record.Result.Audience != ResultAudience || len(record.Result.Signature) != 64 || len(record.Result.Result.CertificateDER) == 0 || len(record.Result.Result.CertificateDER) > 65536 || record.Result.IssuedAt.IsZero() || record.CompletedAt.Before(record.Result.IssuedAt) {
			return ErrStop
		}
	default:
		return ErrStop
	}
	return nil
}
