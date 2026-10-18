package bootstrapcheck

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// These are the operator-approved local observer-profile limits, not an enabled
// issuer policy or runtime default. No existing CLI/runner consumes this package.
const (
	observerMaxValidity = 45 * time.Minute
	observerMaxBackdate = time.Minute
	observerMaxHandoff  = 5 * time.Minute
	observerMaxPolling  = 30 * time.Minute
)

// ObserverInputs must be independently bound to the plan and reviewed policy.
// The nonce is generated before rendering/plan hashing, not chosen from a CSR.
// This checker neither creates a nonce nor proves its entropy or uniqueness.
// Predecessor fields must already be verified against authoritative durable
// outcomes: their presence/digest shape alone is not outcome verification or
// authenticated issuer-request provenance.
type ObserverInputs struct {
	Expected                 Binding
	OperationNonce           string
	CADER                    []byte
	PredecessorStage         int
	PredecessorReceiptDigest string
}

// ObserverBudget is independent stage/issuer evidence, not untrusted certificate
// metadata. IssuedAt requires authenticated issuer provenance before any future
// runtime integration. WrapperOverhead must cover the actual selected wrapper;
// a caller-provided number alone does not prove its completeness.
type ObserverBudget struct {
	IssuedAt        time.Time
	PollTimeout     time.Duration
	WrapperOverhead time.Duration
}

func observerConstraints(inputs ObserverInputs) (Constraints, error) {
	decoded, err := hex.DecodeString(inputs.OperationNonce)
	if err != nil || len(decoded) != 16 || len(inputs.OperationNonce) != 32 || inputs.OperationNonce != strings.ToLower(inputs.OperationNonce) || !validBinding(inputs.Expected) {
		return Constraints{}, errors.New("independent observer identity required")
	}
	if !isDigest(inputs.PredecessorReceiptDigest) ||
		inputs.Expected.Role == "network-observer" && (inputs.PredecessorStage != 4 || inputs.PredecessorReceiptDigest != inputs.Expected.Stage4ReceiptDigest) ||
		inputs.Expected.Role == "runtime-observer" && inputs.PredecessorStage != 5 {
		return Constraints{}, errors.New("role-specific predecessor evidence required")
	}
	return Constraints{
		Expected:    inputs.Expected,
		CommonName:  "ok147:" + inputs.OperationNonce + ":" + inputs.Expected.Role,
		CADER:       inputs.CADER,
		MaxValidity: observerMaxValidity,
		ClockSkew:   observerMaxBackdate,
	}, nil
}

// ValidateObserverRequest fixes the subject/lifetime constraints for the two
// observer roles. It does not approve RBAC, Pod discovery, exec or issuance.
func ValidateObserverRequest(request Request, inputs ObserverInputs) error {
	constraints, err := observerConstraints(inputs)
	if err != nil {
		return err
	}
	return ValidateRequest(request, constraints)
}

// ValidateObserverPollingBudget rejects impossible request budgets before any
// future issuance claim. Actual remaining validity is checked at stage entry.
func ValidateObserverPollingBudget(poll, overhead time.Duration) error {
	if poll <= 0 || poll > observerMaxPolling || overhead <= 0 || overhead >= observerMaxValidity-poll {
		return errors.New("observer polling or wrapper budget rejected")
	}
	return nil
}

// ValidateObserverStageEntry checks certificate consistency at authenticated
// issuance time and at the proposed stage entry. It does not execute a stage,
// grant rights, persist a claim or return a reusable authorization token.
// Pod discovery/probing must still be platform-mediated; raw Pod LIST/exec and
// installer credentials are not made acceptable by passing this function.
func ValidateObserverStageEntry(request Request, result Result, inputs ObserverInputs, budget ObserverBudget, now time.Time) error {
	constraints, err := observerConstraints(inputs)
	if err != nil {
		return err
	}
	if budget.IssuedAt.IsZero() || now.IsZero() || budget.IssuedAt.After(now) || now.Sub(budget.IssuedAt) > observerMaxHandoff || ValidateObserverPollingBudget(budget.PollTimeout, budget.WrapperOverhead) != nil {
		return errors.New("observer stage handoff or budget rejected")
	}
	// Backdating is measured at issuance, not at stage entry several minutes
	// later. Both timestamps are independent expectations, not certificate claims.
	if err := ValidateResult(request, result, constraints, budget.IssuedAt); err != nil {
		return err
	}
	if err := validateResultAt(request, result, constraints, now, false); err != nil {
		return err
	}
	cert, _ := x509.ParseCertificate(result.CertificateDER)
	remaining := cert.NotAfter.Sub(now)
	// Subtract instead of summing arbitrary durations to avoid overflow. Equality
	// is denied because NotAfter is exclusive at the end of the required window.
	if remaining <= budget.PollTimeout || budget.WrapperOverhead >= remaining-budget.PollTimeout {
		return errors.New("observer certificate does not cover full stage window")
	}
	return nil
}
