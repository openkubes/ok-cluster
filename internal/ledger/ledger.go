// Package ledger provides an atomic, local single-use boundary for verified
// grants. It records intent before any future external write and never retries
// an indeterminate operation.
package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ClaimFormat   = "ok147-grant-claim/v1"
	OutcomeFormat = "ok147-operation-receipt/v1"
)

var ErrGrantConsumed = errors.New("authorization grant is already consumed")

var (
	ErrRecordExists   = errors.New("ledger record already exists")
	ErrRecordNotFound = errors.New("ledger record not found")
)

// RecordStore is the only persistence capability required by the ledger.
// Implementations must provide atomic create-if-absent and exact-name reads.
type RecordStore interface {
	Create(context.Context, string, string, []byte) error
	Get(context.Context, string, string) ([]byte, error)
}

// Ledger stores immutable claim and outcome files below a private directory.
type Ledger struct {
	store RecordStore
}

// ClaimReceipt is written atomically before a future operation begins.
type ClaimReceipt struct {
	Format                   string `json:"format"`
	State                    string `json:"state"`
	AuthorizationDigest      string `json:"authorizationDigest"`
	GrantID                  string `json:"grantId"`
	KeyID                    string `json:"keyId"`
	Operation                string `json:"operation"`
	RequestDigest            string `json:"requestDigest"`
	ContractRevision         string `json:"contractRevision"`
	ProjectionManifestDigest string `json:"projectionManifestDigest"`
	ClaimedAt                string `json:"claimedAt"`
}

// OutcomeReceipt is a separate immutable completion record. Absence after a
// claim means STOP/INDETERMINATE, never permission to retry.
type OutcomeReceipt struct {
	Format         string `json:"format"`
	State          string `json:"state"`
	GrantID        string `json:"grantId"`
	Operation      string `json:"operation"`
	RequestDigest  string `json:"requestDigest"`
	ClaimDigest    string `json:"claimDigest"`
	Outcome        string `json:"outcome"`
	MutationState  string `json:"mutationState"`
	EvidenceDigest string `json:"evidenceDigest"`
	CompletedAt    string `json:"completedAt"`
}

// Inspection is the fail-closed restart decision for a verified grant.
type Inspection struct {
	State         string          `json:"state"`
	ClaimAllowed  bool            `json:"claimAllowed"`
	ClaimDigest   string          `json:"claimDigest,omitempty"`
	OutcomeDigest string          `json:"outcomeDigest,omitempty"`
	Outcome       *OutcomeReceipt `json:"outcome,omitempty"`
}

// Open creates or verifies a private, non-symlink ledger directory.
func Open(root string) (*Ledger, error) {
	if root == "" {
		return nil, errors.New("ledger root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve ledger root: %w", err)
	}
	if err := secureDirectory(abs); err != nil {
		return nil, err
	}
	store := &fileStore{claims: filepath.Join(abs, "claims"), outcomes: filepath.Join(abs, "outcomes")}
	if err := secureDirectory(store.claims); err != nil {
		return nil, err
	}
	if err := secureDirectory(store.outcomes); err != nil {
		return nil, err
	}
	return New(store)
}

// New constructs a ledger around a durable RecordStore.
func New(store RecordStore) (*Ledger, error) {
	if store == nil {
		return nil, errors.New("ledger record store is required")
	}
	return &Ledger{store: store}, nil
}

// Claim atomically consumes a verified grant. A second call always returns
// ErrGrantConsumed, including after a process crash.
func (ledger *Ledger) Claim(ctx context.Context, grant authorization.VerifiedGrant, at time.Time) (ClaimReceipt, error) {
	binding, err := grant.ConsumptionBinding()
	if err != nil {
		return ClaimReceipt{}, err
	}
	expires, err := time.Parse(time.RFC3339, binding.NotAfter)
	if err != nil {
		return ClaimReceipt{}, fmt.Errorf("grant expiration: %w", err)
	}
	if !at.Before(expires) {
		return ClaimReceipt{}, errors.New("grant expired before consumption")
	}
	receipt := ClaimReceipt{
		Format:                   ClaimFormat,
		State:                    "CLAIMED",
		AuthorizationDigest:      binding.AuthorizationDigest,
		GrantID:                  binding.GrantID,
		KeyID:                    binding.KeyID,
		Operation:                binding.Operation,
		RequestDigest:            binding.RequestDigest,
		ContractRevision:         binding.ContractRevision,
		ProjectionManifestDigest: binding.ProjectionManifestDigest,
		ClaimedAt:                at.UTC().Format(time.RFC3339Nano),
	}
	raw, _, err := canonicalRecord(receipt)
	if err != nil {
		return ClaimReceipt{}, err
	}
	key := recordKey(binding.GrantID)
	if err := ledger.store.Create(ctx, "claims", key, raw); err != nil {
		if errors.Is(err, ErrRecordExists) {
			return ClaimReceipt{}, ErrGrantConsumed
		}
		return ClaimReceipt{}, fmt.Errorf("write grant claim: %w", err)
	}
	return receipt, nil
}

// Complete writes one outcome. Repeating the exact completion is idempotent;
// a conflicting completion fails closed.
func (ledger *Ledger) Complete(ctx context.Context, claim ClaimReceipt, outcome, mutationState, evidenceDigest string, at time.Time) (OutcomeReceipt, error) {
	if !allowed(outcome, "SUCCEEDED", "FAILED", "STOPPED") {
		return OutcomeReceipt{}, fmt.Errorf("unsupported outcome %q", outcome)
	}
	if !allowed(mutationState, "NOT_ATTEMPTED", "ATTEMPTED", "UNKNOWN") {
		return OutcomeReceipt{}, fmt.Errorf("unsupported mutation state %q", mutationState)
	}
	if claim.Operation == "CreateCluster" && outcome == "SUCCEEDED" && mutationState != "ATTEMPTED" {
		return OutcomeReceipt{}, errors.New("successful CreateCluster outcome requires mutationState ATTEMPTED")
	}
	if !validDigest(evidenceDigest) {
		return OutcomeReceipt{}, errors.New("evidence digest is invalid")
	}
	stored, claimDigest, err := ledger.readClaim(ctx, claim.GrantID)
	if err != nil {
		return OutcomeReceipt{}, err
	}
	_, providedDigest, err := canonicalRecord(claim)
	if err != nil {
		return OutcomeReceipt{}, err
	}
	if claimDigest != providedDigest || stored != claim {
		return OutcomeReceipt{}, errors.New("provided claim differs from immutable ledger claim")
	}
	claimedAt, err := time.Parse(time.RFC3339Nano, claim.ClaimedAt)
	if err != nil || at.Before(claimedAt) {
		return OutcomeReceipt{}, errors.New("completion time precedes claim")
	}
	receipt := OutcomeReceipt{
		Format:         OutcomeFormat,
		State:          "COMPLETED",
		GrantID:        claim.GrantID,
		Operation:      claim.Operation,
		RequestDigest:  claim.RequestDigest,
		ClaimDigest:    claimDigest,
		Outcome:        outcome,
		MutationState:  mutationState,
		EvidenceDigest: evidenceDigest,
		CompletedAt:    at.UTC().Format(time.RFC3339Nano),
	}
	raw, expectedDigest, err := canonicalRecord(receipt)
	if err != nil {
		return OutcomeReceipt{}, err
	}
	key := recordKey(claim.GrantID)
	if err := ledger.store.Create(ctx, "outcomes", key, raw); err != nil {
		if !errors.Is(err, ErrRecordExists) {
			return OutcomeReceipt{}, fmt.Errorf("write operation outcome: %w", err)
		}
		existing, existingDigest, readErr := ledger.readOutcome(ctx, claim.GrantID)
		if readErr != nil {
			return OutcomeReceipt{}, readErr
		}
		if existingDigest == expectedDigest && existing == receipt {
			return existing, nil
		}
		return OutcomeReceipt{}, errors.New("conflicting operation outcome already exists")
	}
	return receipt, nil
}

// Inspect returns AVAILABLE, CLAIMED_INDETERMINATE_STOP, or COMPLETED. It never
// recommends retrying an already claimed grant.
func (ledger *Ledger) Inspect(ctx context.Context, grant authorization.VerifiedGrant) (Inspection, error) {
	binding, err := grant.ConsumptionBinding()
	if err != nil {
		return Inspection{}, err
	}
	claim, claimDigest, err := ledger.readClaim(ctx, binding.GrantID)
	if errors.Is(err, ErrRecordNotFound) {
		return Inspection{State: "AVAILABLE", ClaimAllowed: true}, nil
	}
	if err != nil {
		return Inspection{}, err
	}
	if err := matchBinding(claim, binding); err != nil {
		return Inspection{}, err
	}
	outcome, outcomeDigest, err := ledger.readOutcome(ctx, binding.GrantID)
	if errors.Is(err, ErrRecordNotFound) {
		return Inspection{State: "CLAIMED_INDETERMINATE_STOP", ClaimAllowed: false, ClaimDigest: claimDigest}, nil
	}
	if err != nil {
		return Inspection{}, err
	}
	if outcome.ClaimDigest != claimDigest || outcome.GrantID != claim.GrantID || outcome.RequestDigest != claim.RequestDigest || outcome.Operation != claim.Operation {
		return Inspection{}, errors.New("operation outcome does not match immutable claim")
	}
	return Inspection{State: "COMPLETED", ClaimAllowed: false, ClaimDigest: claimDigest, OutcomeDigest: outcomeDigest, Outcome: &outcome}, nil
}

func (ledger *Ledger) readClaim(ctx context.Context, grantID string) (ClaimReceipt, string, error) {
	var value ClaimReceipt
	raw, err := ledger.store.Get(ctx, "claims", recordKey(grantID))
	if err != nil {
		return value, "", err
	}
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return value, "", fmt.Errorf("decode grant claim: %w", err)
	}
	canonical, identity, err := canonicalRecord(value)
	if err != nil {
		return value, "", err
	}
	if !bytes.Equal(raw, canonical) {
		return value, "", errors.New("grant claim is not canonical or was modified")
	}
	return value, identity, validateClaim(value)
}

func (ledger *Ledger) readOutcome(ctx context.Context, grantID string) (OutcomeReceipt, string, error) {
	var value OutcomeReceipt
	raw, err := ledger.store.Get(ctx, "outcomes", recordKey(grantID))
	if err != nil {
		return value, "", err
	}
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return value, "", fmt.Errorf("decode operation outcome: %w", err)
	}
	canonical, identity, err := canonicalRecord(value)
	if err != nil {
		return value, "", err
	}
	if !bytes.Equal(raw, canonical) {
		return value, "", errors.New("operation outcome is not canonical or was modified")
	}
	return value, identity, validateOutcome(value)
}

func recordKey(grantID string) string {
	return digest.SHA256([]byte(grantID))[7:]
}

func canonicalRecord(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, "", err
	}
	canonical, err := contract.JCS(generic)
	if err != nil {
		return nil, "", err
	}
	return canonical, digest.SHA256(canonical), nil
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create private ledger directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("ledger path %s is not a real directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("ledger directory %s permissions are broader than 0700", path)
	}
	return nil
}

type fileStore struct {
	claims   string
	outcomes string
}

func (store *fileStore) Create(ctx context.Context, category, key string, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, directory, err := store.path(category, key)
	if err != nil {
		return err
	}
	if err := writeExclusive(path, raw, directory); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrRecordExists
		}
		return err
	}
	return nil
}

func (store *fileStore) Get(ctx context.Context, category, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, _, err := store.path(category, key)
	if err != nil {
		return nil, err
	}
	raw, err := readRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrRecordNotFound
	}
	return raw, err
}

func (store *fileStore) path(category, key string) (string, string, error) {
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) {
		return "", "", errors.New("ledger record key is invalid")
	}
	var directory string
	switch category {
	case "claims":
		directory = store.claims
	case "outcomes":
		directory = store.outcomes
	default:
		return "", "", fmt.Errorf("ledger record category %q is invalid", category)
	}
	return filepath.Join(directory, key+".json"), directory, nil
}

func writeExclusive(path string, raw []byte, directory string) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("ledger record %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("ledger record %s permissions are broader than 0600", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 1<<20))
}

func validateClaim(value ClaimReceipt) error {
	if value.Format != ClaimFormat || value.State != "CLAIMED" || value.GrantID == "" || value.Operation == "" {
		return errors.New("grant claim is incomplete")
	}
	for _, identity := range []string{value.AuthorizationDigest, value.KeyID, value.RequestDigest, value.ContractRevision, value.ProjectionManifestDigest} {
		if !validDigest(identity) {
			return errors.New("grant claim contains an invalid digest")
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, value.ClaimedAt); err != nil {
		return errors.New("grant claim has an invalid timestamp")
	}
	return nil
}

func matchBinding(claim ClaimReceipt, binding authorization.ConsumptionBinding) error {
	if claim.AuthorizationDigest != binding.AuthorizationDigest || claim.GrantID != binding.GrantID || claim.KeyID != binding.KeyID || claim.Operation != binding.Operation || claim.RequestDigest != binding.RequestDigest || claim.ContractRevision != binding.ContractRevision || claim.ProjectionManifestDigest != binding.ProjectionManifestDigest {
		return errors.New("stored grant claim differs from verified authorization")
	}
	return nil
}

func validateOutcome(value OutcomeReceipt) error {
	if value.Format != OutcomeFormat || value.State != "COMPLETED" || value.GrantID == "" || value.Operation == "" {
		return errors.New("operation outcome is incomplete")
	}
	if !allowed(value.Outcome, "SUCCEEDED", "FAILED", "STOPPED") || !allowed(value.MutationState, "NOT_ATTEMPTED", "ATTEMPTED", "UNKNOWN") {
		return errors.New("operation outcome contains an invalid state")
	}
	for _, identity := range []string{value.RequestDigest, value.ClaimDigest, value.EvidenceDigest} {
		if !validDigest(identity) {
			return errors.New("operation outcome contains an invalid digest")
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, value.CompletedAt); err != nil {
		return errors.New("operation outcome has an invalid timestamp")
	}
	if value.Operation == "CreateCluster" && value.Outcome == "SUCCEEDED" && value.MutationState != "ATTEMPTED" {
		return errors.New("successful CreateCluster outcome lacks attempted mutation state")
	}
	return nil
}

func validDigest(value string) bool {
	return regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(value)
}

func allowed(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
