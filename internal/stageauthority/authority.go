// Package stageauthority implements a bounded, single-use stage grant issuer.
// It is an external policy authority for the runner, not a lifecycle controller.
package stageauthority

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/runner"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

const (
	PolicyFormat  = "ok147-bounded-stage-authority-policy/v1"
	ReceiptFormat = "ok147-bounded-stage-authority-receipt/v1"

	requestMediaType  = "application/vnd.openkubes.stage-authorization-request+json"
	responseMediaType = "application/vnd.openkubes.stage-authorization+json"
	requestPath       = "/v1/stage-authorizations"

	maximumPolicyBytes     = 128 * 1024
	maximumRequestBytes    = 128 * 1024
	maximumCredentialBytes = 8 * 1024
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,127}$`)
)

// StagePolicy is the exact immutable stage shape the authority may sign.
type StagePolicy struct {
	StageID     string   `json:"stageId"`
	StageOrder  int      `json:"stageOrder"`
	StageDigest string   `json:"stageDigest"`
	Operation   string   `json:"operation"`
	Authority   string   `json:"authority"`
	Requires    []string `json:"requires"`
}

// Policy binds grant issuance to one plan and one R/E/P/Fixture identity.
// It carries no credential, key, endpoint or authorization decision.
type Policy struct {
	Format             string            `json:"format"`
	PlanDigest         string            `json:"planDigest"`
	ContractIdentity   contract.Identity `json:"contractIdentity"`
	ContractRevision   string            `json:"contractRevision"`
	EnablementRevision string            `json:"enablementRevision"`
	PlatformRevision   string            `json:"platformRevision"`
	ExecutionFixture   string            `json:"executionFixture"`
	Stages             []StagePolicy     `json:"stages"`
}

// Config contains private runtime material. Files are read once when the
// authority opens and are never exposed through HTTP responses or receipts.
type Config struct {
	PolicyPath           string
	ExpectedPolicyDigest string
	PrivateKeyPath       string
	TokenFile            string
	StateDirectory       string
	GrantValidFor        time.Duration
	Clock                func() time.Time
}

// Receipt is safe to record publicly after opening the authority.
type Receipt struct {
	Format          string `json:"format"`
	State           string `json:"state"`
	PolicyDigest    string `json:"policyDigest"`
	KeyID           string `json:"keyId"`
	StageCount      int    `json:"stageCount"`
	GrantValidFor   string `json:"grantValidFor"`
	SingleUseLedger string `json:"singleUseLedger"`
	MutationAllowed bool   `json:"mutationAllowed"`
}

type PolicyReceipt struct {
	Format          string `json:"format"`
	State           string `json:"state"`
	PolicyDigest    string `json:"policyDigest"`
	PlanDigest      string `json:"planDigest"`
	StageCount      int    `json:"stageCount"`
	MutationAllowed bool   `json:"mutationAllowed"`
}

type Authority struct {
	policy        Policy
	policyDigest  string
	stages        map[string]StagePolicy
	privateKey    ed25519.PrivateKey
	keyID         string
	token         []byte
	stateDir      string
	grantValidFor time.Duration
	clock         func() time.Time
}

type stageEnvelope struct {
	Format    string                     `json:"format"`
	Payload   authorization.StagePayload `json:"payload"`
	Signature stageSignature             `json:"signature"`
}

type stageSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyId"`
	Value     string `json:"value"`
}

type claimRecord struct {
	Format        string `json:"format"`
	RequestDigest string `json:"requestDigest"`
	PolicyDigest  string `json:"policyDigest"`
	ClaimedAt     string `json:"claimedAt"`
}

// FromPlan derives the authority allowlist solely from a verified staged plan.
// It never accepts caller-authored stage fields, and it includes only stages
// that the plan itself classifies as mutating.
func FromPlan(plan stageplan.Binding) ([]byte, PolicyReceipt, error) {
	if !digestPattern.MatchString(plan.PlanDigest) || len(plan.Stages) == 0 {
		return nil, PolicyReceipt{}, errors.New("verified staged plan is required")
	}
	policy := Policy{
		Format: PolicyFormat, PlanDigest: plan.PlanDigest, ContractIdentity: plan.ContractIdentity,
		ContractRevision: plan.IntentRevision, EnablementRevision: plan.EnablementRevision,
		PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
	}
	for _, candidate := range plan.Stages {
		stage, stageDigest, err := plan.Stage(candidate.ID)
		if err != nil {
			return nil, PolicyReceipt{}, errors.New("reverify staged plan while deriving authority policy")
		}
		if !stageplan.IsMutating(stage) {
			continue
		}
		policy.Stages = append(policy.Stages, StagePolicy{
			StageID: stage.ID, StageOrder: stage.Order, StageDigest: stageDigest,
			Operation: stage.GrantOperation, Authority: stage.Authority, Requires: append([]string{}, stage.Requires...),
		})
	}
	if len(policy.Stages) == 0 {
		return nil, PolicyReceipt{}, errors.New("verified staged plan contains no mutating stage")
	}
	raw, err := canonicalJSON(policy)
	if err != nil {
		return nil, PolicyReceipt{}, err
	}
	verified, policyDigest, err := verifyPolicy(raw)
	if err != nil || len(verified.Stages) != len(policy.Stages) {
		return nil, PolicyReceipt{}, errors.New("verify derived bounded stage authority policy")
	}
	receipt := PolicyReceipt{
		Format: "ok147-bounded-stage-authority-policy-receipt/v1", State: "VERIFIED",
		PolicyDigest: policyDigest, PlanDigest: plan.PlanDigest, StageCount: len(policy.Stages), MutationAllowed: false,
	}
	return raw, receipt, nil
}

// Open validates all policy and private runtime material without contacting a
// cluster or starting a listener.
func Open(config Config) (*Authority, Receipt, error) {
	if config.Clock == nil || config.GrantValidFor < time.Minute || config.GrantValidFor > authorization.MaximumWindow {
		return nil, Receipt{}, errors.New("bounded stage authority timing is invalid")
	}
	policyRaw, err := readPrivateRegular(config.PolicyPath, maximumPolicyBytes, false)
	if err != nil {
		return nil, Receipt{}, errors.New("read bounded stage authority policy")
	}
	policy, policyDigest, err := verifyPolicy(policyRaw)
	if err != nil {
		return nil, Receipt{}, err
	}
	if !digestPattern.MatchString(config.ExpectedPolicyDigest) || policyDigest != config.ExpectedPolicyDigest {
		return nil, Receipt{}, errors.New("bounded stage authority policy differs from expected identity")
	}
	privateRaw, err := readPrivateRegular(config.PrivateKeyPath, maximumCredentialBytes, true)
	if err != nil {
		return nil, Receipt{}, errors.New("read bounded stage authority private key")
	}
	privateKey, keyID, err := parsePrivateKey(privateRaw)
	if err != nil {
		return nil, Receipt{}, err
	}
	tokenRaw, err := readPrivateRegular(config.TokenFile, maximumCredentialBytes, true)
	if err != nil {
		return nil, Receipt{}, errors.New("read bounded stage authority bearer token")
	}
	token := bytes.TrimSuffix(tokenRaw, []byte("\n"))
	if !validBearerToken(token) {
		return nil, Receipt{}, errors.New("bounded stage authority bearer token is invalid")
	}
	stateInfo, err := os.Lstat(config.StateDirectory)
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 || stateInfo.Mode().Perm()&0o077 != 0 ||
		!filepath.IsAbs(config.StateDirectory) || filepath.Clean(config.StateDirectory) != config.StateDirectory {
		return nil, Receipt{}, errors.New("bounded stage authority state directory is not private")
	}
	stages := make(map[string]StagePolicy, len(policy.Stages))
	for _, stage := range policy.Stages {
		stages[stage.StageID] = stage
	}
	authority := &Authority{
		policy: policy, policyDigest: policyDigest, stages: stages,
		privateKey: privateKey, keyID: keyID, token: append([]byte(nil), token...),
		stateDir: config.StateDirectory, grantValidFor: config.GrantValidFor, clock: config.Clock,
	}
	receipt := Receipt{
		Format: ReceiptFormat, State: "VERIFIED", PolicyDigest: policyDigest, KeyID: keyID,
		StageCount: len(policy.Stages), GrantValidFor: config.GrantValidFor.String(),
		SingleUseLedger: "create-only-local/v1", MutationAllowed: false,
	}
	return authority, receipt, nil
}

func validBearerToken(token []byte) bool {
	if len(token) < 32 || len(token) > maximumCredentialBytes || len(token) != len(bytes.TrimSpace(token)) || bytes.ContainsAny(token, "\r\n") {
		return false
	}
	for _, value := range token {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("._~-", rune(value)) {
			continue
		}
		return false
	}
	return true
}

// ServeHTTP accepts only the exact normal stage-authorization protocol. It
// intentionally rejects recovery media types; those require separate policy.
func (authority *Authority) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if authority == nil || authority.clock == nil || len(authority.privateKey) != ed25519.PrivateKeySize {
		http.Error(response, "authority unavailable", http.StatusServiceUnavailable)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != requestPath || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		http.Error(response, "request not accepted", http.StatusNotFound)
		return
	}
	if request.Header.Get("Content-Type") != requestMediaType || request.Header.Get("Accept") != responseMediaType {
		http.Error(response, "media type not accepted", http.StatusUnsupportedMediaType)
		return
	}
	presented := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	if presented == request.Header.Get("Authorization") || subtle.ConstantTimeCompare([]byte(presented), authority.token) != 1 {
		http.Error(response, "request not authorized", http.StatusUnauthorized)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maximumRequestBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumRequestBytes {
		http.Error(response, "request not accepted", http.StatusBadRequest)
		return
	}
	var document runner.StageAuthorizationRequest
	if err := jsonstrict.Decode(raw, &document); err != nil {
		http.Error(response, "request not accepted", http.StatusBadRequest)
		return
	}
	canonical, err := document.Bytes()
	if err != nil || !bytes.Equal(canonical, raw) || authority.verifyRequest(document) != nil {
		http.Error(response, "request not permitted", http.StatusForbidden)
		return
	}
	now := authority.clock().UTC().Truncate(time.Second)
	if now.IsZero() {
		http.Error(response, "authority unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := authority.claim(document.RequestDigest, now); err != nil {
		http.Error(response, "request already consumed", http.StatusConflict)
		return
	}
	payload := authority.payload(document, now)
	signed, err := authorization.StageSigningBytes(payload)
	if err != nil {
		http.Error(response, "authority unavailable", http.StatusInternalServerError)
		return
	}
	envelope := stageEnvelope{
		Format: authorization.StageFormat, Payload: payload,
		Signature: stageSignature{Algorithm: "Ed25519", KeyID: authority.keyID, Value: base64.StdEncoding.EncodeToString(ed25519.Sign(authority.privateKey, signed))},
	}
	responseRaw, err := json.Marshal(envelope)
	if err != nil {
		http.Error(response, "authority unavailable", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", responseMediaType)
	response.WriteHeader(http.StatusCreated)
	_, _ = response.Write(responseRaw)
}

func (authority *Authority) verifyRequest(request runner.StageAuthorizationRequest) error {
	if request.PlanDigest != authority.policy.PlanDigest || request.ContractIdentity != authority.policy.ContractIdentity ||
		request.ContractRevision != authority.policy.ContractRevision || request.EnablementRevision != authority.policy.EnablementRevision ||
		request.PlatformRevision != authority.policy.PlatformRevision || request.ExecutionFixture != authority.policy.ExecutionFixture || request.MaxUses != 1 {
		return errors.New("request plan identity differs")
	}
	stage, ok := authority.stages[request.StageID]
	if !ok || request.StageOrder != stage.StageOrder || request.StageDigest != stage.StageDigest || request.Operation != stage.Operation || request.Authority != stage.Authority || len(request.Predecessors) != len(stage.Requires) {
		return errors.New("request stage differs")
	}
	for index, predecessor := range request.Predecessors {
		if predecessor.StageID != stage.Requires[index] || !digestPattern.MatchString(predecessor.ReceiptDigest) {
			return errors.New("request predecessor shape differs")
		}
	}
	return nil
}

func (authority *Authority) payload(request runner.StageAuthorizationRequest, now time.Time) authorization.StagePayload {
	payload := authorization.StagePayload{
		Audience: request.Audience, GrantID: "ok147-dev-" + strings.TrimPrefix(request.RequestDigest, "sha256:")[:32], Decision: "ALLOW",
		PlanDigest: request.PlanDigest, ContractIdentity: request.ContractIdentity, ContractRevision: request.ContractRevision,
		EnablementRevision: request.EnablementRevision, PlatformRevision: request.PlatformRevision, ExecutionFixture: request.ExecutionFixture,
		StageID: request.StageID, StageOrder: request.StageOrder, StageDigest: request.StageDigest, Operation: request.Operation, Authority: request.Authority,
		NotBefore: now.Format(time.RFC3339), NotAfter: now.Add(authority.grantValidFor).Format(time.RFC3339), MaxUses: 1,
	}
	payload.Predecessors = make([]authorization.StagePredecessor, len(request.Predecessors))
	for index, predecessor := range request.Predecessors {
		payload.Predecessors[index] = authorization.StagePredecessor{StageID: predecessor.StageID, OutcomeDigest: predecessor.ReceiptDigest}
	}
	return payload
}

func (authority *Authority) claim(requestDigest string, at time.Time) error {
	if !digestPattern.MatchString(requestDigest) {
		return errors.New("request digest is invalid")
	}
	claimPath := filepath.Join(authority.stateDir, strings.TrimPrefix(requestDigest, "sha256:")+".claimed.json")
	record := claimRecord{Format: "ok147-bounded-stage-authority-claim/v1", RequestDigest: requestDigest, PolicyDigest: authority.policyDigest, ClaimedAt: at.Format(time.RFC3339)}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(claimPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

func verifyPolicy(raw []byte) (Policy, string, error) {
	var policy Policy
	if err := jsonstrict.Decode(raw, &policy); err != nil {
		return Policy{}, "", fmt.Errorf("decode bounded stage authority policy: %w", err)
	}
	if policy.Format != PolicyFormat || policy.ContractIdentity.Name == "" || policy.ContractIdentity.Namespace == "" || len(policy.Stages) == 0 {
		return Policy{}, "", errors.New("bounded stage authority policy identity is incomplete")
	}
	for _, value := range []string{policy.PlanDigest, policy.ContractRevision, policy.EnablementRevision, policy.PlatformRevision, policy.ExecutionFixture} {
		if !digestPattern.MatchString(value) {
			return Policy{}, "", errors.New("bounded stage authority policy digest identity is invalid")
		}
	}
	seen := map[string]struct{}{}
	previousOrder := 0
	for _, stage := range policy.Stages {
		if !namePattern.MatchString(stage.StageID) || stage.StageOrder <= previousOrder || !digestPattern.MatchString(stage.StageDigest) ||
			stage.Operation == "" || strings.TrimSpace(stage.Operation) != stage.Operation || !namePattern.MatchString(stage.Authority) || stage.Requires == nil {
			return Policy{}, "", errors.New("bounded stage authority stage policy is invalid")
		}
		if _, exists := seen[stage.StageID]; exists {
			return Policy{}, "", errors.New("bounded stage authority stage policy is duplicated")
		}
		seen[stage.StageID] = struct{}{}
		previousOrder = stage.StageOrder
		for _, predecessor := range stage.Requires {
			if !namePattern.MatchString(predecessor) {
				return Policy{}, "", errors.New("bounded stage authority predecessor is invalid")
			}
		}
	}
	canonical, err := canonicalJSON(policy)
	if err != nil {
		return Policy{}, "", err
	}
	return policy, digest.SHA256(canonical), nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return contract.JCS(generic)
}

func parsePrivateKey(raw []byte) (ed25519.PrivateKey, string, error) {
	encoded := strings.TrimSuffix(string(raw), "\n")
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PrivateKeySize || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, "", errors.New("bounded stage authority private key encoding is invalid")
	}
	privateKey := append(ed25519.PrivateKey(nil), decoded...)
	return privateKey, digest.SHA256(privateKey.Public().(ed25519.PublicKey)), nil
}

func readPrivateRegular(path string, maximum int64, private bool) ([]byte, error) {
	if path == "" {
		return nil, errors.New("file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximum || private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("file identity changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || len(raw) > int(maximum) {
		return nil, errors.New("bounded file read failed")
	}
	return raw, nil
}

var _ http.Handler = (*Authority)(nil)
