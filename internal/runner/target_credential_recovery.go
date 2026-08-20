package runner

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

const (
	TargetCredentialRecoveryAuthorizationRequestFormat  = "ok147-target-credential-recovery-authorization-request/v1"
	ResolvedTargetCredentialRecoveryAuthorizationFormat = "ok147-resolved-target-credential-recovery-authorization/v1"
	TargetCredentialRecoveryReceiptFormat               = "ok147-target-credential-recovery/v2"
)

// TargetCredentialRecoveryAuthorizationRequest tells the external authority
// that a new single-use Stage-8 grant is requested only because the original
// successful Stage-8 receipt can no longer hand private material to Stage 9.
// It is redaction-safe and binds both the old receipt and old authorization.
type TargetCredentialRecoveryAuthorizationRequest struct {
	Format                      string                    `json:"format"`
	RequestDigest               string                    `json:"requestDigest"`
	Stage                       StageAuthorizationRequest `json:"stage"`
	PriorStageReceiptDigest     string                    `json:"priorStageReceiptDigest"`
	OriginalAuthorizationDigest string                    `json:"originalAuthorizationDigest"`
}

type targetCredentialRecoveryAuthorizationRequestPayload struct {
	Format                      string                    `json:"format"`
	Stage                       StageAuthorizationRequest `json:"stage"`
	PriorStageReceiptDigest     string                    `json:"priorStageReceiptDigest"`
	OriginalAuthorizationDigest string                    `json:"originalAuthorizationDigest"`
}

type TargetCredentialRecoveryAuthorizationResolver interface {
	ResolveTargetCredentialRecoveryAuthorization(context.Context, TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error)
}

type TargetCredentialRecoveryAuthorizationResolverFunc func(context.Context, TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error)

func (resolve TargetCredentialRecoveryAuthorizationResolverFunc) ResolveTargetCredentialRecoveryAuthorization(ctx context.Context, request TargetCredentialRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
	return resolve(ctx, request)
}

type ResolvedTargetCredentialRecoveryAuthorization struct {
	request  TargetCredentialRecoveryAuthorizationRequest
	source   StageAuthorizationSource
	grant    authorization.VerifiedStageGrant
	verified bool
}

type ResolvedTargetCredentialRecoveryAuthorizationReceipt struct {
	Format                      string `json:"format"`
	State                       string `json:"state"`
	RequestDigest               string `json:"requestDigest"`
	PriorStageReceiptDigest     string `json:"priorStageReceiptDigest"`
	OriginalAuthorizationDigest string `json:"originalAuthorizationDigest"`
	RecoveryAuthorizationDigest string `json:"recoveryAuthorizationDigest"`
	GrantID                     string `json:"grantId"`
	KeyID                       string `json:"keyId"`
	PlanDigest                  string `json:"planDigest"`
	StageID                     string `json:"stageId"`
	NotAfter                    string `json:"notAfter"`
	MaxUses                     int    `json:"maxUses"`
}

func (request TargetCredentialRecoveryAuthorizationRequest) Bytes() ([]byte, error) {
	digestValue, err := targetCredentialRecoveryAuthorizationRequestDigest(request)
	if err != nil || request.Format != TargetCredentialRecoveryAuthorizationRequestFormat || request.RequestDigest != digestValue ||
		!stageReceiptPrefixDigestPattern.MatchString(request.PriorStageReceiptDigest) || !stageReceiptPrefixDigestPattern.MatchString(request.OriginalAuthorizationDigest) {
		return nil, errors.New("target-credential recovery authorization request was not produced by verification")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return canonicalTargetRegistrationValue(json.RawMessage(raw))
}

func (resolved ResolvedTargetCredentialRecoveryAuthorization) Receipt() (ResolvedTargetCredentialRecoveryAuthorizationReceipt, error) {
	if !resolved.verified {
		return ResolvedTargetCredentialRecoveryAuthorizationReceipt{}, errors.New("target-credential recovery authorization was not produced by verification")
	}
	grant := resolved.grant.Receipt()
	if grant.AuthorizationDigest == resolved.request.OriginalAuthorizationDigest || grant.GrantID == "" {
		return ResolvedTargetCredentialRecoveryAuthorizationReceipt{}, errors.New("target-credential recovery authorization is not independent")
	}
	return ResolvedTargetCredentialRecoveryAuthorizationReceipt{
		Format: ResolvedTargetCredentialRecoveryAuthorizationFormat, State: "VERIFIED",
		RequestDigest: resolved.request.RequestDigest, PriorStageReceiptDigest: resolved.request.PriorStageReceiptDigest,
		OriginalAuthorizationDigest: resolved.request.OriginalAuthorizationDigest, RecoveryAuthorizationDigest: grant.AuthorizationDigest,
		GrantID: grant.GrantID, KeyID: grant.KeyID, PlanDigest: grant.PlanDigest, StageID: grant.StageID,
		NotAfter: grant.NotAfter, MaxUses: grant.MaxUses,
	}, nil
}

// ResolveTargetCredentialRecoveryAuthorization verifies the already durable
// successful Stage-8 receipt before asking an external authority for a fresh
// grant. The new grant must have a different authorization digest and GrantID.
func ResolveTargetCredentialRecoveryAuthorization(ctx context.Context, bundle VerifiedTargetCredentialStageBundle, prior StageReceiptSource, resolver TargetCredentialRecoveryAuthorizationResolver) (ResolvedTargetCredentialRecoveryAuthorization, error) {
	if err := verifyTargetCredentialStageBundle(bundle); err != nil || resolver == nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("verified target-credential bundle and recovery resolver are required")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("target-credential recovery authorization context is unavailable")
	}
	verifiedPrior, err := loadSuccessfulTargetCredentialReceipt(bundle, prior)
	if err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, err
	}
	decision, err := bundle.cursor.Decision()
	if err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, err
	}
	stageRequest, err := newStageAuthorizationRequest(bundle.plan, decision)
	if err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, err
	}
	request := TargetCredentialRecoveryAuthorizationRequest{
		Format: TargetCredentialRecoveryAuthorizationRequestFormat, Stage: stageRequest,
		PriorStageReceiptDigest: prior.Digest, OriginalAuthorizationDigest: bundle.receipt.AuthorizationDigest,
	}
	request.RequestDigest, err = targetCredentialRecoveryAuthorizationRequestDigest(request)
	if err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("canonicalize target-credential recovery authorization request")
	}
	source, err := resolver.ResolveTargetCredentialRecoveryAuthorization(ctx, cloneTargetCredentialRecoveryAuthorizationRequest(request))
	if err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("resolve target-credential recovery authorization")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("target-credential recovery authorization context became unavailable")
	}
	if source.GrantPath == "" || source.PublicKeyPath == "" || source.EvaluationTime.IsZero() {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("resolved target-credential recovery authorization source is incomplete")
	}
	predecessors, err := bundle.cursor.Predecessors()
	if err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, err
	}
	grant, err := authorization.LoadStage(source.GrantPath, source.PublicKeyPath, bundle.plan, "target-credential", predecessors, source.EvaluationTime)
	if err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("verify target-credential recovery authorization")
	}
	newReceipt, originalReceipt := grant.Receipt(), bundle.grant.Receipt()
	if newReceipt.AuthorizationDigest == originalReceipt.AuthorizationDigest || newReceipt.GrantID == originalReceipt.GrantID {
		return ResolvedTargetCredentialRecoveryAuthorization{}, errors.New("target-credential recovery requires an independent authorization and GrantID")
	}
	if _, err := verifiedPrior.Digest(); err != nil {
		return ResolvedTargetCredentialRecoveryAuthorization{}, err
	}
	return ResolvedTargetCredentialRecoveryAuthorization{request: request, source: source, grant: grant, verified: true}, nil
}

func cloneTargetCredentialRecoveryAuthorizationRequest(request TargetCredentialRecoveryAuthorizationRequest) TargetCredentialRecoveryAuthorizationRequest {
	request.Stage = cloneStageAuthorizationRequest(request.Stage)
	return request
}

func targetCredentialRecoveryAuthorizationRequestDigest(request TargetCredentialRecoveryAuthorizationRequest) (string, error) {
	payload := targetCredentialRecoveryAuthorizationRequestPayload{
		Format: request.Format, Stage: request.Stage, PriorStageReceiptDigest: request.PriorStageReceiptDigest,
		OriginalAuthorizationDigest: request.OriginalAuthorizationDigest,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalTargetRegistrationValue(json.RawMessage(raw))
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}

func verifyResolvedTargetCredentialRecoveryAuthorization(resolved ResolvedTargetCredentialRecoveryAuthorization, bundle VerifiedTargetCredentialStageBundle, prior StageReceiptSource) error {
	if !resolved.verified || resolved.request.Format != TargetCredentialRecoveryAuthorizationRequestFormat || resolved.request.PriorStageReceiptDigest != prior.Digest ||
		resolved.request.OriginalAuthorizationDigest != bundle.receipt.AuthorizationDigest || resolved.request.Stage.StageID != "target-credential" {
		return errors.New("target-credential recovery authorization was not produced by verification")
	}
	digestValue, err := targetCredentialRecoveryAuthorizationRequestDigest(resolved.request)
	if err != nil || digestValue != resolved.request.RequestDigest {
		return errors.New("target-credential recovery authorization request identity changed")
	}
	predecessors, err := bundle.cursor.Predecessors()
	if err != nil {
		return err
	}
	if _, err := authorization.BindStageGrant(resolved.grant, bundle.plan, "target-credential", predecessors); err != nil {
		return errors.New("target-credential recovery authorization binding changed")
	}
	current, original := resolved.grant.Receipt(), bundle.grant.Receipt()
	if current.AuthorizationDigest == original.AuthorizationDigest || current.GrantID == original.GrantID {
		return errors.New("target-credential recovery authorization is not independent")
	}
	return nil
}

type TargetCredentialRecoveryConfig struct {
	Bundle        VerifiedTargetCredentialStageBundle
	StageReceipt  StageReceiptSource
	Authorization ResolvedTargetCredentialRecoveryAuthorization
	Ledger        KubernetesLedgerConfig
	Workload      WorkloadAuthorityFileResolverConfig
	Clock         func() time.Time
}

type TargetCredentialRecoveryReceipt struct {
	Format                       string                      `json:"format"`
	State                        string                      `json:"state"`
	PlanDigest                   string                      `json:"planDigest"`
	PriorStageReceiptDigest      string                      `json:"priorStageReceiptDigest"`
	RecoveryRequestDigest        string                      `json:"recoveryRequestDigest"`
	OriginalAuthorizationDigest  string                      `json:"originalAuthorizationDigest"`
	RecoveryAuthorizationDigest  string                      `json:"recoveryAuthorizationDigest"`
	TargetIdentityDigest         string                      `json:"targetIdentityDigest"`
	Claim                        *ledger.StageClaimReceipt   `json:"claim,omitempty"`
	Outcome                      *ledger.StageOutcomeReceipt `json:"outcome,omitempty"`
	CredentialIssueReceiptDigest string                      `json:"credentialIssueReceiptDigest,omitempty"`
	IssuedAt                     string                      `json:"issuedAt,omitempty"`
	ExpiresAt                    string                      `json:"expiresAt,omitempty"`
	CredentialBytesInReceipt     bool                        `json:"credentialBytesInReceipt"`
	StageReceiptRewritten        bool                        `json:"stageReceiptRewritten"`
}

// RecoverTargetCredential claims the fresh recovery grant before making one
// TokenRequest. It records a durable outcome but deliberately never finalizes
// or overwrites the authoritative successful Stage-8 receipt.
func RecoverTargetCredential(ctx context.Context, config TargetCredentialRecoveryConfig) (TargetCredentialRecoveryReceipt, *VerifiedTargetCredentialStageHandoff, error) {
	receipt := TargetCredentialRecoveryReceipt{Format: TargetCredentialRecoveryReceiptFormat, State: "PRECLAIM"}
	if err := verifyTargetCredentialStageBundle(config.Bundle); err != nil || config.Clock == nil {
		return receipt, nil, errors.New("verified target-credential recovery config and clock are required")
	}
	if err := verifyResolvedTargetCredentialRecoveryAuthorization(config.Authorization, config.Bundle, config.StageReceipt); err != nil {
		return receipt, nil, err
	}
	prior, err := loadSuccessfulTargetCredentialReceipt(config.Bundle, config.StageReceipt)
	if err != nil {
		return receipt, nil, err
	}
	recoveryGrant := config.Authorization.grant
	recoveryGrantReceipt := recoveryGrant.Receipt()
	receipt.PlanDigest = config.Bundle.plan.PlanDigest
	receipt.PriorStageReceiptDigest = config.StageReceipt.Digest
	receipt.RecoveryRequestDigest = config.Authorization.request.RequestDigest
	receipt.OriginalAuthorizationDigest = config.Bundle.receipt.AuthorizationDigest
	receipt.RecoveryAuthorizationDigest = recoveryGrantReceipt.AuthorizationDigest
	receipt.TargetIdentityDigest = config.Bundle.receipt.TargetIdentityDigest

	issuer, err := OpenTargetCredentialIssuer(config.Bundle, TargetCredentialIssuerConfig{Workload: config.Workload, Clock: config.Clock})
	if err != nil {
		return receipt, nil, err
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return receipt, nil, errors.New("open target-credential recovery ledger")
	}
	if len(ledgerToken) == len(issuer.authorityToken) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(issuer.authorityToken)) == 1 {
		return receipt, nil, errors.New("ledger and target-credential recovery authority credentials must be distinct")
	}
	inspection, err := store.InspectStage(ctx, recoveryGrant)
	if err != nil {
		return receipt, nil, err
	}
	if inspection.State != "AVAILABLE" || !inspection.ClaimAllowed {
		return receipt, nil, errors.New("target-credential recovery authorization is not available")
	}
	claim, err := store.ClaimStage(ctx, recoveryGrant, config.Clock())
	if err != nil {
		return receipt, nil, err
	}
	receipt.Claim = &claim
	receipt.State = "CLAIMED_INDETERMINATE_STOP"

	credential, issueErr := issuer.Issue(ctx)
	if issueErr != nil {
		stoppedRaw, _ := canonicalTargetRegistrationValue(targetCredentialStoppedEvidence{
			Format: "ok147-target-credential-recovery-stopped-evidence/v1", StageID: "target-credential",
			PlanDigest: config.Bundle.plan.PlanDigest, PolicyDigest: config.Bundle.receipt.PolicyDigest,
			TargetIdentityDigest: config.Bundle.receipt.TargetIdentityDigest, State: "STOPPED", CredentialRetained: false,
		})
		outcome, completeErr := store.CompleteStage(ctx, claim, "STOPPED", "UNKNOWN", digest.SHA256(stoppedRaw), config.Clock())
		if completeErr != nil {
			return receipt, nil, errors.New("target-credential recovery stopped before durable completion")
		}
		receipt.Outcome, receipt.State = &outcome, "COMPLETED_STOPPED"
		return receipt, nil, errors.New("bounded target-credential recovery issuance stopped")
	}
	issued, err := credential.Receipt()
	if err != nil || issued.TargetIdentityDigest != receipt.TargetIdentityDigest {
		return receipt, nil, errors.New("recovered target credential differs from bound target")
	}
	issuedRaw, err := canonicalTargetRegistrationValue(issued)
	if err != nil {
		return receipt, nil, errors.New("canonicalize recovered target credential evidence")
	}
	receipt.CredentialIssueReceiptDigest = digest.SHA256(issuedRaw)
	receipt.IssuedAt, receipt.ExpiresAt = issued.IssuedAt, issued.ExpiresAt
	outcome, err := store.CompleteStage(ctx, claim, "SUCCEEDED", "ATTEMPTED", receipt.CredentialIssueReceiptDigest, config.Clock())
	if err != nil {
		return receipt, nil, errors.New("complete target-credential recovery outcome")
	}
	receipt.Outcome, receipt.State = &outcome, "REISSUED"
	handoff, err := newVerifiedRecoveredTargetCredentialStageHandoff(config.Bundle.plan, config.Bundle.prefix, prior, credential, receipt)
	if err != nil {
		return receipt, nil, err
	}
	return receipt, handoff, nil
}

func loadSuccessfulTargetCredentialReceipt(bundle VerifiedTargetCredentialStageBundle, source StageReceiptSource) (stagereceipt.Verified, error) {
	predecessors, err := bundle.cursor.Predecessors()
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	verified, err := stagereceipt.Load(source.Path, source.Digest, bundle.plan, predecessors)
	if err != nil {
		return stagereceipt.Verified{}, errors.New("load durable target-credential receipt for recovery")
	}
	receipt, err := verified.Receipt()
	if err != nil || receipt.StageID != "target-credential" || receipt.State != "SUCCEEDED" || receipt.MutationState != "ATTEMPTED" || receipt.EvidenceDigest == "" {
		return stagereceipt.Verified{}, errors.New("target-credential recovery requires a successful durable Stage-8 receipt")
	}
	prefix := append(append([]stagereceipt.Verified(nil), bundle.prefix...), verified)
	cursor, err := stagecursor.Evaluate(bundle.plan, prefix)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-registration" {
		return stagereceipt.Verified{}, errors.New("durable receipt chain does not select target registration")
	}
	return verified, nil
}
