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
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const (
	TargetRegistrationRecoveryAuthorizationRequestFormat  = "ok147-target-registration-recovery-authorization-request/v1"
	ResolvedTargetRegistrationRecoveryAuthorizationFormat = "ok147-resolved-target-registration-recovery-authorization/v1"
	TargetRegistrationRecoveryReceiptFormat               = "ok147-target-registration-recovery/v1"
)

type TargetRegistrationRecoveryAuthorizationRequest struct {
	Format                          string                    `json:"format"`
	RequestDigest                   string                    `json:"requestDigest"`
	Stage                           StageAuthorizationRequest `json:"stage"`
	PriorStageReceiptDigest         string                    `json:"priorStageReceiptDigest"`
	CredentialRecoveryRequestDigest string                    `json:"credentialRecoveryRequestDigest"`
	CredentialIssueReceiptDigest    string                    `json:"credentialIssueReceiptDigest"`
}

type targetRegistrationRecoveryAuthorizationRequestPayload struct {
	Format                          string                    `json:"format"`
	Stage                           StageAuthorizationRequest `json:"stage"`
	PriorStageReceiptDigest         string                    `json:"priorStageReceiptDigest"`
	CredentialRecoveryRequestDigest string                    `json:"credentialRecoveryRequestDigest"`
	CredentialIssueReceiptDigest    string                    `json:"credentialIssueReceiptDigest"`
}

type TargetRegistrationRecoveryAuthorizationResolver interface {
	ResolveTargetRegistrationRecoveryAuthorization(context.Context, TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error)
}

type TargetRegistrationRecoveryAuthorizationResolverFunc func(context.Context, TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error)

func (resolve TargetRegistrationRecoveryAuthorizationResolverFunc) ResolveTargetRegistrationRecoveryAuthorization(ctx context.Context, request TargetRegistrationRecoveryAuthorizationRequest) (StageAuthorizationSource, error) {
	return resolve(ctx, request)
}

type ResolvedTargetRegistrationRecoveryAuthorization struct {
	request  TargetRegistrationRecoveryAuthorizationRequest
	source   StageAuthorizationSource
	grant    authorization.VerifiedStageGrant
	verified bool
}

type ResolvedTargetRegistrationRecoveryAuthorizationReceipt struct {
	Format                          string `json:"format"`
	State                           string `json:"state"`
	RequestDigest                   string `json:"requestDigest"`
	PriorStageReceiptDigest         string `json:"priorStageReceiptDigest"`
	CredentialRecoveryRequestDigest string `json:"credentialRecoveryRequestDigest"`
	CredentialIssueReceiptDigest    string `json:"credentialIssueReceiptDigest"`
	AuthorizationDigest             string `json:"authorizationDigest"`
	GrantID                         string `json:"grantId"`
	KeyID                           string `json:"keyId"`
	PlanDigest                      string `json:"planDigest"`
	StageID                         string `json:"stageId"`
	NotAfter                        string `json:"notAfter"`
	MaxUses                         int    `json:"maxUses"`
}

func ResolveTargetRegistrationRecoveryAuthorization(ctx context.Context, handoff *VerifiedTargetCredentialStageHandoff, prior StageReceiptSource, resolver TargetRegistrationRecoveryAuthorizationResolver) (ResolvedTargetRegistrationRecoveryAuthorization, error) {
	if handoff == nil || resolver == nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("recovered target-credential handoff and registration recovery resolver are required")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("target-registration recovery authorization context is unavailable")
	}
	plan, cursor, prefix, err := handoff.registrationContext()
	if err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, err
	}
	credentialEvidence, recoveryRequest, err := handoff.credentialEvidence()
	if err != nil || recoveryRequest == "" {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("target-registration recovery requires an independently recovered credential")
	}
	if _, err := loadSuccessfulTargetRegistrationReceipt(plan, cursor, prefix, prior); err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, err
	}
	decision, err := cursor.Decision()
	if err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, err
	}
	stageRequest, err := newStageAuthorizationRequest(plan, decision)
	if err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, err
	}
	request := TargetRegistrationRecoveryAuthorizationRequest{
		Format: TargetRegistrationRecoveryAuthorizationRequestFormat, Stage: stageRequest,
		PriorStageReceiptDigest: prior.Digest, CredentialRecoveryRequestDigest: recoveryRequest,
		CredentialIssueReceiptDigest: credentialEvidence,
	}
	request.RequestDigest, err = targetRegistrationRecoveryAuthorizationRequestDigest(request)
	if err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("canonicalize target-registration recovery authorization request")
	}
	source, err := resolver.ResolveTargetRegistrationRecoveryAuthorization(ctx, cloneTargetRegistrationRecoveryAuthorizationRequest(request))
	if err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("resolve target-registration recovery authorization")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("target-registration recovery authorization context became unavailable")
	}
	if source.GrantPath == "" || source.PublicKeyPath == "" || source.EvaluationTime.IsZero() {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("resolved target-registration recovery authorization source is incomplete")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, err
	}
	grant, err := authorization.LoadStage(source.GrantPath, source.PublicKeyPath, plan, "target-registration", predecessors, source.EvaluationTime)
	if err != nil {
		return ResolvedTargetRegistrationRecoveryAuthorization{}, errors.New("verify target-registration recovery authorization")
	}
	return ResolvedTargetRegistrationRecoveryAuthorization{request: request, source: source, grant: grant, verified: true}, nil
}

func (request TargetRegistrationRecoveryAuthorizationRequest) Bytes() ([]byte, error) {
	digestValue, err := targetRegistrationRecoveryAuthorizationRequestDigest(request)
	if err != nil || request.Format != TargetRegistrationRecoveryAuthorizationRequestFormat || request.RequestDigest != digestValue ||
		request.Stage.StageID != "target-registration" ||
		!stageReceiptPrefixDigestPattern.MatchString(request.PriorStageReceiptDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(request.CredentialRecoveryRequestDigest) ||
		!stageReceiptPrefixDigestPattern.MatchString(request.CredentialIssueReceiptDigest) {
		return nil, errors.New("target-registration recovery authorization request was not produced by verification")
	}
	if _, err := request.Stage.Bytes(); err != nil {
		return nil, errors.New("target-registration recovery stage request was not produced by verification")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return canonicalTargetRegistrationValue(json.RawMessage(raw))
}

func (resolved ResolvedTargetRegistrationRecoveryAuthorization) Receipt() (ResolvedTargetRegistrationRecoveryAuthorizationReceipt, error) {
	if !resolved.verified {
		return ResolvedTargetRegistrationRecoveryAuthorizationReceipt{}, errors.New("target-registration recovery authorization was not produced by verification")
	}
	grant := resolved.grant.Receipt()
	return ResolvedTargetRegistrationRecoveryAuthorizationReceipt{
		Format: ResolvedTargetRegistrationRecoveryAuthorizationFormat, State: "VERIFIED",
		RequestDigest: resolved.request.RequestDigest, PriorStageReceiptDigest: resolved.request.PriorStageReceiptDigest,
		CredentialRecoveryRequestDigest: resolved.request.CredentialRecoveryRequestDigest,
		CredentialIssueReceiptDigest:    resolved.request.CredentialIssueReceiptDigest,
		AuthorizationDigest:             grant.AuthorizationDigest, GrantID: grant.GrantID, KeyID: grant.KeyID,
		PlanDigest: grant.PlanDigest, StageID: grant.StageID, NotAfter: grant.NotAfter, MaxUses: grant.MaxUses,
	}, nil
}

func cloneTargetRegistrationRecoveryAuthorizationRequest(request TargetRegistrationRecoveryAuthorizationRequest) TargetRegistrationRecoveryAuthorizationRequest {
	request.Stage = cloneStageAuthorizationRequest(request.Stage)
	return request
}

func targetRegistrationRecoveryAuthorizationRequestDigest(request TargetRegistrationRecoveryAuthorizationRequest) (string, error) {
	payload := targetRegistrationRecoveryAuthorizationRequestPayload{
		Format: request.Format, Stage: request.Stage, PriorStageReceiptDigest: request.PriorStageReceiptDigest,
		CredentialRecoveryRequestDigest: request.CredentialRecoveryRequestDigest,
		CredentialIssueReceiptDigest:    request.CredentialIssueReceiptDigest,
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

type TargetRegistrationRecoveryConfig struct {
	Handoff             *VerifiedTargetCredentialStageHandoff
	PriorStageReceipt   StageReceiptSource
	Authorization       ResolvedTargetRegistrationRecoveryAuthorization
	ArtifactPath        string
	Expected            submission.TargetRegistrationExpected
	Ledger              KubernetesLedgerConfig
	GitOps              KubernetesAuthorityConfig
	Runtime             VerifiedRuntimeBindingMaterial
	MaterializationTime time.Time
	Clock               func() time.Time
}

type TargetRegistrationRecoveryReceipt struct {
	Format                          string                            `json:"format"`
	State                           string                            `json:"state"`
	PlanDigest                      string                            `json:"planDigest"`
	PriorStageReceiptDigest         string                            `json:"priorStageReceiptDigest"`
	RecoveryRequestDigest           string                            `json:"recoveryRequestDigest"`
	CredentialRecoveryRequestDigest string                            `json:"credentialRecoveryRequestDigest"`
	CredentialIssueReceiptDigest    string                            `json:"credentialIssueReceiptDigest"`
	AuthorizationDigest             string                            `json:"authorizationDigest"`
	Claim                           *ledger.StageClaimReceipt         `json:"claim,omitempty"`
	Outcome                         *ledger.StageOutcomeReceipt       `json:"outcome,omitempty"`
	Refresh                         *TargetRegistrationRefreshReceipt `json:"refresh,omitempty"`
	StageReceiptRewritten           bool                              `json:"stageReceiptRewritten"`
}

func RecoverTargetRegistration(ctx context.Context, config TargetRegistrationRecoveryConfig) (TargetRegistrationRecoveryReceipt, error) {
	receipt := TargetRegistrationRecoveryReceipt{Format: TargetRegistrationRecoveryReceiptFormat, State: "PRECLAIM"}
	if config.Handoff == nil || config.Clock == nil || config.MaterializationTime.IsZero() || !config.Authorization.verified {
		return receipt, errors.New("verified target-registration recovery config is required")
	}
	plan, cursor, prefix, err := config.Handoff.registrationContext()
	if err != nil {
		return receipt, err
	}
	if _, err := loadSuccessfulTargetRegistrationReceipt(plan, cursor, prefix, config.PriorStageReceipt); err != nil {
		return receipt, err
	}
	if err := verifyResolvedTargetRegistrationRecoveryAuthorization(config.Authorization, plan, cursor, config.PriorStageReceipt, config.Handoff); err != nil {
		return receipt, err
	}
	resolvedReceipt, _ := config.Authorization.Receipt()
	receipt.PlanDigest, receipt.PriorStageReceiptDigest = plan.PlanDigest, config.PriorStageReceipt.Digest
	receipt.RecoveryRequestDigest = resolvedReceipt.RequestDigest
	receipt.CredentialRecoveryRequestDigest = resolvedReceipt.CredentialRecoveryRequestDigest
	receipt.CredentialIssueReceiptDigest = resolvedReceipt.CredentialIssueReceiptDigest
	receipt.AuthorizationDigest = resolvedReceipt.AuthorizationDigest

	bundle, err := LoadTargetRegistrationStageBundleFromHandoff(TargetRegistrationStageHandoffConfig{
		Handoff: config.Handoff, GrantPath: config.Authorization.source.GrantPath,
		GrantPublicKeyPath: config.Authorization.source.PublicKeyPath, EvaluationTime: config.Authorization.source.EvaluationTime,
		ArtifactPath: config.ArtifactPath, Expected: config.Expected,
	})
	if err != nil {
		return receipt, err
	}
	credential, err := bundle.handoff.takeCredential()
	if err != nil {
		return receipt, err
	}
	material, err := BuildTargetRegistrationMaterial(TargetRegistrationMaterializeConfig{
		Bundle: bundle, Runtime: config.Runtime, Credential: credential, MaterializationTime: config.MaterializationTime,
	})
	if err != nil {
		return receipt, err
	}
	writerToken, ca, client, err := openBoundedKubernetesMaterial(config.GitOps.TokenFile, config.GitOps.CAFile)
	if err != nil || digest.SHA256(ca) != config.GitOps.CABundleDigest || config.GitOps.AuthorityIdentity != plan.Authorities.GitOps {
		return receipt, errors.New("open bounded target-registration recovery writer")
	}
	refresher, err := newKubernetesTargetRegistrationRefresher(targetRegistrationLauncherClientConfig{
		Endpoint: config.GitOps.Endpoint, BearerToken: writerToken, AuthorityIdentity: config.GitOps.AuthorityIdentity,
		Client: client, Clock: config.Clock,
	}, material)
	if err != nil {
		return receipt, err
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return receipt, errors.New("open target-registration recovery ledger")
	}
	if len(ledgerToken) == len(writerToken) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(writerToken)) == 1 {
		return receipt, errors.New("ledger and target-registration recovery writer credentials must be distinct")
	}
	inspection, err := store.InspectStage(ctx, config.Authorization.grant)
	if err != nil || inspection.State != "AVAILABLE" || !inspection.ClaimAllowed {
		return receipt, errors.New("target-registration recovery authorization is not available")
	}
	claim, err := store.ClaimStage(ctx, config.Authorization.grant, config.Clock())
	if err != nil {
		return receipt, err
	}
	receipt.Claim, receipt.State = &claim, "CLAIMED_INDETERMINATE_STOP"
	refresh, refreshErr := refresher.Refresh(ctx)
	receipt.Refresh = &refresh
	refreshRaw, canonicalErr := canonicalTargetRegistrationValue(refresh)
	if canonicalErr != nil {
		return receipt, errors.New("canonicalize target-registration recovery evidence")
	}
	if refreshErr != nil {
		mutationState := refresh.MutationState
		if mutationState != "UNKNOWN" && mutationState != "ATTEMPTED" {
			mutationState = "NOT_ATTEMPTED"
		}
		outcome, completeErr := store.CompleteStage(ctx, claim, "STOPPED", mutationState, digest.SHA256(refreshRaw), config.Clock())
		if completeErr != nil {
			return receipt, errors.New("target-registration recovery stopped before durable completion")
		}
		receipt.Outcome, receipt.State = &outcome, "COMPLETED_STOPPED"
		return receipt, errors.New("bounded target-registration recovery stopped")
	}
	outcome, err := store.CompleteStage(ctx, claim, "SUCCEEDED", "ATTEMPTED", digest.SHA256(refreshRaw), config.Clock())
	if err != nil {
		return receipt, errors.New("complete target-registration recovery outcome")
	}
	receipt.Outcome, receipt.State = &outcome, "REFRESHED"
	return receipt, nil
}

func verifyResolvedTargetRegistrationRecoveryAuthorization(resolved ResolvedTargetRegistrationRecoveryAuthorization, plan stageplan.Binding, cursor stagecursor.Cursor, prior StageReceiptSource, handoff *VerifiedTargetCredentialStageHandoff) error {
	if !resolved.verified || resolved.request.PriorStageReceiptDigest != prior.Digest {
		return errors.New("target-registration recovery authorization was not produced by verification")
	}
	if _, err := resolved.request.Bytes(); err != nil {
		return err
	}
	credentialEvidence, recoveryRequest, err := handoff.credentialEvidence()
	if err != nil || resolved.request.CredentialIssueReceiptDigest != credentialEvidence || resolved.request.CredentialRecoveryRequestDigest != recoveryRequest {
		return errors.New("target-registration recovery credential binding changed")
	}
	digestValue, err := targetRegistrationRecoveryAuthorizationRequestDigest(resolved.request)
	if err != nil || digestValue != resolved.request.RequestDigest {
		return errors.New("target-registration recovery request identity changed")
	}
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return err
	}
	_, err = authorization.BindStageGrant(resolved.grant, plan, "target-registration", predecessors)
	return err
}

func loadSuccessfulTargetRegistrationReceipt(plan stageplan.Binding, cursor stagecursor.Cursor, prefix []stagereceipt.Verified, source StageReceiptSource) (stagereceipt.Verified, error) {
	predecessors, err := cursor.Predecessors()
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	verified, err := stagereceipt.Load(source.Path, source.Digest, plan, predecessors)
	if err != nil {
		return stagereceipt.Verified{}, errors.New("load durable target-registration receipt for recovery")
	}
	stage, err := verified.Receipt()
	if err != nil || stage.StageID != "target-registration" || stage.State != "SUCCEEDED" || stage.MutationState != "ATTEMPTED" {
		return stagereceipt.Verified{}, errors.New("target-registration recovery requires successful durable Stage-9 receipt")
	}
	combined := append(append([]stagereceipt.Verified(nil), prefix...), verified)
	next, err := stagecursor.Evaluate(plan, combined)
	if err != nil {
		return stagereceipt.Verified{}, err
	}
	decision, err := next.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "platform-applications" {
		return stagereceipt.Verified{}, errors.New("durable receipt chain does not select platform Applications")
	}
	return verified, nil
}
