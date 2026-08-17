package runner

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const (
	TargetCredentialPolicyFormat             = "ok147-target-credential-policy/v1"
	TargetCredentialStageBundleReceiptFormat = "ok147-target-credential-stage-bundle/v1"
	maximumTargetCredentialPolicyBytes       = 64 * 1024
	targetCredentialLifetimeSeconds          = 3 * 60 * 60
)

type targetCredentialServiceAccount struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type targetCredentialPolicyDocument struct {
	Format               string                         `json:"format"`
	TargetIdentityDigest string                         `json:"targetIdentityDigest"`
	ServiceAccount       targetCredentialServiceAccount `json:"serviceAccount"`
	RequestedAudiences   []string                       `json:"requestedAudiences"`
	ExpirationSeconds    int                            `json:"expirationSeconds"`
	CredentialUse        string                         `json:"credentialUse"`
	Retention            string                         `json:"retention"`
	NativeRotation       bool                           `json:"nativeRotation"`
	ProductionSuitable   bool                           `json:"productionSuitable"`
}

// TargetCredentialStageBundleConfig binds the successful seven-stage prefix,
// the exact target-access artifact, one immutable credential policy and one
// IssueTargetCredential grant. Loading performs no TokenRequest or API call.
type TargetCredentialStageBundleConfig struct {
	PlanPath                    string
	PlanExpected                stageplan.Expected
	Receipts                    []StageReceiptSource
	GrantPath                   string
	GrantPublicKeyPath          string
	EvaluationTime              time.Time
	PolicyPath                  string
	TargetAccessArtifactPath    string
	TargetAccessExpectedObjects []projection.ResourceIdentity
}

type TargetCredentialStageBundleReceipt struct {
	Format                       string `json:"format"`
	State                        string `json:"state"`
	PlanDigest                   string `json:"planDigest"`
	StageID                      string `json:"stageId"`
	AuthorizationDigest          string `json:"authorizationDigest"`
	PolicyDigest                 string `json:"policyDigest"`
	TargetAccessArtifactDigest   string `json:"targetAccessArtifactDigest"`
	TargetIdentityDigest         string `json:"targetIdentityDigest"`
	ServiceAccountIdentityDigest string `json:"serviceAccountIdentityDigest"`
	AudienceMode                 string `json:"audienceMode"`
	ExpirationSeconds            int    `json:"expirationSeconds"`
	CredentialRetention          string `json:"credentialRetention"`
	NativeRotationClaimed        bool   `json:"nativeRotationClaimed"`
	ProductionSuitableClaimed    bool   `json:"productionSuitableClaimed"`
	MutationAllowed              bool   `json:"mutationAllowed"`
}

type VerifiedTargetCredentialStageBundle struct {
	plan     stageplan.Binding
	cursor   stagecursor.Cursor
	prefix   []stagereceipt.Verified
	grant    authorization.VerifiedStageGrant
	policy   targetCredentialPolicyDocument
	receipt  TargetCredentialStageBundleReceipt
	verified bool
}

type TargetCredentialStageRuntimeConfig struct {
	Ledger   KubernetesLedgerConfig
	Workload WorkloadAuthorityFileResolverConfig
	Clock    func() time.Time
}

type BoundTargetCredentialStage struct {
	operation execution.StagedOperation
	mutator   *TargetCredentialStageMutator
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	previous  []stagereceipt.Verified
	grant     authorization.VerifiedStageGrant
	verified  bool
}

// LoadTargetCredentialStageBundle proves that the credential request is for
// the ServiceAccount installed by the successful target-access predecessor.
// The v1 policy deliberately binds server-default audience selection because
// OK-141 disproved the earlier guessed custom audience.
func LoadTargetCredentialStageBundle(config TargetCredentialStageBundleConfig) (VerifiedTargetCredentialStageBundle, error) {
	if config.Receipts == nil || config.EvaluationTime.IsZero() {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target-credential receipt prefix and authorization evaluation time are required")
	}
	plan, cursor, prefix, err := loadStageResumeWithPrefix(StageResumeConfig{
		PlanPath: config.PlanPath, PlanExpected: config.PlanExpected, Receipts: config.Receipts,
	})
	if err != nil {
		return VerifiedTargetCredentialStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "target-credential" || decision.Kind != "Credential" || decision.Authority != "workload" || !decision.RequiresAuthorization || decision.Operation != "IssueTargetCredential" {
		return VerifiedTargetCredentialStageBundle{}, errors.New("verified prefix does not select target credential issuance")
	}
	if len(prefix) != 7 {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target credential requires the exact seven-receipt prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target credential lacks durable workload identity")
	}
	targetAccessReceipt, err := prefix[6].Receipt()
	if err != nil || targetAccessReceipt.StageID != "target-access" || targetAccessReceipt.State != "SUCCEEDED" || targetAccessReceipt.MutationState != "ATTEMPTED" {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target credential lacks successful target-access installation")
	}
	targetAccessStage, _, err := plan.Stage("target-access")
	if err != nil || len(targetAccessStage.Inputs) != 1 || targetAccessStage.Inputs[0].Name != "stage.target-access" {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target-access stage must bind exactly one renderer artifact")
	}
	access, err := submission.LoadTargetAccess(config.TargetAccessArtifactPath, submission.TargetAccessExpected{
		ArtifactDigest: targetAccessStage.Inputs[0].Digest, ContractIdentity: plan.ContractIdentity,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision, ExecutionFixture: plan.ExecutionFixture,
		TargetIdentityDigest: lifecycle.TargetClusterUIDDigest, WorkloadAuthority: lifecycle.TargetClusterUIDDigest,
		Objects: config.TargetAccessExpectedObjects,
	})
	if err != nil {
		return VerifiedTargetCredentialStageBundle{}, err
	}
	if len(access.Workload.Objects) != 8 || access.Workload.Objects[1].Identity.Kind != "ServiceAccount" {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target-access artifact lacks the credential ServiceAccount")
	}
	credentialStage, _, err := plan.Stage("target-credential")
	if err != nil || len(credentialStage.Inputs) != 1 || credentialStage.Inputs[0].Name != "stage.target-credential" {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target-credential stage must bind exactly one policy artifact")
	}
	policyRaw, err := readBoundedRegular(config.PolicyPath, maximumTargetCredentialPolicyBytes)
	if err != nil {
		return VerifiedTargetCredentialStageBundle{}, errors.New("read bounded target-credential policy")
	}
	if digest.SHA256(policyRaw) != credentialStage.Inputs[0].Digest {
		return VerifiedTargetCredentialStageBundle{}, errors.New("target-credential policy digest differs from staged input")
	}
	var policy targetCredentialPolicyDocument
	if err := jsonstrict.Decode(policyRaw, &policy); err != nil {
		return VerifiedTargetCredentialStageBundle{}, fmt.Errorf("decode target-credential policy: %w", err)
	}
	serviceAccount := access.Workload.Objects[1].Identity
	if err := validateTargetCredentialPolicy(policy, lifecycle.TargetClusterUIDDigest, serviceAccount); err != nil {
		return VerifiedTargetCredentialStageBundle{}, err
	}
	directPredecessors, err := cursor.Predecessors()
	if err != nil {
		return VerifiedTargetCredentialStageBundle{}, err
	}
	grant, err := authorization.LoadStage(config.GrantPath, config.GrantPublicKeyPath, plan, "target-credential", directPredecessors, config.EvaluationTime)
	if err != nil {
		return VerifiedTargetCredentialStageBundle{}, err
	}
	if _, err := authorization.BindStageGrant(grant, plan, "target-credential", directPredecessors); err != nil {
		return VerifiedTargetCredentialStageBundle{}, err
	}
	identityRaw, _ := json.Marshal(serviceAccount)
	receipt := TargetCredentialStageBundleReceipt{
		Format: TargetCredentialStageBundleReceiptFormat, State: "VERIFIED", PlanDigest: plan.PlanDigest,
		StageID: "target-credential", AuthorizationDigest: grant.Receipt().AuthorizationDigest,
		PolicyDigest: credentialStage.Inputs[0].Digest, TargetAccessArtifactDigest: targetAccessStage.Inputs[0].Digest,
		TargetIdentityDigest: lifecycle.TargetClusterUIDDigest, ServiceAccountIdentityDigest: digest.SHA256(identityRaw),
		AudienceMode: "server-default", ExpirationSeconds: policy.ExpirationSeconds,
		CredentialRetention: policy.Retention, NativeRotationClaimed: policy.NativeRotation,
		ProductionSuitableClaimed: policy.ProductionSuitable, MutationAllowed: false,
	}
	return VerifiedTargetCredentialStageBundle{
		plan: plan, cursor: cursor, prefix: prefix, grant: grant, policy: policy, receipt: receipt, verified: true,
	}, nil
}

func validateTargetCredentialPolicy(policy targetCredentialPolicyDocument, targetIdentity string, serviceAccount projection.ResourceIdentity) error {
	if policy.Format != TargetCredentialPolicyFormat || policy.TargetIdentityDigest != targetIdentity {
		return errors.New("target-credential policy target identity differs from verified workload")
	}
	if policy.ServiceAccount.Namespace != serviceAccount.Namespace || policy.ServiceAccount.Name != serviceAccount.Name || serviceAccount.APIVersion != "v1" || serviceAccount.Kind != "ServiceAccount" {
		return errors.New("target-credential ServiceAccount differs from target-access artifact")
	}
	if len(policy.RequestedAudiences) != 0 {
		return errors.New("target-credential v1 requires server-default audience selection")
	}
	if policy.ExpirationSeconds != targetCredentialLifetimeSeconds || policy.CredentialUse != "argocd-target-registration" || policy.Retention != "memory-only" {
		return errors.New("target-credential lifetime, use, or retention boundary is invalid")
	}
	if policy.NativeRotation || policy.ProductionSuitable {
		return errors.New("target-credential v1 cannot claim native rotation or production suitability")
	}
	if strings.TrimSpace(policy.ServiceAccount.Name) != policy.ServiceAccount.Name || strings.TrimSpace(policy.ServiceAccount.Namespace) != policy.ServiceAccount.Namespace {
		return errors.New("target-credential ServiceAccount identity is invalid")
	}
	return nil
}

func (bundle VerifiedTargetCredentialStageBundle) Decision() (stagecursor.Decision, error) {
	if err := verifyTargetCredentialStageBundle(bundle); err != nil {
		return stagecursor.Decision{}, err
	}
	return bundle.cursor.Decision()
}

func (bundle VerifiedTargetCredentialStageBundle) Receipt() (TargetCredentialStageBundleReceipt, error) {
	if err := verifyTargetCredentialStageBundle(bundle); err != nil {
		return TargetCredentialStageBundleReceipt{}, err
	}
	return bundle.receipt, nil
}

// Open binds the verified credential policy to the workload authority and
// durable ledger without contacting either Kubernetes API.
func (bundle VerifiedTargetCredentialStageBundle) Open(config TargetCredentialStageRuntimeConfig) (BoundTargetCredentialStage, error) {
	if err := verifyTargetCredentialStageBundle(bundle); err != nil || config.Clock == nil {
		return BoundTargetCredentialStage{}, errors.New("verified target-credential bundle and clock are required")
	}
	issuer, err := OpenTargetCredentialIssuer(bundle, TargetCredentialIssuerConfig{Workload: config.Workload, Clock: config.Clock})
	if err != nil {
		return BoundTargetCredentialStage{}, err
	}
	ledgerStore, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return BoundTargetCredentialStage{}, errors.New("open target-credential stage ledger")
	}
	if len(ledgerToken) == len(issuer.authorityToken) && subtle.ConstantTimeCompare([]byte(ledgerToken), []byte(issuer.authorityToken)) == 1 {
		return BoundTargetCredentialStage{}, errors.New("ledger and target-credential authority credentials must be distinct")
	}
	mutator, err := NewTargetCredentialStageMutator(bundle.plan, bundle.receipt, issuer)
	if err != nil {
		return BoundTargetCredentialStage{}, err
	}
	previous, err := bundle.cursor.Predecessors()
	if err != nil {
		return BoundTargetCredentialStage{}, err
	}
	return BoundTargetCredentialStage{
		operation: execution.StagedOperation{Ledger: ledgerStore, Mutator: mutator, Clock: config.Clock},
		mutator:   mutator, plan: bundle.plan, cursor: bundle.cursor, previous: previous,
		grant: bundle.grant, verified: true,
	}, nil
}

// Run durably completes Stage 8 and transfers the verified credential exactly
// once to the immediately following in-process registration step. A replay can
// recover the public receipt but deliberately cannot recreate private material.
func (stage BoundTargetCredentialStage) Run(ctx context.Context) (execution.StagedOperationReceipt, VerifiedTargetCredentialMaterial, error) {
	receipt, handoff, err := stage.RunHandoff(ctx)
	if err != nil {
		return receipt, VerifiedTargetCredentialMaterial{}, err
	}
	material, err := handoff.takeCredential()
	if err != nil {
		return receipt, VerifiedTargetCredentialMaterial{}, err
	}
	return receipt, material, nil
}

// RunHandoff additionally returns the canonical redaction-safe Stage-8 receipt
// needed by a later authorizer while keeping credential bytes private.
func (stage BoundTargetCredentialStage) RunHandoff(ctx context.Context) (execution.StagedOperationReceipt, *VerifiedTargetCredentialStageHandoff, error) {
	if !stage.verified || stage.mutator == nil {
		return execution.StagedOperationReceipt{}, nil, errors.New("target-credential stage runtime was not produced by verification")
	}
	receipt, err := stage.operation.Run(ctx, stage.plan, stage.cursor, stage.grant)
	if err != nil {
		return receipt, nil, err
	}
	verified, err := stage.operation.Ledger.LoadStageReceipt(ctx, stage.plan, "target-credential", receipt.StageReceiptDigest, stage.previous)
	if err != nil {
		return receipt, nil, errors.New("reload durable target-credential receipt for handoff")
	}
	material, err := stage.mutator.TakeMaterial()
	if err != nil {
		return receipt, nil, errors.New("durable target-credential outcome has no in-memory credential; registration must stop")
	}
	handoff, err := newVerifiedTargetCredentialStageHandoff(verified, material)
	if err != nil {
		return receipt, nil, err
	}
	return receipt, handoff, nil
}

func verifyTargetCredentialStageBundle(bundle VerifiedTargetCredentialStageBundle) error {
	if !bundle.verified || bundle.receipt.Format != TargetCredentialStageBundleReceiptFormat || bundle.receipt.State != "VERIFIED" || bundle.receipt.StageID != "target-credential" || bundle.receipt.MutationAllowed || len(bundle.prefix) != 7 {
		return errors.New("target-credential stage bundle was not produced by verification")
	}
	for _, value := range []string{
		bundle.receipt.PlanDigest, bundle.receipt.AuthorizationDigest, bundle.receipt.PolicyDigest,
		bundle.receipt.TargetAccessArtifactDigest, bundle.receipt.TargetIdentityDigest, bundle.receipt.ServiceAccountIdentityDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(value) {
			return errors.New("target-credential stage bundle digest identity is invalid")
		}
	}
	if bundle.receipt.AudienceMode != "server-default" || bundle.receipt.ExpirationSeconds != targetCredentialLifetimeSeconds || bundle.receipt.CredentialRetention != "memory-only" || bundle.receipt.NativeRotationClaimed || bundle.receipt.ProductionSuitableClaimed {
		return errors.New("target-credential stage bundle claim boundary changed after verification")
	}
	return nil
}
