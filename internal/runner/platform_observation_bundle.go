package runner

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
	"github.com/openkubes/ok-cluster/internal/stagereceipt"
)

type PlatformObservationStageBundleConfig struct {
	StageResumeConfig
	Profile               observation.PlatformProfile
	ExpectedProfileDigest string
}

type VerifiedPlatformObservationStageBundle struct {
	plan          stageplan.Binding
	cursor        stagecursor.Cursor
	prefix        []stagereceipt.Verified
	profile       observation.PlatformProfile
	profileDigest string
	verified      bool
}

type PlatformObservationStageRuntimeConfig struct {
	Ledger       KubernetesLedgerConfig
	Argo         KubernetesAuthorityConfig
	Runtime      VerifiedRuntimeBindingMaterial
	Capability   observation.PlatformCapabilitySource
	PollInterval time.Duration
	PollTimeout  time.Duration
	Clock        func() time.Time
	Wait         ObservationWaiter
}

type OpenedPlatformObservationStage struct {
	operation execution.ObservationStageOperation
	plan      stageplan.Binding
	cursor    stagecursor.Cursor
	verified  bool
}

func LoadPlatformObservationStageBundle(config PlatformObservationStageBundleConfig) (VerifiedPlatformObservationStageBundle, error) {
	plan, cursor, prefix, err := loadStageResumeWithPrefix(config.StageResumeConfig)
	if err != nil {
		return VerifiedPlatformObservationStageBundle{}, err
	}
	decision, err := cursor.Decision()
	if err != nil || decision.State != "NEXT" || decision.StageID != "platform-observation" || decision.Kind != "Observation" || decision.Authority != "gitops" || decision.RequiresAuthorization || decision.Operation != "" {
		return VerifiedPlatformObservationStageBundle{}, errors.New("verified prefix does not select platform observation")
	}
	if len(prefix) != 10 {
		return VerifiedPlatformObservationStageBundle{}, errors.New("platform observation requires the exact ten-receipt prefix")
	}
	lifecycle, err := prefix[1].Receipt()
	if err != nil || lifecycle.StageID != "cluster-lifecycle" || !stageReceiptPrefixDigestPattern.MatchString(lifecycle.TargetClusterUIDDigest) {
		return VerifiedPlatformObservationStageBundle{}, errors.New("platform observation lacks durable workload identity")
	}
	platformApplications, err := prefix[9].Receipt()
	if err != nil || platformApplications.StageID != "platform-applications" || platformApplications.State != "SUCCEEDED" || platformApplications.MutationState != "ATTEMPTED" {
		return VerifiedPlatformObservationStageBundle{}, errors.New("platform observation lacks successful Application submission")
	}
	profileDigest, err := observation.PlatformProfileDigest(config.Profile)
	if err != nil || config.ExpectedProfileDigest != profileDigest {
		return VerifiedPlatformObservationStageBundle{}, errors.New("platform observation profile identity is invalid")
	}
	stage, _, err := plan.Stage("platform-observation")
	if err != nil || len(stage.Inputs) != 1 || stage.Inputs[0].Name != "stage.platform-observation" || stage.Inputs[0].Digest != profileDigest || config.Profile.IntentRevision != plan.IntentRevision || config.Profile.PlatformRevision != plan.PlatformRevision || config.Profile.ExecutionFixture != plan.ExecutionFixture {
		return VerifiedPlatformObservationStageBundle{}, errors.New("platform observation profile differs from verified stage plan")
	}
	profile := config.Profile
	profile.RequiredApplications = append([]observation.PlatformApplicationExpectation(nil), config.Profile.RequiredApplications...)
	return VerifiedPlatformObservationStageBundle{plan: plan, cursor: cursor, prefix: prefix, profile: profile, profileDigest: profileDigest, verified: true}, nil
}

func (bundle VerifiedPlatformObservationStageBundle) Decision() (stagecursor.Decision, error) {
	if err := verifyPlatformObservationStageBundle(bundle); err != nil {
		return stagecursor.Decision{}, err
	}
	return bundle.cursor.Decision()
}

// Open reads bounded credentials and private runtime identity but performs no
// Kubernetes request and no capability action.
func (bundle VerifiedPlatformObservationStageBundle) Open(config PlatformObservationStageRuntimeConfig) (OpenedPlatformObservationStage, error) {
	if err := verifyPlatformObservationStageBundle(bundle); err != nil || config.Capability == nil || config.Clock == nil || config.Wait == nil {
		return OpenedPlatformObservationStage{}, errors.New("verified platform observation bundle, capability, clock, and waiter are required")
	}
	if err := verifyRuntimeBindingMaterial(config.Runtime); err != nil ||
		config.Runtime.receipt.PlanDigest != bundle.plan.PlanDigest || config.Runtime.material.PlanDigest != bundle.plan.PlanDigest ||
		config.Runtime.material.IntentRevision != bundle.plan.IntentRevision || config.Runtime.material.EnablementRevision != bundle.plan.EnablementRevision ||
		config.Runtime.material.PlatformRevision != bundle.plan.PlatformRevision || config.Runtime.material.ExecutionFixture != bundle.plan.ExecutionFixture ||
		config.Runtime.receipt.TargetClusterUIDDigest != digest.SHA256([]byte(config.Runtime.material.Target.CAPIClusterUID)) {
		return OpenedPlatformObservationStage{}, errors.New("platform observation runtime differs from verified execution target")
	}
	lifecycle, err := bundle.prefix[1].Receipt()
	if err != nil || lifecycle.TargetClusterUIDDigest != config.Runtime.receipt.TargetClusterUIDDigest {
		return OpenedPlatformObservationStage{}, errors.New("platform observation runtime differs from durable lifecycle target")
	}
	store, ledgerToken, err := openKubernetesLedger(config.Ledger)
	if err != nil {
		return OpenedPlatformObservationStage{}, errors.New("open platform observation ledger")
	}
	source, argoToken, err := openKubernetesPlatformSourceCollector(KubernetesPlatformObserverConfig{
		Argo: config.Argo, ExpectedArgoAuthority: bundle.plan.Authorities.GitOps,
		Profile: bundle.profile, Capability: config.Capability,
		TargetClusterUID: config.Runtime.material.Target.CAPIClusterUID, Clock: config.Clock,
	})
	if err != nil {
		return OpenedPlatformObservationStage{}, errors.New("open bounded platform observation source")
	}
	if sameSecret(ledgerToken, argoToken) {
		return OpenedPlatformObservationStage{}, errors.New("ledger and platform observation credentials must be distinct")
	}
	observer, err := NewPlatformStageObserver(PlatformStageObserverConfig{
		Plan: bundle.plan, ReceiptPrefix: bundle.prefix, TargetClusterUID: config.Runtime.material.Target.CAPIClusterUID,
		Source: source, Profile: bundle.profile, PollInterval: config.PollInterval, PollTimeout: config.PollTimeout,
		Clock: config.Clock, Wait: config.Wait,
	})
	if err != nil {
		return OpenedPlatformObservationStage{}, err
	}
	return OpenedPlatformObservationStage{
		operation: execution.ObservationStageOperation{Ledger: store, Observer: observer},
		plan:      bundle.plan, cursor: bundle.cursor, verified: true,
	}, nil
}

func (stage OpenedPlatformObservationStage) Run(ctx context.Context) (execution.ObservationStageRunReceipt, error) {
	if !stage.verified {
		return execution.ObservationStageRunReceipt{}, errors.New("platform observation stage is not opened")
	}
	return stage.operation.Run(ctx, stage.plan, stage.cursor)
}

func verifyPlatformObservationStageBundle(bundle VerifiedPlatformObservationStageBundle) error {
	if !bundle.verified || len(bundle.prefix) != 10 || !stageReceiptPrefixDigestPattern.MatchString(bundle.profileDigest) {
		return errors.New("platform observation stage bundle is not verified")
	}
	digest, err := observation.PlatformProfileDigest(bundle.profile)
	if err != nil || digest != bundle.profileDigest || bundle.profile.IntentRevision != bundle.plan.IntentRevision || bundle.profile.PlatformRevision != bundle.plan.PlatformRevision || bundle.profile.ExecutionFixture != bundle.plan.ExecutionFixture {
		return errors.New("platform observation profile changed after verification")
	}
	return nil
}
