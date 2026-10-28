package execution

import (
	"context"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
)

// TargetAccessWireObjectExpectation is independently derived from the
// receiver's trusted plan/profile, never from the dispatch being verified.
type TargetAccessWireObjectExpectation struct {
	Identity       projection.ResourceIdentity
	Digest         string
	CollectionPath string
	ObjectPath     string
}

// TargetAccessWireExpectation is trusted receiver configuration. In
// particular, RequiredPredecessors, the pinned public key, target identity and
// expected object set must not be populated from the untrusted wire request.
type TargetAccessWireExpectation struct {
	Authorization        authorization.StageDispatchExpectation
	TrustedPublicKey     []byte
	ArtifactDigest       string
	TargetIdentityDigest string
	Objects              []TargetAccessWireObjectExpectation
}

// VerifyTargetAccessDispatchWire checks the serialized request against
// receiver-owned expectations and verifies its Ed25519 stage grant. It is an
// offline preflight only: it does not persist a claim, check runtime Cluster
// identity, apply target admission policy or authorize a Kubernetes write.
func VerifyTargetAccessDispatchWire(raw []byte, expected TargetAccessWireExpectation, at time.Time) (TargetAccessDispatch, error) {
	dispatch, err := DecodeTargetAccessDispatch(raw)
	if err != nil {
		return TargetAccessDispatch{}, err
	}
	request := dispatch.Mutation
	grant := expected.Authorization
	if len(expected.Objects) != len(dispatch.Plane.Objects) || len(expected.Objects) == 0 ||
		dispatch.ArtifactDigest != expected.ArtifactDigest || dispatch.TargetIdentityDigest != expected.TargetIdentityDigest ||
		request.AuthorizationDigest != grant.AuthorizationDigest || request.AuthorizationKeyID != grant.AuthorizationKeyID ||
		request.GrantID != grant.GrantID || request.PlanDigest != grant.PlanDigest || request.ContractIdentity != grant.ContractIdentity ||
		request.ContractRevision != grant.ContractRevision || request.EnablementRevision != grant.EnablementRevision ||
		request.PlatformRevision != grant.PlatformRevision || request.ExecutionFixture != grant.ExecutionFixture ||
		request.ExecutionAttemptDigest != grant.ExecutionAttempt || request.StageID != grant.StageID ||
		request.StageOrder != grant.StageOrder || request.StageDigest != grant.StageDigest ||
		request.Operation != grant.Operation || request.Authority != grant.Authority ||
		request.PredecessorDigest != grant.PredecessorDigest ||
		dispatch.TargetIdentityDigest != dispatch.Plane.Identity {
		return TargetAccessDispatch{}, errors.New("target-access dispatch differs from receiver-owned expectations")
	}
	for index, object := range dispatch.Plane.Objects {
		want := expected.Objects[index]
		if object.Identity != want.Identity || object.Digest != want.Digest ||
			object.CollectionPath != want.CollectionPath || object.ObjectPath != want.ObjectPath {
			return TargetAccessDispatch{}, errors.New("target-access dispatch object set differs from receiver-owned expectations")
		}
	}
	claimedAt, err := time.Parse(time.RFC3339Nano, request.StageClaim.ClaimedAt)
	if err != nil || claimedAt.After(at) {
		return TargetAccessDispatch{}, errors.New("target-access dispatch carries a future or invalid stage-claim time")
	}
	if err := authorization.VerifyStageDispatchAuthorization(request.AuthorizationEnvelope, expected.TrustedPublicKey, grant, at); err != nil {
		return TargetAccessDispatch{}, errors.New("target-access dispatch stage authorization was not accepted")
	}
	return dispatch, nil
}

// VerifyTargetAccessDispatchWithLedger performs the complete read-only
// receiver preflight: verify the signed dispatch, then reread its exact stage
// claim from the durable ledger and require that no terminal outcome exists
// yet. It performs no claim write, target API call or mutation. A successful
// return is still not permission to execute; the receiver needs its own atomic
// create-only dispatch fence and target admission boundary before submitting
// any object.
func VerifyTargetAccessDispatchWithLedger(ctx context.Context, raw []byte, expected TargetAccessWireExpectation, at time.Time, stageLedger *ledger.Ledger) (TargetAccessDispatch, string, error) {
	if stageLedger == nil {
		return TargetAccessDispatch{}, "", errors.New("durable stage ledger is required for target-access dispatch")
	}
	dispatch, err := VerifyTargetAccessDispatchWire(raw, expected, at)
	if err != nil {
		return TargetAccessDispatch{}, "", err
	}
	claimDigest, err := stageLedger.VerifyPendingStageClaim(ctx, dispatch.Mutation.StageClaim)
	if err != nil {
		return TargetAccessDispatch{}, "", errors.New("target-access dispatch stage claim is not pending in the durable ledger")
	}
	return dispatch, claimDigest, nil
}
