package execution

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

// TargetAccessDispatchWireFormat is a serialization contract only. Decoding
// does not verify a stage grant, claim it, authorize execution, or permit a
// receiver to submit the included objects.
const TargetAccessDispatchWireFormat = "ok147-target-access-dispatch-wire/v1"

const maximumTargetAccessDispatchBytes = 1024 * 1024

type targetAccessDispatchWire struct {
	Format               string                `json:"format"`
	Mutation             StageMutationRequest  `json:"mutation"`
	DispatchID           string                `json:"dispatchId"`
	ArtifactDigest       string                `json:"artifactDigest"`
	TargetIdentityDigest string                `json:"targetIdentityDigest"`
	Plane                targetAccessWirePlane `json:"plane"`
}

type targetAccessWirePlane struct {
	Identity string                   `json:"identity"`
	Role     string                   `json:"role"`
	Objects  []targetAccessWireObject `json:"objects"`
}

type targetAccessWireObject struct {
	Identity       projection.ResourceIdentity `json:"identity"`
	Digest         string                      `json:"digest"`
	CollectionPath string                      `json:"collectionPath"`
	ObjectPath     string                      `json:"objectPath"`
	Raw            json.RawMessage             `json:"raw"`
}

// EncodeTargetAccessDispatch encodes the exact validated in-process dispatch
// while preserving every object byte. The result is not an executable command
// or proof that the dispatch is authorized or durably fenced.
func EncodeTargetAccessDispatch(dispatch TargetAccessDispatch) ([]byte, error) {
	wire, err := targetAccessDispatchToWire(dispatch)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) == 0 || len(raw) > maximumTargetAccessDispatchBytes {
		return nil, errors.New("target-access dispatch exceeds the bounded wire format")
	}
	return raw, nil
}

// DecodeTargetAccessDispatch validates the serialization envelope and returns
// its fields as untrusted data. Callers must independently verify the signed
// grant, plan, target identity, durable one-shot claim and object policy.
func DecodeTargetAccessDispatch(raw []byte) (TargetAccessDispatch, error) {
	if len(raw) == 0 || len(raw) > maximumTargetAccessDispatchBytes {
		return TargetAccessDispatch{}, errors.New("target-access dispatch wire size is invalid")
	}
	var wire targetAccessDispatchWire
	if err := jsonstrict.Decode(raw, &wire); err != nil {
		return TargetAccessDispatch{}, errors.New("target-access dispatch wire document is invalid")
	}
	dispatch, err := targetAccessDispatchFromWire(wire)
	if err != nil {
		return TargetAccessDispatch{}, err
	}
	// Reject alternate encodings and trailing bytes; the digest identity is over
	// the semantic envelope, while this also keeps stored request bytes stable.
	reencoded, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(raw, reencoded) {
		return TargetAccessDispatch{}, errors.New("target-access dispatch wire encoding is not canonical")
	}
	return dispatch, nil
}

func targetAccessDispatchToWire(dispatch TargetAccessDispatch) (targetAccessDispatchWire, error) {
	if !dispatch.Mutation.verifiedStageGrant {
		return targetAccessDispatchWire{}, errors.New("target-access dispatch requires a locally verified stage grant")
	}
	if len(dispatch.Plane.Objects) != submission.TargetAccessObjectCount || len(dispatch.Mutation.AuthorizationEnvelope) > 128*1024 {
		return targetAccessDispatchWire{}, errors.New("target-access dispatch exceeds the fixed object or authorization bounds")
	}
	contentBytes := len(dispatch.Mutation.AuthorizationEnvelope)
	for _, object := range dispatch.Plane.Objects {
		if len(object.Raw) > maximumTargetAccessDispatchBytes-contentBytes {
			return targetAccessDispatchWire{}, errors.New("target-access dispatch object content exceeds the wire bound")
		}
		contentBytes += len(object.Raw)
	}
	wire := targetAccessDispatchWire{
		Format: TargetAccessDispatchWireFormat, Mutation: cloneStageMutationRequest(dispatch.Mutation),
		DispatchID: dispatch.DispatchID, ArtifactDigest: dispatch.ArtifactDigest,
		TargetIdentityDigest: dispatch.TargetIdentityDigest,
		Plane: targetAccessWirePlane{Identity: dispatch.Plane.Identity, Role: dispatch.Plane.Role,
			Objects: make([]targetAccessWireObject, len(dispatch.Plane.Objects))},
	}
	for i, object := range dispatch.Plane.Objects {
		wire.Plane.Objects[i] = targetAccessWireObject{
			Identity: object.Identity, Digest: object.Digest, CollectionPath: object.CollectionPath,
			ObjectPath: object.ObjectPath, Raw: append(json.RawMessage(nil), object.Raw...),
		}
	}
	if err := validateTargetAccessDispatchWire(wire); err != nil {
		return targetAccessDispatchWire{}, err
	}
	return wire, nil
}

func targetAccessDispatchFromWire(wire targetAccessDispatchWire) (TargetAccessDispatch, error) {
	if err := validateTargetAccessDispatchWire(wire); err != nil {
		return TargetAccessDispatch{}, err
	}
	plane := submission.Plane{Identity: wire.Plane.Identity, Role: wire.Plane.Role, Objects: make([]submission.Object, len(wire.Plane.Objects))}
	for i, object := range wire.Plane.Objects {
		plane.Objects[i] = submission.Object{
			Identity: object.Identity, Digest: object.Digest, CollectionPath: object.CollectionPath,
			ObjectPath: object.ObjectPath, Raw: append(json.RawMessage(nil), object.Raw...),
		}
	}
	// verifiedStageGrant is intentionally false after decoding. Only the local
	// StagedOperation may produce a request with that private verification bit.
	mutation := cloneStageMutationRequest(wire.Mutation)
	mutation.verifiedStageGrant = false
	return TargetAccessDispatch{
		Mutation: mutation, DispatchID: wire.DispatchID, ArtifactDigest: wire.ArtifactDigest,
		TargetIdentityDigest: wire.TargetIdentityDigest, Plane: plane,
	}, nil
}

func validateTargetAccessDispatchWire(wire targetAccessDispatchWire) error {
	request := wire.Mutation
	if wire.Format != TargetAccessDispatchWireFormat || wire.DispatchID == "" ||
		!stagedDigestPattern.MatchString(wire.ArtifactDigest) || !stagedDigestPattern.MatchString(wire.TargetIdentityDigest) ||
		wire.Plane.Identity != wire.TargetIdentityDigest || wire.Plane.Role != "target-access-writer" ||
		len(wire.Plane.Objects) != submission.TargetAccessObjectCount ||
		request.GrantID == "" ||
		!stagedDigestPattern.MatchString(request.AuthorizationDigest) || !stagedDigestPattern.MatchString(request.AuthorizationKeyID) ||
		len(request.AuthorizationEnvelope) == 0 || len(request.AuthorizationEnvelope) > 128*1024 ||
		digest.SHA256(request.AuthorizationEnvelope) != request.AuthorizationDigest {
		return errors.New("target-access dispatch wire bindings are invalid")
	}
	if request.ContractIdentity.Name == "" || request.ContractIdentity.Namespace == "" ||
		!stagedDigestPattern.MatchString(request.PlanDigest) || !stagedDigestPattern.MatchString(request.StageDigest) ||
		!stagedDigestPattern.MatchString(request.PredecessorDigest) || !stagedDigestPattern.MatchString(request.ContractRevision) ||
		!stagedDigestPattern.MatchString(request.EnablementRevision) || !stagedDigestPattern.MatchString(request.PlatformRevision) ||
		!stagedDigestPattern.MatchString(request.ExecutionFixture) ||
		request.StageID != "target-access" || request.StageOrder <= 0 || request.Operation == "" || request.Authority == "" {
		return errors.New("target-access dispatch stage binding is invalid")
	}
	if request.ExecutionAttemptDigest != "" && !stagedDigestPattern.MatchString(request.ExecutionAttemptDigest) {
		return errors.New("target-access dispatch attempt binding is invalid")
	}
	if !stageClaimMatchesMutation(request) {
		return errors.New("target-access dispatch lacks the exact durable stage-claim binding")
	}
	expectedDispatchID, err := targetAccessDispatchID(request, wire.ArtifactDigest, wire.TargetIdentityDigest)
	if err != nil || expectedDispatchID != wire.DispatchID {
		return errors.New("target-access dispatch identity differs from its bound contents")
	}
	expectedKinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole", "ClusterRole"}
	seen := make(map[projection.ResourceIdentity]struct{}, len(wire.Plane.Objects))
	for i, object := range wire.Plane.Objects {
		if object.Identity.Kind != expectedKinds[i] || object.Identity.Name == "" || object.CollectionPath == "" ||
			object.ObjectPath == "" || len(object.Raw) == 0 || !stagedDigestPattern.MatchString(object.Digest) ||
			digest.SHA256(object.Raw) != object.Digest {
			return errors.New("target-access dispatch object is incomplete or has a different digest")
		}
		if _, duplicate := seen[object.Identity]; duplicate {
			return errors.New("target-access dispatch repeats an object identity")
		}
		seen[object.Identity] = struct{}{}
		if err := validateWireObjectIdentity(object); err != nil {
			return err
		}
	}
	return nil
}

func stageClaimMatchesMutation(request StageMutationRequest) bool {
	claim := request.StageClaim
	if claim.Format != ledger.StageClaimFormat || claim.State != "CLAIMED" || claim.GrantID != request.GrantID ||
		claim.AuthorizationDigest != request.AuthorizationDigest || claim.KeyID != request.AuthorizationKeyID ||
		claim.PlanDigest != request.PlanDigest || claim.StageID != request.StageID || claim.StageDigest != request.StageDigest ||
		claim.Operation != request.Operation || claim.Authority != request.Authority ||
		claim.PredecessorDigest != request.PredecessorDigest || claim.ContractRevision != request.ContractRevision {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, claim.ClaimedAt)
	return err == nil
}

func validateWireObjectIdentity(object targetAccessWireObject) error {
	var value map[string]any
	if err := jsonstrict.Decode(object.Raw, &value); err != nil {
		return errors.New("target-access dispatch raw object is invalid")
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return errors.New("target-access dispatch raw object identity differs from its envelope")
	}
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if value["apiVersion"] != object.Identity.APIVersion || value["kind"] != object.Identity.Kind ||
		name != object.Identity.Name || namespace != object.Identity.Namespace {
		return errors.New("target-access dispatch raw object identity differs from its envelope")
	}
	collection, err := targetAccessCollectionPath(object.Identity)
	if err != nil || object.CollectionPath != collection || object.ObjectPath != collection+"/"+object.Identity.Name {
		return errors.New("target-access dispatch object path differs from its identity")
	}
	return nil
}

func targetAccessCollectionPath(identity projection.ResourceIdentity) (string, error) {
	switch identity.Kind {
	case "Namespace":
		if identity.APIVersion != "v1" || identity.Namespace != "" {
			return "", errors.New("invalid Namespace identity in target-access dispatch")
		}
		return "/api/v1/namespaces", nil
	case "ServiceAccount":
		if identity.APIVersion != "v1" || identity.Namespace == "" {
			return "", errors.New("invalid ServiceAccount identity in target-access dispatch")
		}
		return "/api/v1/namespaces/" + identity.Namespace + "/serviceaccounts", nil
	case "ClusterRole":
		if identity.APIVersion != "rbac.authorization.k8s.io/v1" || identity.Namespace != "" {
			return "", errors.New("invalid ClusterRole identity in target-access dispatch")
		}
		return "/apis/rbac.authorization.k8s.io/v1/clusterroles", nil
	case "ClusterRoleBinding":
		if identity.APIVersion != "rbac.authorization.k8s.io/v1" || identity.Namespace != "" {
			return "", errors.New("invalid ClusterRoleBinding identity in target-access dispatch")
		}
		return "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", nil
	case "Role":
		if identity.APIVersion != "rbac.authorization.k8s.io/v1" || identity.Namespace == "" {
			return "", errors.New("invalid Role identity in target-access dispatch")
		}
		return "/apis/rbac.authorization.k8s.io/v1/namespaces/" + identity.Namespace + "/roles", nil
	case "RoleBinding":
		if identity.APIVersion != "rbac.authorization.k8s.io/v1" || identity.Namespace == "" {
			return "", errors.New("invalid RoleBinding identity in target-access dispatch")
		}
		return "/apis/rbac.authorization.k8s.io/v1/namespaces/" + identity.Namespace + "/rolebindings", nil
	default:
		return "", errors.New("target-access dispatch kind is outside the fixed allowlist")
	}
}

func cloneStageMutationRequest(request StageMutationRequest) StageMutationRequest {
	request.AuthorizationEnvelope = append([]byte(nil), request.AuthorizationEnvelope...)
	return request
}
