// Package targetadmission contains the offline decision core for a future,
// fixed-purpose target-side Stage-7 admission adapter. It is not a Kubernetes
// admission server and does not install or authenticate its policy inputs.
// Callers must provision the policy from an independently reviewed source.
package targetadmission

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/projection"
	"github.com/openkubes/ok-cluster/internal/submission"
)

const (
	PolicyFormat   = "ok147-target-access-admission-policy/v2"
	MaxObjectBytes = 256 * 1024
	MaxPolicyBytes = 2 * 1024 * 1024
)

var stageSevenKinds = []string{
	"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding",
	"Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount",
	"Role", "RoleBinding", "ClusterRole", "ClusterRole", "ClusterRole",
	"ClusterRole", "ClusterRole",
}

var stageSevenAPIVersions = []string{
	"v1", "v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1",
	"rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1",
	"v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1",
	"rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1", "rbac.authorization.k8s.io/v1",
}

// Object is one independently provisioned allowlist entry. Raw must be copied
// from the verified target-access artifact; it must never come from a dispatch.
type Object struct {
	Identity projection.ResourceIdentity `json:"identity"`
	Digest   string                      `json:"digest"`
	Raw      []byte                      `json:"rawObject"`
}

// Config is trusted admission configuration, not a request payload. In a real
// deployment it must be installed/updated by an authority independent of the
// Stage-7 writer and bound to the verified target cluster before activation.
type Config struct {
	WriterUsername       string   `json:"writerUsername"`
	ArtifactDigest       string   `json:"artifactDigest"`
	IntentRevision       string   `json:"intentRevision"`
	PlatformRevision     string   `json:"platformRevision"`
	ExecutionFixture     string   `json:"executionFixture"`
	TargetIdentityDigest string   `json:"targetIdentityDigest"`
	APIServerSourceCIDRs []string `json:"apiServerSourceCidrs"`
	Objects              []Object `json:"objects"`
}

type Policy struct {
	writerUsername       string
	artifactDigest       string
	intentRevision       string
	platformRevision     string
	executionFixture     string
	targetIdentityDigest string
	apiServerSourceCIDRs []netip.Prefix
	objects              []compiledObject
	digest               string
}

type compiledObject struct {
	identity  projection.ResourceIdentity
	digest    string
	canonical []byte
}

type policyDigestObject struct {
	Identity projection.ResourceIdentity `json:"identity"`
	Digest   string                      `json:"digest"`
}

type policyDigestDocument struct {
	Format               string               `json:"format"`
	WriterUsername       string               `json:"writerUsername"`
	ArtifactDigest       string               `json:"artifactDigest"`
	IntentRevision       string               `json:"intentRevision"`
	PlatformRevision     string               `json:"platformRevision"`
	ExecutionFixture     string               `json:"executionFixture"`
	TargetIdentityDigest string               `json:"targetIdentityDigest"`
	APIServerSourceCIDRs []string             `json:"apiServerSourceCidrs"`
	Objects              []policyDigestObject `json:"objects"`
}

type Request struct {
	Operation string
	Username  string
	Object    []byte
}

// New compiles a closed allowlist for the exact sixteen-object Stage-7 set.
// It authenticates neither Config nor the cluster on which a caller installs it.
func New(config Config) (*Policy, error) {
	parts := strings.Split(config.WriterUsername, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" ||
		len(config.WriterUsername) > 256 || !validDigest(config.ArtifactDigest) || !validDigest(config.IntentRevision) ||
		!validDigest(config.PlatformRevision) || !validDigest(config.ExecutionFixture) || !validDigest(config.TargetIdentityDigest) ||
		len(config.Objects) != submission.TargetAccessObjectCount {
		return nil, errors.New("trusted Stage-7 admission configuration is incomplete")
	}
	peerCIDRs, err := compileAPIServerSourceCIDRs(config.APIServerSourceCIDRs)
	if err != nil {
		return nil, err
	}
	policy := &Policy{
		writerUsername: config.WriterUsername, artifactDigest: config.ArtifactDigest,
		intentRevision: config.IntentRevision, platformRevision: config.PlatformRevision,
		executionFixture: config.ExecutionFixture, targetIdentityDigest: config.TargetIdentityDigest,
		apiServerSourceCIDRs: peerCIDRs,
		objects:              make([]compiledObject, 0, len(config.Objects)),
	}
	seen := make(map[projection.ResourceIdentity]struct{}, len(config.Objects))
	total := 0
	for index, object := range config.Objects {
		if object.Identity.Kind != stageSevenKinds[index] || object.Identity.APIVersion != stageSevenAPIVersions[index] ||
			object.Identity.Name == "" || !validDigest(object.Digest) || len(object.Raw) == 0 || len(object.Raw) > MaxObjectBytes ||
			digest.SHA256(object.Raw) != object.Digest {
			return nil, fmt.Errorf("trusted Stage-7 object %d is invalid", index)
		}
		if _, duplicate := seen[object.Identity]; duplicate {
			return nil, errors.New("trusted Stage-7 object identities are not unique")
		}
		seen[object.Identity] = struct{}{}
		canonical, identity, err := canonicalObject(object.Raw)
		if err != nil || identity != object.Identity {
			return nil, fmt.Errorf("trusted Stage-7 object %d identity is invalid", index)
		}
		total += len(canonical)
		if total > MaxPolicyBytes {
			return nil, errors.New("trusted Stage-7 admission policy exceeds size limit")
		}
		policy.objects = append(policy.objects, compiledObject{identity: object.Identity, digest: object.Digest, canonical: canonical})
	}
	policyObjects := make([]policyDigestObject, len(policy.objects))
	for i, object := range policy.objects {
		policyObjects[i] = policyDigestObject{Identity: object.identity, Digest: object.digest}
	}
	policyBytes, err := json.Marshal(policyDigestDocument{
		Format: PolicyFormat, WriterUsername: policy.writerUsername, ArtifactDigest: policy.artifactDigest,
		IntentRevision: policy.intentRevision, PlatformRevision: policy.platformRevision,
		ExecutionFixture:     policy.executionFixture,
		TargetIdentityDigest: policy.targetIdentityDigest,
		APIServerSourceCIDRs: append([]string(nil), config.APIServerSourceCIDRs...), Objects: policyObjects,
	})
	if err != nil {
		return nil, errors.New("derive trusted Stage-7 admission policy digest")
	}
	policy.digest = digest.SHA256(policyBytes)
	return policy, nil
}

// NewFromPlan compiles the allowlist from the verified output of
// submission.LoadTargetAccess. It rechecks all public bindings and each raw
// object's digest/identity. The caller must still ensure the plan was actually
// produced by that verifier and install this policy independently.
func NewFromPlan(writerUsername string, apiServerSourceCIDRs []string, plan submission.TargetAccessPlan) (*Policy, error) {
	if plan.Format != submission.TargetAccessPlanFormat || plan.MutationAllowed ||
		!validDigest(plan.ArtifactDigest) || !validDigest(plan.IntentRevision) ||
		!validDigest(plan.PlatformRevision) || !validDigest(plan.ExecutionFixture) ||
		!validDigest(plan.TargetIdentityDigest) || plan.Workload.Identity != plan.TargetIdentityDigest ||
		plan.Workload.Role != "target-access-writer" || len(plan.Workload.Objects) != submission.TargetAccessObjectCount {
		return nil, errors.New("verified target-access plan is required")
	}
	objects := make([]Object, len(plan.Workload.Objects))
	for i, object := range plan.Workload.Objects {
		if object.CollectionPath == "" || object.ObjectPath != object.CollectionPath+"/"+object.Identity.Name {
			return nil, fmt.Errorf("verified target-access object %d path is invalid", i)
		}
		objects[i] = Object{Identity: object.Identity, Digest: object.Digest, Raw: append([]byte(nil), object.Raw...)}
	}
	return New(Config{
		WriterUsername: writerUsername, ArtifactDigest: plan.ArtifactDigest,
		IntentRevision: plan.IntentRevision, PlatformRevision: plan.PlatformRevision,
		ExecutionFixture: plan.ExecutionFixture, TargetIdentityDigest: plan.TargetIdentityDigest,
		APIServerSourceCIDRs: append([]string(nil), apiServerSourceCIDRs...),
		Objects:              objects,
	})
}

func (policy *Policy) Digest() string {
	if policy == nil {
		return ""
	}
	return policy.digest
}

// AllowsAPIServerPeer checks the actual transport peer. Forwarded headers are
// intentionally ignored because a direct in-cluster caller can forge them.
func (policy *Policy) AllowsAPIServerPeer(remoteAddr string) bool {
	if policy == nil || len(policy.apiServerSourceCIDRs) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	address = address.WithZone("").Unmap()
	for _, prefix := range policy.apiServerSourceCIDRs {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func compileAPIServerSourceCIDRs(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 || len(values) > 32 {
		return nil, errors.New("trusted API server source CIDR allowlist is required and must be bounded")
	}
	prefixes := make([]netip.Prefix, len(values))
	for index, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || prefix != prefix.Masked() || prefix.Bits() == 0 {
			return nil, errors.New("trusted API server source CIDR allowlist is invalid or noncanonical")
		}
		if index > 0 && values[index-1] >= value {
			return nil, errors.New("trusted API server source CIDRs must be sorted and unique")
		}
		for previous := 0; previous < index; previous++ {
			if prefix.Overlaps(prefixes[previous]) {
				return nil, errors.New("trusted API server source CIDRs must not overlap")
			}
		}
		prefixes[index] = prefix
	}
	return prefixes, nil
}

// AdmitCreate allows only an exact semantic copy of an allowlisted object from
// the designated writer. Every non-CREATE request and every mismatch is denied.
func (policy *Policy) AdmitCreate(request Request) error {
	if policy == nil || policy.digest == "" || request.Operation != "CREATE" || request.Username != policy.writerUsername ||
		len(request.Object) == 0 || len(request.Object) > MaxObjectBytes {
		return errors.New("target-access admission denied")
	}
	canonical, identity, err := canonicalObject(request.Object)
	if err != nil {
		return errors.New("target-access admission denied")
	}
	for _, expected := range policy.objects {
		if identity == expected.identity {
			if digest.SHA256(expected.canonical) != digest.SHA256(canonical) {
				return errors.New("target-access admission denied")
			}
			return nil
		}
	}
	return errors.New("target-access admission denied")
}

func canonicalObject(raw []byte) ([]byte, projection.ResourceIdentity, error) {
	var value map[string]any
	if err := jsonstrict.Decode(raw, &value); err != nil {
		return nil, projection.ResourceIdentity{}, err
	}
	apiVersion, _ := value["apiVersion"].(string)
	kind, _ := value["kind"].(string)
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return nil, projection.ResourceIdentity{}, errors.New("object metadata is required")
	}
	name, _ := metadata["name"].(string)
	namespace, _ := metadata["namespace"].(string)
	if apiVersion == "" || kind == "" || name == "" {
		return nil, projection.ResourceIdentity{}, errors.New("object identity is incomplete")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, projection.ResourceIdentity{}, err
	}
	return canonical, projection.ResourceIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name}, nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}
