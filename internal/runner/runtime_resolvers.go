package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
)

const (
	WorkloadAuthorityBindingFormat = "ok147-workload-authority-binding/v1"
	maximumWorkloadBindingBytes    = 64 * 1024
)

var runtimeInputUIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// WorkloadAuthorityBinding is private durable correlation data for a later
// observation invocation. Credential bytes and local file paths are not part
// of this semantic record; its API endpoint still prevents public retention.
type WorkloadAuthorityBinding struct {
	Format               string `json:"format"`
	IntentRevision       string `json:"intentRevision"`
	TargetClusterUID     string `json:"targetClusterUid"`
	TargetIdentityScheme string `json:"targetIdentityScheme"`
	Endpoint             string `json:"endpoint"`
	CABundleDigest       string `json:"caBundleDigest"`
}

// WorkloadAuthorityFileResolverConfig binds the semantic record to separately
// mounted short-lived credential material. Paths are execution inputs and are
// deliberately excluded from the binding digest.
type WorkloadAuthorityFileResolverConfig struct {
	Path                  string
	ExpectedBindingDigest string
	TokenFile             string
	CAFile                string
}

// WorkloadAuthorityFileResolver reads and verifies the runtime binding only
// after submission has supplied a concrete target Cluster UID.
type WorkloadAuthorityFileResolver struct {
	config WorkloadAuthorityFileResolverConfig
}

// OpenWorkloadAuthorityFileResolver validates only the static configuration;
// it performs no file read and no API request.
func OpenWorkloadAuthorityFileResolver(config WorkloadAuthorityFileResolverConfig) (*WorkloadAuthorityFileResolver, error) {
	if config.Path == "" || config.TokenFile == "" || config.CAFile == "" || !platformInputDigestPattern.MatchString(config.ExpectedBindingDigest) {
		return nil, errors.New("workload authority file resolver binding is invalid")
	}
	return &WorkloadAuthorityFileResolver{config: config}, nil
}

func (resolver *WorkloadAuthorityFileResolver) ResolveWorkloadAuthority(ctx context.Context, policy observation.Policy) (KubernetesAuthorityConfig, error) {
	if resolver == nil {
		return KubernetesAuthorityConfig{}, errors.New("workload authority file resolver is required")
	}
	if err := ctx.Err(); err != nil {
		return KubernetesAuthorityConfig{}, errors.New("workload authority resolution cancelled")
	}
	if _, err := observation.PolicyDigest(policy); err != nil {
		return KubernetesAuthorityConfig{}, errors.New("runtime-bound observation policy is invalid")
	}
	raw, err := readBoundedRegular(resolver.config.Path, maximumWorkloadBindingBytes)
	if err != nil {
		return KubernetesAuthorityConfig{}, errors.New("read bounded workload authority binding")
	}
	var binding WorkloadAuthorityBinding
	if err := jsonstrict.Decode(raw, &binding); err != nil {
		return KubernetesAuthorityConfig{}, errors.New("decode strict workload authority binding")
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		return KubernetesAuthorityConfig{}, errors.New("validate workload authority binding")
	}
	if bindingDigest != resolver.config.ExpectedBindingDigest || binding.IntentRevision != policy.IntentRevision || binding.TargetClusterUID != policy.TargetClusterUID {
		return KubernetesAuthorityConfig{}, errors.New("workload authority binding differs from runtime-bound observation policy")
	}
	ca, err := readBoundedRegular(resolver.config.CAFile, maximumCABytes)
	if err != nil {
		return KubernetesAuthorityConfig{}, errors.New("read bounded workload API CA")
	}
	if digest.SHA256(ca) != binding.CABundleDigest {
		return KubernetesAuthorityConfig{}, errors.New("workload API CA differs from runtime binding")
	}
	return KubernetesAuthorityConfig{
		Endpoint: binding.Endpoint, AuthorityIdentity: policy.TargetClusterUID,
		TokenFile: resolver.config.TokenFile, CAFile: resolver.config.CAFile,
		CABundleDigest: binding.CABundleDigest,
	}, nil
}

// WorkloadAuthorityBindingDigest identifies the canonical, secret-free
// runtime correlation record.
func WorkloadAuthorityBindingDigest(binding WorkloadAuthorityBinding) (string, error) {
	if err := validateWorkloadAuthorityBinding(binding); err != nil {
		return "", err
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", err
	}
	canonical, err := contract.JCS(value)
	if err != nil {
		return "", err
	}
	return digest.SHA256(canonical), nil
}

func validateWorkloadAuthorityBinding(binding WorkloadAuthorityBinding) error {
	if binding.Format != WorkloadAuthorityBindingFormat || !platformInputDigestPattern.MatchString(binding.IntentRevision) || !runtimeInputUIDPattern.MatchString(binding.TargetClusterUID) || binding.TargetIdentityScheme != "capi-cluster-uid/v1" || !platformInputDigestPattern.MatchString(binding.CABundleDigest) {
		return errors.New("workload authority binding identity is invalid")
	}
	endpoint, err := url.Parse(binding.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("workload authority endpoint is invalid")
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("workload authority endpoint port is invalid")
	}
	return nil
}

// PlatformCapabilityFileResolverConfig binds one already produced capability
// assertion for resumable observation. The assertion digest must come from
// durable execution correlation data, not from the file itself.
type PlatformCapabilityFileResolverConfig struct {
	Path                   string
	ExpectedEvidenceDigest string
}

type PlatformCapabilityFileResolver struct {
	config PlatformCapabilityFileResolverConfig
}

// OpenPlatformCapabilityFileResolver performs no file read. The file is read
// only after the runtime policy and Platform profile have been correlated.
func OpenPlatformCapabilityFileResolver(config PlatformCapabilityFileResolverConfig) (*PlatformCapabilityFileResolver, error) {
	if config.Path == "" || !platformInputDigestPattern.MatchString(config.ExpectedEvidenceDigest) {
		return nil, errors.New("Platform capability file resolver binding is invalid")
	}
	return &PlatformCapabilityFileResolver{config: config}, nil
}

func (resolver *PlatformCapabilityFileResolver) ResolvePlatformCapability(ctx context.Context, policy observation.Policy, profile observation.PlatformProfile) (observation.PlatformCapabilitySource, error) {
	if resolver == nil {
		return nil, errors.New("Platform capability file resolver is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("Platform capability resolution cancelled")
	}
	if _, err := observation.PolicyDigest(policy); err != nil {
		return nil, errors.New("runtime-bound observation policy is invalid")
	}
	if _, err := observation.PlatformProfileDigest(profile); err != nil || profile.IntentRevision != policy.IntentRevision || profile.PlatformRevision != policy.PlatformRevision {
		return nil, errors.New("Platform profile differs from runtime-bound observation policy")
	}
	loaded, err := LoadPlatformCapabilityFile(PlatformCapabilityFileConfig{
		Path: resolver.config.Path, ExpectedEvidenceDigest: resolver.config.ExpectedEvidenceDigest,
		ExpectedIntentRevision: policy.IntentRevision, ExpectedPlatformRevision: policy.PlatformRevision,
		ExpectedExecutionFixture: profile.ExecutionFixture, ExpectedTargetClusterUID: policy.TargetClusterUID,
		ExpectedContractDigest: profile.CapabilityContractDigest, ExpectedExecutableDigest: profile.CapabilityExecutableDigest,
	})
	if err != nil {
		return nil, errors.New("load runtime-bound Platform capability evidence")
	}
	return loaded, nil
}

var _ WorkloadAuthorityResolver = (*WorkloadAuthorityFileResolver)(nil)
var _ PlatformCapabilityResolver = (*PlatformCapabilityFileResolver)(nil)
