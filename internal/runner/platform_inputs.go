package runner

import (
	"context"
	"errors"
	"regexp"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
)

const (
	maximumPlatformProfileBytes    = 64 * 1024
	maximumPlatformCapabilityBytes = 64 * 1024
)

var platformInputDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PlatformProfileFileConfig binds a strict local profile to identities from
// already verified execution inputs. The path itself is never retained.
type PlatformProfileFileConfig struct {
	Path                     string
	ExpectedProfileDigest    string
	ExpectedIntentRevision   string
	ExpectedPlatformRevision string
	ExpectedExecutionFixture string
}

type LoadedPlatformProfile struct {
	Profile observation.PlatformProfile
	Digest  string
}

// LoadPlatformProfileFile reads one bounded regular strict-JSON document and
// rejects any semantic or canonical-identity difference from its bindings.
func LoadPlatformProfileFile(config PlatformProfileFileConfig) (LoadedPlatformProfile, error) {
	if config.Path == "" || !platformInputDigestPattern.MatchString(config.ExpectedProfileDigest) || !platformInputDigestPattern.MatchString(config.ExpectedIntentRevision) || !platformInputDigestPattern.MatchString(config.ExpectedPlatformRevision) || !platformInputDigestPattern.MatchString(config.ExpectedExecutionFixture) {
		return LoadedPlatformProfile{}, errors.New("platform profile file binding is invalid")
	}
	raw, err := readBoundedRegular(config.Path, maximumPlatformProfileBytes)
	if err != nil {
		return LoadedPlatformProfile{}, errors.New("read bounded platform profile")
	}
	var profile observation.PlatformProfile
	if err := jsonstrict.Decode(raw, &profile); err != nil {
		return LoadedPlatformProfile{}, errors.New("decode strict platform profile")
	}
	if profile.IntentRevision != config.ExpectedIntentRevision || profile.PlatformRevision != config.ExpectedPlatformRevision || profile.ExecutionFixture != config.ExpectedExecutionFixture {
		return LoadedPlatformProfile{}, errors.New("platform profile identity differs from verified execution input")
	}
	digest, err := observation.PlatformProfileDigest(profile)
	if err != nil {
		return LoadedPlatformProfile{}, errors.New("validate semantic platform profile")
	}
	if digest != config.ExpectedProfileDigest {
		return LoadedPlatformProfile{}, errors.New("platform profile digest differs from verified execution input")
	}
	return LoadedPlatformProfile{Profile: profile, Digest: digest}, nil
}

// PlatformCapabilityFileConfig binds a redaction-safe assertion to all of the
// identities that make it relevant to the current execution.
type PlatformCapabilityFileConfig struct {
	Path                     string
	ExpectedEvidenceDigest   string
	ExpectedIntentRevision   string
	ExpectedPlatformRevision string
	ExpectedExecutionFixture string
	ExpectedTargetClusterUID string
	ExpectedContractDigest   string
	ExpectedExecutableDigest string
}

// LoadedPlatformCapability is an immutable in-memory capability source. Raw
// bytes and the input path are discarded before it can be passed to the Argo
// collector.
type LoadedPlatformCapability struct {
	state  observation.PlatformCapabilityState
	digest string
}

func (loaded LoadedPlatformCapability) Capability(ctx context.Context) (observation.PlatformCapabilityState, error) {
	if err := ctx.Err(); err != nil {
		return observation.PlatformCapabilityState{}, err
	}
	return loaded.state, nil
}

func (loaded LoadedPlatformCapability) EvidenceDigest() string {
	return loaded.digest
}

// LoadPlatformCapabilityFile verifies one previously produced capability
// assertion. It never executes the capability test or reads cluster state.
func LoadPlatformCapabilityFile(config PlatformCapabilityFileConfig) (LoadedPlatformCapability, error) {
	if config.Path == "" || !platformInputDigestPattern.MatchString(config.ExpectedEvidenceDigest) || !platformInputDigestPattern.MatchString(config.ExpectedIntentRevision) || !platformInputDigestPattern.MatchString(config.ExpectedPlatformRevision) || !platformInputDigestPattern.MatchString(config.ExpectedExecutionFixture) || config.ExpectedTargetClusterUID == "" || !platformInputDigestPattern.MatchString(config.ExpectedContractDigest) || !platformInputDigestPattern.MatchString(config.ExpectedExecutableDigest) {
		return LoadedPlatformCapability{}, errors.New("platform capability file binding is invalid")
	}
	raw, err := readBoundedRegular(config.Path, maximumPlatformCapabilityBytes)
	if err != nil {
		return LoadedPlatformCapability{}, errors.New("read bounded platform capability evidence")
	}
	var state observation.PlatformCapabilityState
	if err := jsonstrict.Decode(raw, &state); err != nil {
		return LoadedPlatformCapability{}, errors.New("decode strict platform capability evidence")
	}
	if err := observation.ValidatePlatformCapabilityState(state); err != nil {
		return LoadedPlatformCapability{}, errors.New("validate platform capability evidence")
	}
	if state.EvidenceDigest != config.ExpectedEvidenceDigest || state.IntentRevision != config.ExpectedIntentRevision || state.PlatformRevision != config.ExpectedPlatformRevision || state.ExecutionFixture != config.ExpectedExecutionFixture || state.TargetClusterUID != config.ExpectedTargetClusterUID || state.ContractDigest != config.ExpectedContractDigest || state.ExecutableDigest != config.ExpectedExecutableDigest {
		return LoadedPlatformCapability{}, errors.New("platform capability identity differs from verified execution input")
	}
	return LoadedPlatformCapability{state: state, digest: state.EvidenceDigest}, nil
}

var _ observation.PlatformCapabilitySource = LoadedPlatformCapability{}
