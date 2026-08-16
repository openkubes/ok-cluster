package runner

import (
	"errors"
	"regexp"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/observation"
)

const maximumNetworkProfileBytes = 64 * 1024

var networkProfileDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// NetworkProfileFileConfig binds one local semantic profile to an independently
// supplied digest plus the Contract-derived R and E identities.
type NetworkProfileFileConfig struct {
	Path                       string
	ExpectedProfileDigest      string
	ExpectedIntentRevision     string
	ExpectedEnablementRevision string
}

// LoadedNetworkProfile retains the verified profile identity used by the
// NetworkReady evaluator. It contains no source path or raw document.
type LoadedNetworkProfile struct {
	Profile observation.NetworkProfile
	Digest  string
}

// LoadNetworkProfileFile reads one bounded strict-JSON profile. The caller must
// obtain all expected identities from already verified execution inputs.
func LoadNetworkProfileFile(config NetworkProfileFileConfig) (LoadedNetworkProfile, error) {
	if config.Path == "" || !networkProfileDigestPattern.MatchString(config.ExpectedProfileDigest) || !networkProfileDigestPattern.MatchString(config.ExpectedIntentRevision) || !networkProfileDigestPattern.MatchString(config.ExpectedEnablementRevision) {
		return LoadedNetworkProfile{}, errors.New("network profile file binding is invalid")
	}
	raw, err := readBoundedRegular(config.Path, maximumNetworkProfileBytes)
	if err != nil {
		return LoadedNetworkProfile{}, errors.New("read bounded network profile")
	}
	var profile observation.NetworkProfile
	if err := jsonstrict.Decode(raw, &profile); err != nil {
		return LoadedNetworkProfile{}, errors.New("decode strict network profile")
	}
	if profile.IntentRevision != config.ExpectedIntentRevision || profile.EnablementRevision != config.ExpectedEnablementRevision {
		return LoadedNetworkProfile{}, errors.New("network profile revision differs from verified execution input")
	}
	digest, err := observation.NetworkProfileDigest(profile)
	if err != nil {
		return LoadedNetworkProfile{}, errors.New("validate semantic network profile")
	}
	if digest != config.ExpectedProfileDigest {
		return LoadedNetworkProfile{}, errors.New("network profile digest differs from verified execution input")
	}
	return LoadedNetworkProfile{Profile: profile, Digest: digest}, nil
}
