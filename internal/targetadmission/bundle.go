package targetadmission

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const SignedBundleFormat = "ok147-target-access-signed-policy/v2"

var signedBundleDomain = []byte("openkubes/ok147/target-access-policy/v2\x00")

// TargetBinding is supplied by the independent platform authority after it
// verifies runtime binding evidence. The namespace UID is checked again by
// the in-cluster webhook process before it becomes ready.
type TargetBinding struct {
	CAPIClusterUID         string `json:"capiClusterUid"`
	KubeSystemNamespaceUID string `json:"kubeSystemNamespaceUid"`
}

type SignedBundle struct {
	Format    string        `json:"format"`
	Policy    Config        `json:"policy"`
	Target    TargetBinding `json:"target"`
	Signature string        `json:"signature"`
}

type verifiedBundleDocument struct {
	Format string        `json:"format"`
	Policy Config        `json:"policy"`
	Target TargetBinding `json:"target"`
}

// SignBundle is intended for an independently controlled platform signer.
// Its private key must never be held by ok-cli or the Stage-7 writer.
func SignBundle(config Config, target TargetBinding, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize || validateTargetBinding(config, target) != nil {
		return nil, errors.New("independent target policy signing inputs are invalid")
	}
	if _, err := New(config); err != nil {
		return nil, fmt.Errorf("compile target policy before signing: %w", err)
	}
	document := verifiedBundleDocument{Format: SignedBundleFormat, Policy: cloneConfig(config), Target: target}
	canonical, err := json.Marshal(document)
	if err != nil {
		return nil, errors.New("encode target policy signing document")
	}
	signature := ed25519.Sign(privateKey, append(append([]byte(nil), signedBundleDomain...), canonical...))
	bundle := SignedBundle{Format: SignedBundleFormat, Policy: document.Policy, Target: target, Signature: encodeSignature(signature)}
	encoded, err := json.Marshal(bundle)
	if err != nil || len(encoded) > MaxPolicyBytes {
		return nil, errors.New("encode bounded signed target policy")
	}
	return append(encoded, '\n'), nil
}

// VerifyBundle authenticates the policy with an out-of-band pinned platform
// public key, then compiles it. Verification does not install or activate it.
func VerifyBundle(raw []byte, trustedKey ed25519.PublicKey) (*Policy, TargetBinding, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes || len(trustedKey) != ed25519.PublicKeySize {
		return nil, TargetBinding{}, errors.New("signed target policy bundle or pinned key is invalid")
	}
	var bundle SignedBundle
	if err := jsonstrict.Decode(raw, &bundle); err != nil || bundle.Format != SignedBundleFormat {
		return nil, TargetBinding{}, errors.New("signed target policy bundle is invalid")
	}
	if err := validateTargetBinding(bundle.Policy, bundle.Target); err != nil {
		return nil, TargetBinding{}, err
	}
	signature, err := decodeSignature(bundle.Signature)
	if err != nil {
		return nil, TargetBinding{}, errors.New("signed target policy signature is invalid")
	}
	document := verifiedBundleDocument{Format: bundle.Format, Policy: cloneConfig(bundle.Policy), Target: bundle.Target}
	canonical, err := json.Marshal(document)
	if err != nil || !ed25519.Verify(trustedKey, append(append([]byte(nil), signedBundleDomain...), canonical...), signature) {
		return nil, TargetBinding{}, errors.New("signed target policy signature verification failed")
	}
	policy, err := New(bundle.Policy)
	if err != nil {
		return nil, TargetBinding{}, fmt.Errorf("compile verified target policy: %w", err)
	}
	return policy, bundle.Target, nil
}

// VerifyTargetBinding prevents a correctly signed bundle for a different
// workload cluster from activating in this process. namespaceUID must be read
// from the live in-cluster Kubernetes API using a narrowly scoped identity.
func VerifyTargetBinding(expected TargetBinding, actualKubeSystemNamespaceUID string) error {
	if expected.CAPIClusterUID == "" || expected.KubeSystemNamespaceUID == "" || actualKubeSystemNamespaceUID == "" ||
		expected.KubeSystemNamespaceUID != actualKubeSystemNamespaceUID {
		return errors.New("signed policy target does not match this Kubernetes cluster")
	}
	return nil
}

func validateTargetBinding(config Config, target TargetBinding) error {
	if target.CAPIClusterUID == "" || len(target.CAPIClusterUID) > 128 || target.KubeSystemNamespaceUID == "" || len(target.KubeSystemNamespaceUID) > 128 ||
		config.TargetIdentityDigest != digest.SHA256([]byte(target.CAPIClusterUID)) {
		return errors.New("signed target policy binding does not match the runtime target identity")
	}
	return nil
}

func cloneConfig(source Config) Config {
	clone := source
	clone.APIServerSourceCIDRs = append([]string(nil), source.APIServerSourceCIDRs...)
	clone.Objects = make([]Object, len(source.Objects))
	for index, object := range source.Objects {
		clone.Objects[index] = Object{Identity: object.Identity, Digest: object.Digest, Raw: append([]byte(nil), object.Raw...)}
	}
	return clone
}

func encodeSignature(signature []byte) string { return hex.EncodeToString(signature) }

func decodeSignature(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature")
	}
	return decoded, nil
}

// PublicKeyFingerprint is a display-only pin identifier for review records.
func PublicKeyFingerprint(key ed25519.PublicKey) string {
	if len(key) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(sum[:])
}
