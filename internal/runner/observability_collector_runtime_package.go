package runner

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const (
	ObservabilityCollectorRuntimePackageFormat = "ok147-observability-collector-runtime-package/v1"
	maximumObservabilityCollectorRuntimeBytes  = 2 * 1024 * 1024
)

type ObservabilityCollectorRuntimePackageConfig struct {
	Activation        ObservabilityCollectorActivationPackageConfig
	JobTemplate       []byte
	JobTemplateDigest string
	RunID             string
	ImageDigest       string
	WorkloadAPICIDR   string
	AlertSourceCIDR   string
}

type ObservabilityCollectorRuntimePackageReceipt struct {
	Format                    string   `json:"format"`
	State                     string   `json:"state"`
	PackageDigest             string   `json:"packageDigest"`
	ActivationSecret          string   `json:"activationSecret"`
	ActivationObjectDigest    string   `json:"activationObjectDigest"`
	ActivationDigest          string   `json:"activationDigest"`
	ManifestDigest            string   `json:"manifestDigest"`
	RuntimeBindingDigest      string   `json:"runtimeBindingDigest"`
	PublicEndpointDigest      string   `json:"publicEndpointDigest"`
	TLSCertificateDigest      string   `json:"tlsCertificateDigest"`
	ReceiverIdentityDigest    string   `json:"receiverIdentityDigest"`
	ProfileDigest             string   `json:"profileDigest"`
	ServiceObjectDigest       string   `json:"serviceObjectDigest"`
	NetworkPolicyObjectDigest string   `json:"networkPolicyObjectDigest"`
	JobObjectDigest           string   `json:"jobObjectDigest"`
	JobEnvelopeDigest         string   `json:"jobEnvelopeDigest"`
	JobTemplateDigest         string   `json:"jobTemplateDigest"`
	ImageDigest               string   `json:"imageDigest"`
	ObjectKinds               []string `json:"objectKinds"`
	MutationAllowed           bool     `json:"mutationAllowed"`
}

type VerifiedObservabilityCollectorRuntimePackage struct {
	raw      []byte
	receipt  ObservabilityCollectorRuntimePackageReceipt
	verified bool
}

type ObservabilityCollectorRuntimePackageFileConfig struct {
	PackagePath           string
	ReceiptPath           string
	ExpectedReceiptDigest string
}

// LoadObservabilityCollectorRuntimePackage reconstructs one verified private
// package from a 0600 local file and an exact public receipt identity. It does
// not open a Kubernetes credential or contact any API.
func LoadObservabilityCollectorRuntimePackage(config ObservabilityCollectorRuntimePackageFileConfig) (VerifiedObservabilityCollectorRuntimePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.ExpectedReceiptDigest) {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("observability collector receipt identity is invalid")
	}
	info, err := os.Lstat(config.PackagePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("observability collector private package permissions are invalid")
	}
	raw, err := readBoundedRegular(config.PackagePath, maximumObservabilityCollectorRuntimeBytes)
	if err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("read bounded observability collector private package")
	}
	receiptRaw, err := readBoundedRegular(config.ReceiptPath, maximumRuntimeBindingMaterialFileBytes)
	if err != nil || digest.SHA256(receiptRaw) != config.ExpectedReceiptDigest {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("observability collector public receipt differs from expected identity")
	}
	var receipt ObservabilityCollectorRuntimePackageReceipt
	if err := jsonstrict.Decode(receiptRaw, &receipt); err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("decode strict observability collector public receipt")
	}
	packaged := VerifiedObservabilityCollectorRuntimePackage{raw: raw, receipt: receipt, verified: true}
	if err := verifyObservabilityCollectorRuntimePackage(packaged); err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("verify replayed observability collector runtime package")
	}
	return packaged, nil
}

// BuildObservabilityCollectorRuntimePackage composes the private activation,
// one LoadBalancer Service, exact NetworkPolicy and time-limited non-retrying
// Job into a single offline installation unit.
func BuildObservabilityCollectorRuntimePackage(config ObservabilityCollectorRuntimePackageConfig) (VerifiedObservabilityCollectorRuntimePackage, error) {
	if !stageReceiptPrefixDigestPattern.MatchString(config.JobTemplateDigest) ||
		digest.SHA256(config.JobTemplate) != config.JobTemplateDigest {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("observability collector Job template differs from expected identity")
	}
	activationPackage, err := BuildObservabilityCollectorActivationPackage(config.Activation)
	if err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, err
	}
	activationReceipt, err := activationPackage.Receipt()
	if err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, err
	}
	activationObject, err := activationPackage.PrivateBytes()
	if err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, err
	}
	activation, err := observabilityCollectorActivationFromSecret(activationObject)
	if err != nil || activation.ManifestDigest != activationReceipt.ManifestDigest ||
		activation.RuntimeBindingDigest != activationReceipt.RuntimeBindingDigest ||
		digest.SHA256([]byte(activation.PublicEndpoint)) != activationReceipt.PublicEndpointDigest {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("observability collector runtime activation differs")
	}
	jobEnvelope, err := RenderObservabilityCollectorJobTemplate(config.JobTemplate, ObservabilityCollectorJobValues{
		RunID: config.RunID, ImageDigest: config.ImageDigest, ActivationSecret: activationReceipt.ActivationSecret,
		ActivationDigest: activationReceipt.ActivationDigest, ManifestDigest: activationReceipt.ManifestDigest,
		RuntimeBindingDigest: activationReceipt.RuntimeBindingDigest, PublicEndpointDigest: activationReceipt.PublicEndpointDigest,
		PublicEndpoint: activation.PublicEndpoint, WorkloadAPIURL: activation.WorkloadEndpoint,
		WorkloadAPICIDR: config.WorkloadAPICIDR, AlertSourceCIDR: config.AlertSourceCIDR,
	})
	if err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, err
	}
	jobObjects := bytes.Split(jobEnvelope, []byte("\n---\n"))
	if len(jobObjects) != 3 {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("observability collector Job envelope object count differs")
	}
	packageRaw := bytes.Join([][]byte{activationObject, jobEnvelope}, []byte("\n---\n"))
	if len(packageRaw) > maximumObservabilityCollectorRuntimeBytes {
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("observability collector runtime package exceeds size limit")
	}
	receipt := ObservabilityCollectorRuntimePackageReceipt{
		Format: ObservabilityCollectorRuntimePackageFormat, State: "VERIFIED",
		PackageDigest: digest.SHA256(packageRaw), ActivationSecret: activationReceipt.ActivationSecret,
		ActivationObjectDigest: digest.SHA256(activationObject), ActivationDigest: activationReceipt.ActivationDigest,
		ManifestDigest: activationReceipt.ManifestDigest, RuntimeBindingDigest: activationReceipt.RuntimeBindingDigest,
		PublicEndpointDigest: activationReceipt.PublicEndpointDigest, TLSCertificateDigest: activationReceipt.TLSCertificateDigest,
		ReceiverIdentityDigest: activationReceipt.ReceiverIdentityDigest, ProfileDigest: activationReceipt.ProfileDigest,
		ServiceObjectDigest: digest.SHA256(jobObjects[0]), NetworkPolicyObjectDigest: digest.SHA256(jobObjects[1]),
		JobObjectDigest: digest.SHA256(jobObjects[2]), JobEnvelopeDigest: digest.SHA256(jobEnvelope),
		JobTemplateDigest: config.JobTemplateDigest, ImageDigest: config.ImageDigest,
		ObjectKinds: []string{"Secret", "Service", "NetworkPolicy", "Job"}, MutationAllowed: false,
	}
	packaged := VerifiedObservabilityCollectorRuntimePackage{raw: packageRaw, receipt: receipt, verified: true}
	if err := verifyObservabilityCollectorRuntimePackage(packaged); err != nil {
		return VerifiedObservabilityCollectorRuntimePackage{}, err
	}
	return packaged, nil
}

func (packaged VerifiedObservabilityCollectorRuntimePackage) PrivateBytes() ([]byte, error) {
	if err := verifyObservabilityCollectorRuntimePackage(packaged); err != nil {
		return nil, errors.New("observability collector runtime package was not produced by verification")
	}
	return append([]byte(nil), packaged.raw...), nil
}

func (packaged VerifiedObservabilityCollectorRuntimePackage) Receipt() (ObservabilityCollectorRuntimePackageReceipt, error) {
	if err := verifyObservabilityCollectorRuntimePackage(packaged); err != nil {
		return ObservabilityCollectorRuntimePackageReceipt{}, errors.New("observability collector runtime package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
	return receipt, nil
}

func verifyObservabilityCollectorRuntimePackage(packaged VerifiedObservabilityCollectorRuntimePackage) error {
	receipt := packaged.receipt
	if !packaged.verified || receipt.Format != ObservabilityCollectorRuntimePackageFormat || receipt.State != "VERIFIED" ||
		receipt.MutationAllowed || len(packaged.raw) == 0 || digest.SHA256(packaged.raw) != receipt.PackageDigest ||
		len(receipt.ObjectKinds) != 4 || receipt.ObjectKinds[0] != "Secret" || receipt.ObjectKinds[1] != "Service" ||
		receipt.ObjectKinds[2] != "NetworkPolicy" || receipt.ObjectKinds[3] != "Job" {
		return errors.New("observability collector runtime package identity is incomplete")
	}
	for _, identity := range []string{
		receipt.PackageDigest, receipt.ActivationObjectDigest, receipt.ActivationDigest, receipt.ManifestDigest,
		receipt.RuntimeBindingDigest, receipt.PublicEndpointDigest, receipt.TLSCertificateDigest,
		receipt.ReceiverIdentityDigest, receipt.ProfileDigest, receipt.ServiceObjectDigest,
		receipt.NetworkPolicyObjectDigest, receipt.JobObjectDigest, receipt.JobEnvelopeDigest, receipt.JobTemplateDigest,
	} {
		if !stageReceiptPrefixDigestPattern.MatchString(identity) {
			return errors.New("observability collector runtime package digest identity is incomplete")
		}
	}
	if !capabilityImageDigestPattern.MatchString(receipt.ImageDigest) {
		return errors.New("observability collector runtime image identity is invalid")
	}
	parts := bytes.Split(packaged.raw, []byte("\n---\n"))
	if len(parts) != 4 || digest.SHA256(parts[0]) != receipt.ActivationObjectDigest ||
		digest.SHA256(parts[1]) != receipt.ServiceObjectDigest || digest.SHA256(parts[2]) != receipt.NetworkPolicyObjectDigest ||
		digest.SHA256(parts[3]) != receipt.JobObjectDigest ||
		digest.SHA256(bytes.Join(parts[1:], []byte("\n---\n"))) != receipt.JobEnvelopeDigest {
		return errors.New("observability collector runtime package components changed")
	}
	return nil
}

func observabilityCollectorActivationFromSecret(raw []byte) (ObservabilityCollectorActivation, error) {
	var secret postRuntimeActivationSecret
	if err := jsonstrict.Decode(raw, &secret); err != nil || secret.Kind != "Secret" || !secret.Immutable {
		return ObservabilityCollectorActivation{}, errors.New("decode observability collector activation Secret")
	}
	activationRaw, err := base64.StdEncoding.Strict().DecodeString(secret.Data[observabilityCollectorActivationKey])
	if err != nil {
		return ObservabilityCollectorActivation{}, errors.New("decode observability collector activation")
	}
	var activation ObservabilityCollectorActivation
	if err := jsonstrict.Decode(activationRaw, &activation); err != nil {
		return ObservabilityCollectorActivation{}, errors.New("decode strict observability collector activation")
	}
	canonical, err := canonicalObservabilityCollectorActivation(activation)
	if err != nil || !bytes.Equal(canonical, activationRaw) {
		return ObservabilityCollectorActivation{}, errors.New("observability collector activation is not canonical")
	}
	return activation, nil
}
