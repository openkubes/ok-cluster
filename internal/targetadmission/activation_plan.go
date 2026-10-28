package targetadmission

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const ActivationPlanFormat = "ok147-target-admission-activation-plan/v1"
const MaxActivationPlanBytes = 4 * 1024 * 1024

// PlannedObject is an exact, digest-addressed YAML object kept in its
// execution phase. Scaffold objects must be reviewed/applied before the
// webhook activation object; this data structure itself applies nothing.
type PlannedObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Digest     string `json:"digest"`
	Manifest   string `json:"manifest"`
}

type ActivationPlan struct {
	Format                      string          `json:"format"`
	State                       string          `json:"state"`
	PlanDigest                  string          `json:"planDigest"`
	PolicyDigest                string          `json:"policyDigest"`
	TargetBindingDigest         string          `json:"targetBindingDigest"`
	WebhookConfigurationDigest  string          `json:"webhookConfigurationDigest"`
	Image                       string          `json:"image"`
	MinimumKubernetesVersion    string          `json:"minimumKubernetesVersion"`
	KubernetesVersionVerified   bool            `json:"kubernetesVersionVerified"`
	TargetIdentityRecheckNeeded bool            `json:"targetIdentityRecheckNeeded"`
	APIAccessed                 bool            `json:"apiAccessed"`
	MutationAllowed             bool            `json:"mutationAllowed"`
	WebhookActive               bool            `json:"webhookActive"`
	Scaffold                    []PlannedObject `json:"scaffold"`
	Activation                  PlannedObject   `json:"activation"`
}

type activationPlanDigestDocument struct {
	Format                      string          `json:"format"`
	State                       string          `json:"state"`
	PolicyDigest                string          `json:"policyDigest"`
	TargetBindingDigest         string          `json:"targetBindingDigest"`
	WebhookConfigurationDigest  string          `json:"webhookConfigurationDigest"`
	Image                       string          `json:"image"`
	MinimumKubernetesVersion    string          `json:"minimumKubernetesVersion"`
	KubernetesVersionVerified   bool            `json:"kubernetesVersionVerified"`
	TargetIdentityRecheckNeeded bool            `json:"targetIdentityRecheckNeeded"`
	APIAccessed                 bool            `json:"apiAccessed"`
	MutationAllowed             bool            `json:"mutationAllowed"`
	WebhookActive               bool            `json:"webhookActive"`
	Scaffold                    []PlannedObject `json:"scaffold"`
	Activation                  PlannedObject   `json:"activation"`
}

// BuildOfflineActivationPlan verifies the independently signed policy and
// prepares a digest-addressed deployment sequence. It does not claim that the
// signed target is live, verify the target Kubernetes version, access an API,
// authorize writes, or activate the webhook.
func BuildOfflineActivationPlan(bundle []byte, trustedKey ed25519.PublicKey, webhookCA []byte, image string) (ActivationPlan, error) {
	policy, target, err := VerifyBundle(bundle, trustedKey)
	if err != nil {
		return ActivationPlan{}, fmt.Errorf("verify signed target policy: %w", err)
	}
	if !validCABundle(webhookCA) {
		return ActivationPlan{}, errors.New("webhook CA bundle is invalid")
	}
	install, err := RenderInstallSet(image)
	if err != nil {
		return ActivationPlan{}, err
	}
	webhook, err := RenderWebhookConfiguration(policy, InstallNamespace, InstallService, webhookCA)
	if err != nil {
		return ActivationPlan{}, fmt.Errorf("render target webhook activation: %w", err)
	}
	targetBindingBytes, err := json.Marshal(target)
	if err != nil {
		return ActivationPlan{}, errors.New("encode target binding digest input")
	}
	planned := ActivationPlan{
		Format: ActivationPlanFormat, State: "PLAN_ONLY_AWAITING_TARGET_CHECKS",
		PolicyDigest: policy.Digest(), TargetBindingDigest: digest.SHA256(targetBindingBytes),
		WebhookConfigurationDigest: digest.SHA256(webhook), Image: image,
		MinimumKubernetesVersion: "v1.30.0", KubernetesVersionVerified: false,
		TargetIdentityRecheckNeeded: true, APIAccessed: false, MutationAllowed: false, WebhookActive: false,
		Scaffold: make([]PlannedObject, 0, len(install.Objects)),
	}
	for _, object := range install.Objects {
		planned.Scaffold = append(planned.Scaffold, PlannedObject{
			APIVersion: object.APIVersion, Kind: object.Kind, Namespace: object.Namespace,
			Name: object.Name, Digest: object.Digest, Manifest: string(object.Raw),
		})
	}
	planned.Activation = PlannedObject{
		APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingWebhookConfiguration",
		Name: "ok147-target-access.openkubes.io", Digest: digest.SHA256(webhook), Manifest: string(webhook),
	}
	document := activationPlanDigestDocument{
		Format: planned.Format, State: planned.State, PolicyDigest: planned.PolicyDigest,
		TargetBindingDigest: planned.TargetBindingDigest, WebhookConfigurationDigest: planned.WebhookConfigurationDigest,
		Image: planned.Image, MinimumKubernetesVersion: planned.MinimumKubernetesVersion,
		KubernetesVersionVerified: planned.KubernetesVersionVerified, TargetIdentityRecheckNeeded: planned.TargetIdentityRecheckNeeded,
		APIAccessed: planned.APIAccessed, MutationAllowed: planned.MutationAllowed, WebhookActive: planned.WebhookActive,
		Scaffold: planned.Scaffold, Activation: planned.Activation,
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return ActivationPlan{}, errors.New("encode target admission activation plan")
	}
	planned.PlanDigest = digest.SHA256(canonical)
	return planned, nil
}

// VerifyOfflineActivationPlan independently regenerates the exact plan from
// its signed source inputs and compares every field and manifest byte. This
// detects drift or tampering but still does not verify a live target or
// authorize applying any resource.
func VerifyOfflineActivationPlan(plan ActivationPlan, bundle []byte, trustedKey ed25519.PublicKey, webhookCA []byte) error {
	expected, err := BuildOfflineActivationPlan(bundle, trustedKey, webhookCA, plan.Image)
	if err != nil {
		return fmt.Errorf("regenerate target admission plan: %w", err)
	}
	if !reflect.DeepEqual(plan, expected) {
		return errors.New("target admission plan differs from independently regenerated signed-source plan")
	}
	return nil
}

// VerifyOfflineActivationPlanDocument parses a bounded strict JSON plan and
// verifies it by regeneration from the supplied signed sources.
func VerifyOfflineActivationPlanDocument(raw, bundle []byte, trustedKey ed25519.PublicKey, webhookCA []byte) (ActivationPlan, error) {
	if len(raw) == 0 || len(raw) > MaxActivationPlanBytes {
		return ActivationPlan{}, errors.New("target admission activation plan is empty or oversized")
	}
	var plan ActivationPlan
	if err := jsonstrict.Decode(raw, &plan); err != nil {
		return ActivationPlan{}, errors.New("target admission activation plan JSON is invalid")
	}
	if err := VerifyOfflineActivationPlan(plan, bundle, trustedKey, webhookCA); err != nil {
		return ActivationPlan{}, err
	}
	return plan, nil
}
