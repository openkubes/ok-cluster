// Package projection verifies immutable output produced by an authoritative
// Contract-to-CAPI renderer. It does not render or mutate Kubernetes objects.
package projection

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const BindingFormat = "ok147-verified-projection/v1"

type objectSet struct {
	Count  int    `json:"count"`
	Digest string `json:"digest"`
}

type manifest struct {
	Format             string               `json:"format"`
	R                  string               `json:"R"`
	AuthorizationState string               `json:"authorizationState"`
	Artifacts          map[string]string    `json:"artifacts"`
	ObjectSets         map[string]objectSet `json:"objectSets"`
	ProviderAccess     json.RawMessage      `json:"providerAccess"`
	Source             json.RawMessage      `json:"source"`
}

type resource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

type plane struct {
	Identity  string     `json:"identity"`
	Role      string     `json:"role"`
	Resources []resource `json:"resources"`
}

type authorityMap struct {
	Format                    string            `json:"format"`
	ContractIdentity          contract.Identity `json:"contractIdentity"`
	IntentRevision            string            `json:"intentRevision"`
	InfrastructurePlane       plane             `json:"infrastructurePlane"`
	ManagementPlane           plane             `json:"managementPlane"`
	ProviderAccess            json.RawMessage   `json:"providerAccess"`
	ExcludedRendererArtifacts json.RawMessage   `json:"excludedRendererArtifacts"`
}

// Artifact records the verified raw identity of one renderer artifact.
type Artifact struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// ResourceIdentity is the exact Kubernetes identity authorized by the
// renderer's authority map. It is deliberately excluded from CreateRequest
// JSON because AuthorityMapDigest already binds the complete resource set.
// Keeping it in memory lets bounded submitters validate projection documents
// without creating a second renderer or trusting file names alone.
type ResourceIdentity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

// Plane is a verified authority domain, not a credential or Kubernetes context.
type Plane struct {
	Identity      string             `json:"identity"`
	Role          string             `json:"role"`
	ResourceCount int                `json:"resourceCount"`
	Resources     []ResourceIdentity `json:"-"`
}

// Binding is the bounded proof returned after all referenced files and
// authority metadata have been checked.
type Binding struct {
	Format              string            `json:"format"`
	SourceFormat        string            `json:"sourceFormat"`
	ManifestDigest      string            `json:"manifestDigest"`
	AuthorityMapDigest  string            `json:"authorityMapDigest"`
	IntentRevision      string            `json:"intentRevision"`
	ContractIdentity    contract.Identity `json:"contractIdentity"`
	InfrastructurePlane Plane             `json:"infrastructurePlane"`
	ManagementPlane     Plane             `json:"managementPlane"`
	Artifacts           []Artifact        `json:"artifacts"`
}

// Verify validates an existing projection manifest and every artifact it
// references. Artifact paths must be plain file names below root.
func Verify(manifestPath, root, expectedRevision string, expectedIdentity contract.Identity) (Binding, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return Binding{}, fmt.Errorf("read projection manifest: %w", err)
	}
	var source manifest
	if err := jsonstrict.Decode(raw, &source); err != nil {
		return Binding{}, fmt.Errorf("decode projection manifest: %w", err)
	}
	if source.Format == "" || source.Format != "ok141-contract-to-capi-projection/v2" {
		return Binding{}, fmt.Errorf("projection format %q is not supported", source.Format)
	}
	if source.R != expectedRevision {
		return Binding{}, fmt.Errorf("projection revision %s does not match contract revision %s", source.R, expectedRevision)
	}
	if source.AuthorizationState != "NO-GO" {
		return Binding{}, errors.New("projection artifact must remain non-authorizing (authorizationState NO-GO)")
	}
	if len(source.Artifacts) == 0 {
		return Binding{}, errors.New("projection manifest has no artifacts")
	}
	if root == "" {
		root = filepath.Dir(manifestPath)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return Binding{}, fmt.Errorf("resolve projection root: %w", err)
	}

	artifacts := make([]Artifact, 0, len(source.Artifacts))
	var authorityRaw []byte
	for name, expected := range source.Artifacts {
		if err := validateArtifactName(name); err != nil {
			return Binding{}, err
		}
		artifactRaw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return Binding{}, fmt.Errorf("read projection artifact %s: %w", name, err)
		}
		actual := digest.SHA256(artifactRaw)
		if actual != expected {
			return Binding{}, fmt.Errorf("projection artifact %s digest %s does not match %s", name, actual, expected)
		}
		artifacts = append(artifacts, Artifact{Name: name, Digest: actual})
		if name == "authority-map.json" {
			authorityRaw = artifactRaw
		}
	}
	for _, required := range []string{"authority-map.json", "ok-infra-prerequisites.yaml", "ok-mgmt-lifecycle.yaml"} {
		if _, ok := source.Artifacts[required]; !ok {
			return Binding{}, fmt.Errorf("projection manifest does not bind %s", required)
		}
	}
	if authorityRaw == nil {
		return Binding{}, errors.New("projection manifest does not bind authority-map.json")
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })

	var authority authorityMap
	if err := jsonstrict.Decode(authorityRaw, &authority); err != nil {
		return Binding{}, fmt.Errorf("decode authority map: %w", err)
	}
	if authority.Format != source.Format {
		return Binding{}, errors.New("authority map format differs from projection format")
	}
	if authority.IntentRevision != expectedRevision {
		return Binding{}, errors.New("authority map intent revision differs from contract revision")
	}
	if authority.ContractIdentity != expectedIdentity {
		return Binding{}, fmt.Errorf("authority map identity %#v differs from contract identity %#v", authority.ContractIdentity, expectedIdentity)
	}
	if err := validatePlane(authority.InfrastructurePlane, "provider-runtime-and-golden-image-prerequisites"); err != nil {
		return Binding{}, fmt.Errorf("infrastructure plane: %w", err)
	}
	if err := validatePlane(authority.ManagementPlane, "single-lifecycle-writer"); err != nil {
		return Binding{}, fmt.Errorf("management plane: %w", err)
	}
	if authority.InfrastructurePlane.Identity == authority.ManagementPlane.Identity {
		return Binding{}, errors.New("infrastructure and management authority identities must differ")
	}
	if err := matchCount(source.ObjectSets, "okInfraPrerequisites", len(authority.InfrastructurePlane.Resources)); err != nil {
		return Binding{}, err
	}
	if err := matchCount(source.ObjectSets, "okMgmtLifecycle", len(authority.ManagementPlane.Resources)); err != nil {
		return Binding{}, err
	}

	return Binding{
		Format:              BindingFormat,
		SourceFormat:        source.Format,
		ManifestDigest:      digest.SHA256(raw),
		AuthorityMapDigest:  digest.SHA256(authorityRaw),
		IntentRevision:      expectedRevision,
		ContractIdentity:    expectedIdentity,
		InfrastructurePlane: Plane{Identity: authority.InfrastructurePlane.Identity, Role: authority.InfrastructurePlane.Role, ResourceCount: len(authority.InfrastructurePlane.Resources), Resources: exportResources(authority.InfrastructurePlane.Resources)},
		ManagementPlane:     Plane{Identity: authority.ManagementPlane.Identity, Role: authority.ManagementPlane.Role, ResourceCount: len(authority.ManagementPlane.Resources), Resources: exportResources(authority.ManagementPlane.Resources)},
		Artifacts:           artifacts,
	}, nil
}

// ReverifyAtUse reconstructs the non-serialized resource inventories from the
// digest-bound authority map immediately before submission. This prevents an
// in-memory Resource list change from becoming a second, unsigned authority.
func ReverifyAtUse(root string, binding Binding) (Binding, error) {
	if binding.Format != BindingFormat || root == "" {
		return Binding{}, errors.New("verified projection binding and root are required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return Binding{}, fmt.Errorf("resolve projection root: %w", err)
	}
	artifactDigests := make(map[string]string, len(binding.Artifacts))
	for _, artifact := range binding.Artifacts {
		if err := validateArtifactName(artifact.Name); err != nil {
			return Binding{}, err
		}
		if _, duplicate := artifactDigests[artifact.Name]; duplicate {
			return Binding{}, fmt.Errorf("verified projection repeats artifact %s", artifact.Name)
		}
		artifactDigests[artifact.Name] = artifact.Digest
	}
	for _, required := range []string{"authority-map.json", "ok-infra-prerequisites.yaml", "ok-mgmt-lifecycle.yaml"} {
		if _, ok := artifactDigests[required]; !ok {
			return Binding{}, fmt.Errorf("verified projection does not bind %s", required)
		}
	}
	var authorityRaw []byte
	for name, expected := range artifactDigests {
		raw, err := os.ReadFile(filepath.Join(abs, name))
		if err != nil {
			return Binding{}, fmt.Errorf("read projection artifact %s: %w", name, err)
		}
		if actual := digest.SHA256(raw); actual != expected {
			return Binding{}, fmt.Errorf("projection artifact %s changed after verification", name)
		}
		if name == "authority-map.json" {
			authorityRaw = raw
		}
	}
	if digest.SHA256(authorityRaw) != binding.AuthorityMapDigest {
		return Binding{}, errors.New("authority map digest differs from verified binding")
	}
	var authority authorityMap
	if err := jsonstrict.Decode(authorityRaw, &authority); err != nil {
		return Binding{}, fmt.Errorf("decode authority map: %w", err)
	}
	if authority.IntentRevision != binding.IntentRevision || authority.ContractIdentity != binding.ContractIdentity {
		return Binding{}, errors.New("authority map intent or Contract identity differs from verified binding")
	}
	if authority.Format != binding.SourceFormat {
		return Binding{}, errors.New("authority map format differs from verified binding")
	}
	if err := validatePlane(authority.InfrastructurePlane, "provider-runtime-and-golden-image-prerequisites"); err != nil {
		return Binding{}, fmt.Errorf("infrastructure plane: %w", err)
	}
	if err := validatePlane(authority.ManagementPlane, "single-lifecycle-writer"); err != nil {
		return Binding{}, fmt.Errorf("management plane: %w", err)
	}
	if authority.InfrastructurePlane.Identity != binding.InfrastructurePlane.Identity || authority.InfrastructurePlane.Role != binding.InfrastructurePlane.Role || len(authority.InfrastructurePlane.Resources) != binding.InfrastructurePlane.ResourceCount {
		return Binding{}, errors.New("infrastructure authority differs from verified binding")
	}
	if authority.ManagementPlane.Identity != binding.ManagementPlane.Identity || authority.ManagementPlane.Role != binding.ManagementPlane.Role || len(authority.ManagementPlane.Resources) != binding.ManagementPlane.ResourceCount {
		return Binding{}, errors.New("management authority differs from verified binding")
	}
	binding.InfrastructurePlane.Resources = exportResources(authority.InfrastructurePlane.Resources)
	binding.ManagementPlane.Resources = exportResources(authority.ManagementPlane.Resources)
	return binding, nil
}

func exportResources(resources []resource) []ResourceIdentity {
	result := make([]ResourceIdentity, 0, len(resources))
	for _, object := range resources {
		result = append(result, ResourceIdentity{
			APIVersion: object.APIVersion,
			Kind:       object.Kind,
			Name:       object.Name,
			Namespace:  object.Namespace,
		})
	}
	return result
}

func validateArtifactName(name string) error {
	if name == "" || filepath.Base(name) != name || name == "." || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("projection artifact path %q is not a plain file name", name)
	}
	return nil
}

func validatePlane(value plane, role string) error {
	if value.Identity == "" {
		return errors.New("identity is empty")
	}
	if value.Role != role {
		return fmt.Errorf("role %q does not match required %q", value.Role, role)
	}
	if len(value.Resources) == 0 {
		return errors.New("resource set is empty")
	}
	seen := map[string]struct{}{}
	for _, object := range value.Resources {
		if object.APIVersion == "" || object.Kind == "" || object.Name == "" {
			return errors.New("resource identity is incomplete")
		}
		key := strings.Join([]string{object.APIVersion, object.Kind, object.Namespace, object.Name}, "|")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate resource identity %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func matchCount(sets map[string]objectSet, name string, resources int) error {
	set, ok := sets[name]
	if !ok {
		return fmt.Errorf("projection object set %s is missing", name)
	}
	if set.Count != resources {
		return fmt.Errorf("projection object set %s count %d differs from authority resource count %d", name, set.Count, resources)
	}
	if !strings.HasPrefix(set.Digest, "sha256:") || len(set.Digest) != 71 {
		return fmt.Errorf("projection object set %s has invalid digest", name)
	}
	return nil
}
