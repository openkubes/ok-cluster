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

// Plane is a verified authority domain, not a credential or Kubernetes context.
type Plane struct {
	Identity      string `json:"identity"`
	Role          string `json:"role"`
	ResourceCount int    `json:"resourceCount"`
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
		InfrastructurePlane: Plane{Identity: authority.InfrastructurePlane.Identity, Role: authority.InfrastructurePlane.Role, ResourceCount: len(authority.InfrastructurePlane.Resources)},
		ManagementPlane:     Plane{Identity: authority.ManagementPlane.Identity, Role: authority.ManagementPlane.Role, ResourceCount: len(authority.ManagementPlane.Resources)},
		Artifacts:           artifacts,
	}, nil
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
