package submission

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/observation"
	"github.com/openkubes/ok-cluster/internal/projection"
	"gopkg.in/yaml.v3"
)

const (
	PlatformApplicationsPlanFormat   = "ok147-bounded-platform-applications-plan/v1"
	maximumPlatformApplicationsBytes = 2 * 1024 * 1024
)

type PlatformApplicationsExpected struct {
	ArtifactDigest       string
	ContractIdentity     contract.Identity
	IntentRevision       string
	PlatformRevision     string
	ExecutionFixture     string
	TargetIdentityDigest string
	ArgoAuthority        string
	ArgoNamespace        string
	ProjectName          string
	RegistrationName     string
	SourceRepository     string
	Profile              observation.PlatformProfile
}

type PlatformApplicationsPlan struct {
	Format               string   `json:"format"`
	IntentRevision       string   `json:"intentRevision"`
	PlatformRevision     string   `json:"platformRevision"`
	ExecutionFixture     string   `json:"executionFixture"`
	TargetIdentityDigest string   `json:"targetIdentityDigest"`
	ArtifactDigest       string   `json:"artifactDigest"`
	Authority            string   `json:"authority"`
	Applications         []Object `json:"applications"`
	MutationAllowed      bool     `json:"mutationAllowed"`
}

// LoadPlatformApplications verifies the complete exact Application set for P.
// It performs no API request and grants no mutation authority.
func LoadPlatformApplications(path string, expected PlatformApplicationsExpected) (PlatformApplicationsPlan, error) {
	if err := validatePlatformApplicationsExpected(expected); err != nil {
		return PlatformApplicationsPlan{}, err
	}
	raw, err := readPlatformApplicationsArtifact(path)
	if err != nil {
		return PlatformApplicationsPlan{}, err
	}
	if digest.SHA256(raw) != expected.ArtifactDigest {
		return PlatformApplicationsPlan{}, errors.New("platform Applications artifact digest differs from staged input")
	}
	documents, err := decodePlatformApplicationDocuments(raw)
	if err != nil {
		return PlatformApplicationsPlan{}, err
	}
	if len(documents) != len(expected.Profile.RequiredApplications) {
		return PlatformApplicationsPlan{}, errors.New("platform Applications artifact membership differs from profile")
	}
	wanted := make(map[string]string, len(expected.Profile.RequiredApplications))
	for _, application := range expected.Profile.RequiredApplications {
		wanted[application.Name] = application.SpecDigest
	}
	objects := make([]Object, 0, len(documents))
	seen := map[string]struct{}{}
	for _, document := range documents {
		object, specDigest, err := validatePlatformApplication(document, expected)
		if err != nil {
			return PlatformApplicationsPlan{}, err
		}
		wantDigest, exists := wanted[object.Identity.Name]
		if !exists || wantDigest != specDigest {
			return PlatformApplicationsPlan{}, errors.New("platform Application spec differs from immutable profile")
		}
		if _, duplicate := seen[object.Identity.Name]; duplicate {
			return PlatformApplicationsPlan{}, errors.New("platform Applications artifact contains duplicate identity")
		}
		seen[object.Identity.Name] = struct{}{}
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Identity.Name < objects[j].Identity.Name })
	return PlatformApplicationsPlan{
		Format: PlatformApplicationsPlanFormat, IntentRevision: expected.IntentRevision,
		PlatformRevision: expected.PlatformRevision, ExecutionFixture: expected.ExecutionFixture,
		TargetIdentityDigest: expected.TargetIdentityDigest, ArtifactDigest: expected.ArtifactDigest,
		Authority: expected.ArgoAuthority, Applications: objects, MutationAllowed: false,
	}, nil
}

func validatePlatformApplicationsExpected(expected PlatformApplicationsExpected) error {
	for _, value := range []string{expected.ArtifactDigest, expected.IntentRevision, expected.PlatformRevision, expected.ExecutionFixture, expected.TargetIdentityDigest} {
		if !immutableDigestPattern.MatchString(value) {
			return errors.New("platform Applications expected digest identity is invalid")
		}
	}
	if !validName(expected.ContractIdentity.Namespace, 63) || !validName(expected.ContractIdentity.Name, 253) ||
		!validName(expected.ArgoAuthority, 63) || !validName(expected.ArgoNamespace, 63) ||
		!validName(expected.ProjectName, 253) || !validName(expected.RegistrationName, 253) {
		return errors.New("platform Applications expected object identity is invalid")
	}
	if err := observation.ValidatePlatformProfile(expected.Profile); err != nil ||
		expected.Profile.IntentRevision != expected.IntentRevision || expected.Profile.PlatformRevision != expected.PlatformRevision ||
		expected.Profile.ExecutionFixture != expected.ExecutionFixture || expected.Profile.ArgoNamespace != expected.ArgoNamespace ||
		expected.Profile.RegistrationName != expected.RegistrationName || len(expected.Profile.RequiredApplications) != 3 {
		return errors.New("platform Applications profile differs from expected P")
	}
	repository, err := url.Parse(expected.SourceRepository)
	if err != nil || repository.Scheme != "https" || repository.Host == "" || repository.User != nil || repository.RawQuery != "" || repository.Fragment != "" {
		return errors.New("platform Applications source repository is invalid")
	}
	return nil
}

func readPlatformApplicationsArtifact(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("platform Applications artifact path is required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumPlatformApplicationsBytes {
		return nil, errors.New("platform Applications artifact metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open platform Applications artifact")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumPlatformApplicationsBytes+1))
	if err != nil || len(raw) > maximumPlatformApplicationsBytes {
		return nil, errors.New("read bounded platform Applications artifact")
	}
	return raw, nil
}

func decodePlatformApplicationDocuments(raw []byte) ([]map[string]any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	values := []map[string]any{}
	for {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errors.New("decode platform Applications YAML")
		}
		if len(document.Content) == 0 {
			continue
		}
		if err := rejectAliases(document.Content[0]); err != nil {
			return nil, err
		}
		var decoded any
		if err := document.Content[0].Decode(&decoded); err != nil {
			return nil, errors.New("decode platform Application object")
		}
		converted, err := jsonValue(decoded)
		if err != nil {
			return nil, err
		}
		value, ok := converted.(map[string]any)
		if !ok {
			return nil, errors.New("platform Application document is not an object")
		}
		values = append(values, value)
	}
	return values, nil
}

func validatePlatformApplication(value map[string]any, expected PlatformApplicationsExpected) (Object, string, error) {
	if err := rejectTargetAccessUnknownKeys(value, "Application", "apiVersion", "kind", "metadata", "spec"); err != nil {
		return Object{}, "", err
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return Object{}, "", errors.New("platform Application metadata is missing")
	}
	if err := rejectTargetAccessUnknownKeys(metadata, "Application metadata", "name", "namespace", "annotations"); err != nil {
		return Object{}, "", err
	}
	name, namespace := text(metadata["name"]), text(metadata["namespace"])
	if text(value["apiVersion"]) != "argoproj.io/v1alpha1" || text(value["kind"]) != "Application" || namespace != expected.ArgoNamespace || !validName(name, 253) {
		return Object{}, "", errors.New("platform Application identity is invalid")
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	wantAnnotations := map[string]string{
		"openkubes.io/intent-revision": expected.IntentRevision, "openkubes.io/platform-revision": expected.PlatformRevision,
		"openkubes.io/execution-fixture": expected.ExecutionFixture, "openkubes.io/target-identity-digest": expected.TargetIdentityDigest,
	}
	if !ok || len(annotations) != len(wantAnnotations) {
		return Object{}, "", errors.New("platform Application annotations differ from exact revision carriers")
	}
	for key, want := range wantAnnotations {
		if text(annotations[key]) != want {
			return Object{}, "", errors.New("platform Application revision carrier differs")
		}
	}
	spec, ok := value["spec"].(map[string]any)
	if !ok || text(spec["project"]) != expected.ProjectName {
		return Object{}, "", errors.New("platform Application project differs")
	}
	source, _ := spec["source"].(map[string]any)
	destination, _ := spec["destination"].(map[string]any)
	if text(source["repoURL"]) != expected.SourceRepository || text(destination["name"]) != expected.RegistrationName || text(destination["namespace"]) != "ok-observability" {
		return Object{}, "", errors.New("platform Application source or destination differs")
	}
	specDigest, _, err := observation.PlatformApplicationSpecIdentity(spec)
	if err != nil {
		return Object{}, "", fmt.Errorf("platform Application semantic identity: %w", err)
	}
	identity := projection.ResourceIdentity{APIVersion: "argoproj.io/v1alpha1", Kind: "Application", Namespace: namespace, Name: name}
	raw, err := canonicalJSON(value)
	if err != nil {
		return Object{}, "", errors.New("canonicalize platform Application")
	}
	collection := "/apis/argoproj.io/v1alpha1/namespaces/" + namespace + "/applications"
	return Object{Identity: identity, Digest: digest.SHA256(raw), CollectionPath: collection, ObjectPath: collection + "/" + name, Raw: raw}, specDigest, nil
}
