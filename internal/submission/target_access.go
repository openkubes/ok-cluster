package submission

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/projection"
	"gopkg.in/yaml.v3"
)

const TargetAccessPlanFormat = "ok147-bounded-target-access-plan/v1"

const maximumTargetAccessArtifactBytes = 512 * 1024

// TargetAccessExpected is independently bound by the staged plan, verified
// runtime binding and authoritative Platform projection. It does not permit a
// caller to add an object or choose a different workload authority.
type TargetAccessExpected struct {
	ArtifactDigest       string
	ContractIdentity     contract.Identity
	IntentRevision       string
	PlatformRevision     string
	ExecutionFixture     string
	TargetIdentityDigest string
	WorkloadAuthority    string
	Objects              []projection.ResourceIdentity
}

// TargetAccessPlan contains exactly the externally rendered access objects
// that prepare one workload cluster for the later target-credential stage. It
// is verified desired state, not authorization to submit it.
type TargetAccessPlan struct {
	Format               string `json:"format"`
	IntentRevision       string `json:"intentRevision"`
	PlatformRevision     string `json:"platformRevision"`
	ExecutionFixture     string `json:"executionFixture"`
	TargetIdentityDigest string `json:"targetIdentityDigest"`
	ArtifactDigest       string `json:"artifactDigest"`
	MutationAllowed      bool   `json:"mutationAllowed"`
	Workload             Plane  `json:"workload"`
}

// LoadTargetAccess verifies the complete renderer-owned target-access set
// offline. It performs no API request and grants no mutation authority.
func LoadTargetAccess(path string, expected TargetAccessExpected) (TargetAccessPlan, error) {
	if err := validateTargetAccessExpected(expected); err != nil {
		return TargetAccessPlan{}, err
	}
	raw, err := readBoundedTargetAccessArtifact(path)
	if err != nil {
		return TargetAccessPlan{}, err
	}
	if digest.SHA256(raw) != expected.ArtifactDigest {
		return TargetAccessPlan{}, errors.New("target-access artifact digest differs from staged input")
	}
	objects, err := decodeTargetAccessObjects(raw, expected)
	if err != nil {
		return TargetAccessPlan{}, err
	}
	return TargetAccessPlan{
		Format: TargetAccessPlanFormat, IntentRevision: expected.IntentRevision,
		PlatformRevision: expected.PlatformRevision, ExecutionFixture: expected.ExecutionFixture,
		TargetIdentityDigest: expected.TargetIdentityDigest, ArtifactDigest: expected.ArtifactDigest,
		MutationAllowed: false,
		Workload:        Plane{Identity: expected.WorkloadAuthority, Role: "target-access-writer", Objects: objects},
	}, nil
}

func validateTargetAccessExpected(expected TargetAccessExpected) error {
	for _, value := range []string{expected.ArtifactDigest, expected.IntentRevision, expected.PlatformRevision, expected.ExecutionFixture, expected.TargetIdentityDigest} {
		if !immutableDigestPattern.MatchString(value) {
			return errors.New("target-access expected digest identity is invalid")
		}
	}
	if !validName(expected.ContractIdentity.Namespace, 63) || strings.Contains(expected.ContractIdentity.Namespace, ".") || !validName(expected.ContractIdentity.Name, 253) {
		return errors.New("target-access Contract identity is invalid")
	}
	if expected.WorkloadAuthority != expected.TargetIdentityDigest {
		return errors.New("target-access workload authority must equal the immutable target identity")
	}
	if len(expected.Objects) != 11 {
		return errors.New("target-access requires exactly eleven object identities")
	}
	expectedKinds := []string{"Namespace", "ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding", "Role", "RoleBinding", "ServiceAccount", "Role", "RoleBinding"}
	for index, identity := range expected.Objects {
		if identity.Kind != expectedKinds[index] || !validName(identity.Name, 253) {
			return errors.New("target-access expected object order or identity is invalid")
		}
		switch identity.Kind {
		case "Namespace", "ServiceAccount":
			if identity.APIVersion != "v1" {
				return errors.New("target-access core object API version is invalid")
			}
		case "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding":
			if identity.APIVersion != "rbac.authorization.k8s.io/v1" {
				return errors.New("target-access RBAC API version is invalid")
			}
		}
		if identity.Kind == "Namespace" || identity.Kind == "ClusterRole" || identity.Kind == "ClusterRoleBinding" {
			if identity.Namespace != "" {
				return errors.New("target-access cluster-scoped identity contains a namespace")
			}
		} else if identity.Namespace == "" || !validName(identity.Namespace, 63) || strings.Contains(identity.Namespace, ".") {
			return errors.New("target-access namespaced identity is invalid")
		}
	}
	return nil
}

func readBoundedTargetAccessArtifact(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("target-access artifact path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect target-access artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumTargetAccessArtifactBytes {
		return nil, errors.New("target-access artifact metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target-access artifact: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumTargetAccessArtifactBytes+1))
	if err != nil || len(raw) > maximumTargetAccessArtifactBytes {
		return nil, errors.New("read bounded target-access artifact")
	}
	return raw, nil
}

func decodeTargetAccessObjects(raw []byte, expected TargetAccessExpected) ([]Object, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	objects := make([]Object, 0, len(expected.Objects))
	values := make([]map[string]any, 0, len(expected.Objects))
	for {
		var document yaml.Node
		if err := decoder.Decode(&document); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode target-access YAML: %w", err)
		}
		if len(document.Content) == 0 {
			continue
		}
		if err := rejectAliases(document.Content[0]); err != nil {
			return nil, err
		}
		var decoded any
		if err := document.Content[0].Decode(&decoded); err != nil {
			return nil, fmt.Errorf("decode target-access object: %w", err)
		}
		converted, err := jsonValue(decoded)
		if err != nil {
			return nil, err
		}
		value, ok := converted.(map[string]any)
		if !ok {
			return nil, errors.New("target-access document is not a Kubernetes object")
		}
		values = append(values, value)
	}
	if len(values) != len(expected.Objects) {
		return nil, fmt.Errorf("target-access artifact contains %d objects, expected exactly %d", len(values), len(expected.Objects))
	}
	for index, value := range values {
		object, err := validateTargetAccessObject(value, expected.Objects[index])
		if err != nil {
			return nil, fmt.Errorf("target-access document %d: %w", index+1, err)
		}
		objects = append(objects, object)
	}
	if err := validateTargetAccessRelationships(values, expected.Objects); err != nil {
		return nil, err
	}
	return objects, nil
}

func validateTargetAccessObject(value map[string]any, expected projection.ResourceIdentity) (Object, error) {
	if _, exists := value["status"]; exists {
		return Object{}, errors.New("target-access object must not contain status")
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return Object{}, errors.New("target-access object metadata is missing")
	}
	identity := projection.ResourceIdentity{
		APIVersion: text(value["apiVersion"]), Kind: text(value["kind"]), Name: text(metadata["name"]), Namespace: text(metadata["namespace"]),
	}
	if identity != expected {
		return Object{}, errors.New("target-access object identity differs from the staged input")
	}
	for _, forbidden := range []string{"generateName", "uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "deletionGracePeriodSeconds", "managedFields", "ownerReferences", "finalizers"} {
		if _, exists := metadata[forbidden]; exists {
			return Object{}, fmt.Errorf("target-access metadata.%s is not accepted", forbidden)
		}
	}
	if err := rejectTargetAccessUnknownKeys(metadata, "metadata", "name", "namespace", "labels", "annotations"); err != nil {
		return Object{}, err
	}
	switch identity.Kind {
	case "Namespace":
		if err := rejectTargetAccessUnknownKeys(value, "Namespace", "apiVersion", "kind", "metadata"); err != nil {
			return Object{}, err
		}
		if err := validateTargetNamespace(value); err != nil {
			return Object{}, err
		}
	case "ServiceAccount":
		if err := rejectTargetAccessUnknownKeys(value, "ServiceAccount", "apiVersion", "kind", "metadata", "automountServiceAccountToken"); err != nil {
			return Object{}, err
		}
		if _, exists := value["secrets"]; exists {
			return Object{}, errors.New("target-access ServiceAccount must not embed Secret references")
		}
	case "Role", "ClusterRole":
		if err := rejectTargetAccessUnknownKeys(value, identity.Kind, "apiVersion", "kind", "metadata", "rules"); err != nil {
			return Object{}, err
		}
		if err := validateTargetAccessRules(value["rules"]); err != nil {
			return Object{}, err
		}
	case "RoleBinding", "ClusterRoleBinding":
		if err := rejectTargetAccessUnknownKeys(value, identity.Kind, "apiVersion", "kind", "metadata", "roleRef", "subjects"); err != nil {
			return Object{}, err
		}
		if err := validateTargetAccessBindingShape(value); err != nil {
			return Object{}, err
		}
	}
	collection, err := targetAccessCollectionPath(identity)
	if err != nil {
		return Object{}, err
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return Object{}, err
	}
	return Object{Identity: identity, Digest: digest.SHA256(canonical), CollectionPath: collection, ObjectPath: collection + "/" + identity.Name, Raw: canonical}, nil
}

func validateTargetNamespace(value map[string]any) error {
	metadata, _ := value["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	for _, key := range []string{"pod-security.kubernetes.io/enforce", "pod-security.kubernetes.io/audit", "pod-security.kubernetes.io/warn"} {
		level := text(labels[key])
		if level != "restricted" && level != "baseline" && level != "privileged" {
			return fmt.Errorf("target-access Namespace lacks an explicit %s level", key)
		}
	}
	return nil
}

func validateTargetAccessRules(raw any) error {
	rules, ok := raw.([]any)
	if !ok || len(rules) == 0 || len(rules) > 32 {
		return errors.New("target-access RBAC rules are missing or unbounded")
	}
	allowedVerbs := map[string]bool{"get": true, "list": true, "watch": true, "create": true, "patch": true, "update": true, "delete": true, "bind": true, "escalate": true}
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			return errors.New("target-access RBAC rule is invalid")
		}
		if err := rejectTargetAccessUnknownKeys(rule, "RBAC rule", "apiGroups", "resources", "verbs", "resourceNames"); err != nil {
			return err
		}
		for _, key := range []string{"apiGroups", "resources", "verbs"} {
			values, ok := rule[key].([]any)
			if !ok || len(values) == 0 || len(values) > 32 {
				return fmt.Errorf("target-access RBAC %s are missing or unbounded", key)
			}
			for _, rawValue := range values {
				value := text(rawValue)
				if value == "" && key != "apiGroups" || value == "*" || strings.ContainsAny(value, " \t\r\n") {
					return fmt.Errorf("target-access RBAC %s contain an unsafe value", key)
				}
				if key == "verbs" && !allowedVerbs[value] {
					return errors.New("target-access RBAC contains an unsupported verb")
				}
			}
		}
		if names, exists := rule["resourceNames"]; exists {
			values, ok := names.([]any)
			if !ok || len(values) == 0 || len(values) > 32 {
				return errors.New("target-access RBAC resourceNames are invalid")
			}
			for _, name := range values {
				if !validName(text(name), 253) {
					return errors.New("target-access RBAC resourceName is invalid")
				}
			}
		}
		for _, forbidden := range []string{"nonResourceURLs"} {
			if _, exists := rule[forbidden]; exists {
				return errors.New("target-access RBAC non-resource permissions are forbidden")
			}
		}
	}
	return nil
}

func validateTargetAccessBindingShape(value map[string]any) error {
	roleRef, _ := value["roleRef"].(map[string]any)
	if err := rejectTargetAccessUnknownKeys(roleRef, "binding roleRef", "apiGroup", "kind", "name"); err != nil {
		return err
	}
	if text(roleRef["apiGroup"]) != "rbac.authorization.k8s.io" || (text(roleRef["kind"]) != "Role" && text(roleRef["kind"]) != "ClusterRole") || !validName(text(roleRef["name"]), 253) {
		return errors.New("target-access binding roleRef is invalid")
	}
	subjects, ok := value["subjects"].([]any)
	if !ok || len(subjects) != 1 {
		return errors.New("target-access binding must contain exactly one subject")
	}
	subject, _ := subjects[0].(map[string]any)
	if err := rejectTargetAccessUnknownKeys(subject, "binding subject", "kind", "name", "namespace", "apiGroup"); err != nil {
		return err
	}
	if text(subject["kind"]) != "ServiceAccount" || text(subject["apiGroup"]) != "" || !validName(text(subject["name"]), 253) || !validName(text(subject["namespace"]), 63) {
		return errors.New("target-access binding subject must be one exact ServiceAccount")
	}
	return nil
}

func rejectTargetAccessUnknownKeys(value map[string]any, description string, allowed ...string) error {
	accepted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		accepted[key] = true
	}
	for key := range value {
		if !accepted[key] {
			return fmt.Errorf("target-access %s contains unsupported field %s", description, key)
		}
	}
	return nil
}

func validateTargetAccessRelationships(values []map[string]any, identities []projection.ResourceIdentity) error {
	managerServiceAccount := identities[1]
	clusterRole := identities[2]
	for _, index := range []int{3, 5, 7} {
		roleRef := values[index]["roleRef"].(map[string]any)
		subject := values[index]["subjects"].([]any)[0].(map[string]any)
		if text(subject["name"]) != managerServiceAccount.Name || text(subject["namespace"]) != managerServiceAccount.Namespace {
			return errors.New("target-access binding subject differs from the exact manager ServiceAccount")
		}
		wantKind, wantName := identities[index-1].Kind, identities[index-1].Name
		if index == 3 {
			wantKind, wantName = clusterRole.Kind, clusterRole.Name
		}
		if text(roleRef["kind"]) != wantKind || text(roleRef["name"]) != wantName {
			return errors.New("target-access binding roleRef differs from its exact role")
		}
	}
	observerServiceAccount := identities[8]
	if automount, exists := values[8]["automountServiceAccountToken"]; !exists || automount != false {
		return errors.New("target-access observer ServiceAccount must disable automatic token mounting")
	}
	if err := validateTargetAccessObserverRules(values[9]["rules"]); err != nil {
		return err
	}
	roleRef := values[10]["roleRef"].(map[string]any)
	subject := values[10]["subjects"].([]any)[0].(map[string]any)
	if text(subject["name"]) != observerServiceAccount.Name || text(subject["namespace"]) != observerServiceAccount.Namespace {
		return errors.New("target-access observer binding subject differs from the exact observer ServiceAccount")
	}
	if text(roleRef["kind"]) != identities[9].Kind || text(roleRef["name"]) != identities[9].Name {
		return errors.New("target-access observer binding roleRef differs from its exact role")
	}
	return nil
}

func validateTargetAccessObserverRules(raw any) error {
	rules, ok := raw.([]any)
	if !ok || len(rules) != 2 {
		return errors.New("target-access observer role must contain exactly two rules")
	}
	expected := []struct {
		apiGroups []string
		resources []string
		verbs     []string
	}{
		{apiGroups: []string{""}, resources: []string{"services"}, verbs: []string{"get"}},
		{apiGroups: []string{"discovery.k8s.io"}, resources: []string{"endpointslices"}, verbs: []string{"list"}},
	}
	for index, want := range expected {
		rule, ok := rules[index].(map[string]any)
		if !ok || !targetAccessStringListEquals(rule["apiGroups"], want.apiGroups) || !targetAccessStringListEquals(rule["resources"], want.resources) || !targetAccessStringListEquals(rule["verbs"], want.verbs) {
			return errors.New("target-access observer role exceeds the exact read-only permission profile")
		}
		if _, exists := rule["resourceNames"]; exists {
			return errors.New("target-access observer role must not contain resourceNames")
		}
	}
	return nil
}

func targetAccessStringListEquals(raw any, expected []string) bool {
	values, ok := raw.([]any)
	if !ok || len(values) != len(expected) {
		return false
	}
	for index := range expected {
		if text(values[index]) != expected[index] {
			return false
		}
	}
	return true
}

func targetAccessCollectionPath(identity projection.ResourceIdentity) (string, error) {
	switch identity.Kind {
	case "Namespace":
		return "/api/v1/namespaces", nil
	case "ServiceAccount":
		return "/api/v1/namespaces/" + identity.Namespace + "/serviceaccounts", nil
	case "ClusterRole":
		return "/apis/rbac.authorization.k8s.io/v1/clusterroles", nil
	case "ClusterRoleBinding":
		return "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", nil
	case "Role":
		return "/apis/rbac.authorization.k8s.io/v1/namespaces/" + identity.Namespace + "/roles", nil
	case "RoleBinding":
		return "/apis/rbac.authorization.k8s.io/v1/namespaces/" + identity.Namespace + "/rolebindings", nil
	default:
		return "", errors.New("target-access object kind is outside the fixed allowlist")
	}
}
