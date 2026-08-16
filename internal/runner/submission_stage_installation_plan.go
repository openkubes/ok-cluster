package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const SubmissionStageInstallationPlanFormat = "ok147-submission-stage-installation-plan/v1"

type SubmissionStageCreatePlan struct {
	Order           int    `json:"order"`
	APIVersion      string `json:"apiVersion"`
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	PreflightMethod string `json:"preflightMethod"`
	ObjectPath      string `json:"objectPath"`
	CreateMethod    string `json:"createMethod"`
	CollectionPath  string `json:"collectionPath"`
	ObjectDigest    string `json:"objectDigest"`
}

// SubmissionStageInstallationPlan is an offline exact-create description. It
// is not authorization to invoke any of the recorded paths.
type SubmissionStageInstallationPlan struct {
	Format          string                      `json:"format"`
	State           string                      `json:"state"`
	StageID         string                      `json:"stageId"`
	PackageDigest   string                      `json:"packageDigest"`
	Creates         []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed bool                        `json:"mutationAllowed"`
}

// PlanSubmissionStageInstallation derives the exact absence/create sequence
// from a package that can only have been produced by BuildSubmissionStagePackage.
// It performs no API request and opens no credential.
func PlanSubmissionStageInstallation(packaged VerifiedSubmissionStagePackage) (SubmissionStageInstallationPlan, error) {
	if !packaged.verified || len(packaged.raw) == 0 || packaged.receipt.State != "VERIFIED" {
		return SubmissionStageInstallationPlan{}, errors.New("submission stage package was not produced by verification")
	}
	if packaged.installationAuthority == "" {
		return SubmissionStageInstallationPlan{}, errors.New("submission stage package installation authority is missing")
	}
	if packaged.ledgerAuthority != packaged.installationAuthority || packaged.selectedAuthority == "" || packaged.ledgerCredential == "" || packaged.selectedCredential == "" || packaged.ledgerCredential == packaged.selectedCredential {
		return SubmissionStageInstallationPlan{}, errors.New("submission stage package credential binding is invalid")
	}
	if digest.SHA256(packaged.raw) != packaged.receipt.PackageDigest {
		return SubmissionStageInstallationPlan{}, errors.New("submission stage package changed after verification")
	}
	expectedKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	if !equalStringList(packaged.receipt.ObjectKinds, expectedKinds) {
		return SubmissionStageInstallationPlan{}, errors.New("submission stage package object inventory is invalid")
	}
	documents := bytes.Split(packaged.raw, []byte("\n---\n"))
	if len(documents) != len(expectedKinds) || digest.SHA256(documents[0]) != packaged.receipt.InputConfigMapDigest || digest.SHA256(bytes.Join(documents[1:], []byte("\n---\n"))) != packaged.receipt.JobEnvelopeDigest {
		return SubmissionStageInstallationPlan{}, errors.New("submission stage package component identity differs")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]map[string]any, 0, len(expectedKinds))
	for {
		var object map[string]any
		err := decoder.Decode(&object)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(object) == 0 {
			return SubmissionStageInstallationPlan{}, errors.New("decode submission stage package")
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expectedKinds) {
		return SubmissionStageInstallationPlan{}, errors.New("submission stage package object count is invalid")
	}

	configMapName, runID := "", ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return SubmissionStageInstallationPlan{}, errors.New("submission stage package create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return SubmissionStageInstallationPlan{}, errors.New("submission stage package object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return SubmissionStageInstallationPlan{}, errors.New("submission stage package object identity is invalid")
		}
		collectionPath, objectPath, err := submissionStageCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return SubmissionStageInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return SubmissionStageInstallationPlan{}, errors.New("encode submission stage package object")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: "GET", ObjectPath: objectPath, CreateMethod: "POST", CollectionPath: collectionPath,
			ObjectDigest: digest.SHA256(canonical),
		})
		switch kind {
		case "ConfigMap":
			if object["immutable"] != true {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage input ConfigMap is not immutable")
			}
			labels, _ := metadata["labels"].(map[string]any)
			if labels["openkubes.io/stage-id"] != packaged.receipt.StageID {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage input label differs from package stage")
			}
			configMapName = name
		case "NetworkPolicy":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage NetworkPolicy selector differs from run identity")
			}
		case "Job":
			if name != runID {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage Job and NetworkPolicy identities differ")
			}
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage Job runtime identity is invalid")
			}
			if !jobMountsInputConfigMap(podSpec, configMapName) {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage Job input ConfigMap differs")
			}
			if !jobUsesManagementAuthority(podSpec, packaged.installationAuthority) {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage Job management authority differs from installation authority")
			}
			if !jobUsesCredentialSecrets(podSpec, packaged.ledgerCredential, packaged.selectedCredential) {
				return SubmissionStageInstallationPlan{}, errors.New("submission stage Job credential Secrets differ from package binding")
			}
		}
	}
	return SubmissionStageInstallationPlan{
		Format: SubmissionStageInstallationPlanFormat, State: "VERIFIED", StageID: packaged.receipt.StageID,
		PackageDigest: packaged.receipt.PackageDigest, Creates: creates, MutationAllowed: false,
	}, nil
}

func jobUsesCredentialSecrets(podSpec map[string]any, ledger, selected string) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	found := map[string]string{}
	for _, item := range volumes {
		volume, _ := item.(map[string]any)
		name, _ := volume["name"].(string)
		if name != "ledger-credential" && name != "authority-credential" {
			continue
		}
		secret, _ := volume["secret"].(map[string]any)
		secretName, _ := secret["secretName"].(string)
		items, _ := secret["items"].([]any)
		if len(items) != 2 || !credentialSecretItems(items) {
			return false
		}
		found[name] = secretName
	}
	return len(found) == 2 && found["ledger-credential"] == ledger && found["authority-credential"] == selected
}

func credentialSecretItems(items []any) bool {
	expected := map[string]string{"token": "token", "ca.crt": "ca.crt"}
	for _, item := range items {
		entry, _ := item.(map[string]any)
		key, _ := entry["key"].(string)
		path, _ := entry["path"].(string)
		if expected[key] != path {
			return false
		}
		delete(expected, key)
	}
	return len(expected) == 0
}

func jobUsesManagementAuthority(podSpec map[string]any, authority string) bool {
	containers, ok := podSpec["containers"].([]any)
	if !ok || len(containers) != 1 {
		return false
	}
	container, _ := containers[0].(map[string]any)
	if container["name"] != "executor" {
		return false
	}
	arguments, ok := container["args"].([]any)
	if !ok {
		return false
	}
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == "--management-authority" && arguments[index+1] == authority {
			return true
		}
	}
	return false
}

func submissionStageCreatePaths(apiVersion, kind, namespace, name string) (string, string, error) {
	var collection string
	switch {
	case apiVersion == "v1" && kind == "ConfigMap":
		collection = "/api/v1/namespaces/" + namespace + "/configmaps"
	case apiVersion == "networking.k8s.io/v1" && kind == "NetworkPolicy":
		collection = "/apis/networking.k8s.io/v1/namespaces/" + namespace + "/networkpolicies"
	case apiVersion == "batch/v1" && kind == "Job":
		collection = "/apis/batch/v1/namespaces/" + namespace + "/jobs"
	default:
		return "", "", fmt.Errorf("submission stage package contains unsupported %s %s", apiVersion, kind)
	}
	return collection, collection + "/" + name, nil
}

func jobMountsInputConfigMap(podSpec map[string]any, name string) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	for _, item := range volumes {
		volume, _ := item.(map[string]any)
		configMap, _ := volume["configMap"].(map[string]any)
		if volume["name"] == "input" && configMap["name"] == name {
			return true
		}
	}
	return false
}

func equalStringList(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
