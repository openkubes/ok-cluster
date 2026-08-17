package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const NetworkObservationStageInstallationPlanFormat = "ok147-network-observation-stage-installation-plan/v1"

// NetworkObservationStageInstallationPlan is a tokenless offline description
// of the three exact public objects. It grants no create authority.
type NetworkObservationStageInstallationPlan struct {
	Format                   string                      `json:"format"`
	State                    string                      `json:"state"`
	StageID                  string                      `json:"stageId"`
	ObservationPackageDigest string                      `json:"observationPackageDigest"`
	Authority                string                      `json:"authority"`
	Creates                  []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed          bool                        `json:"mutationAllowed"`
}

// PlanNetworkObservationStageInstallation verifies the immutable input,
// NetworkPolicy and Job and derives their exact create order without opening
// credentials or contacting Kubernetes.
func PlanNetworkObservationStageInstallation(packaged VerifiedNetworkObservationStagePackage) (NetworkObservationStageInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return NetworkObservationStageInstallationPlan{}, err
	}
	expectedKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	if !equalStringList(receipt.ObjectKinds, expectedKinds) {
		return NetworkObservationStageInstallationPlan{}, errors.New("network observation package object inventory is invalid")
	}
	documents := bytes.Split(packaged.raw, []byte("\n---\n"))
	if len(documents) != len(expectedKinds) || digest.SHA256(documents[0]) != receipt.InputConfigMapDigest || digest.SHA256(bytes.Join(documents[1:], []byte("\n---\n"))) != receipt.JobEnvelopeDigest {
		return NetworkObservationStageInstallationPlan{}, errors.New("network observation package component identity differs")
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
			return NetworkObservationStageInstallationPlan{}, errors.New("decode network observation package")
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expectedKinds) {
		return NetworkObservationStageInstallationPlan{}, errors.New("network observation package object count is invalid")
	}

	configMapName, runID := "", ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return NetworkObservationStageInstallationPlan{}, errors.New("network observation package create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return NetworkObservationStageInstallationPlan{}, errors.New("network observation package object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return NetworkObservationStageInstallationPlan{}, errors.New("network observation package object identity is invalid")
		}
		collectionPath, objectPath, err := submissionStageCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return NetworkObservationStageInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return NetworkObservationStageInstallationPlan{}, errors.New("encode network observation package object")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: "GET", ObjectPath: objectPath, CreateMethod: "POST", CollectionPath: collectionPath,
			ObjectDigest: digest.SHA256(canonical),
		})
		switch kind {
		case "ConfigMap":
			labels, _ := metadata["labels"].(map[string]any)
			if object["immutable"] != true || labels["openkubes.io/stage-id"] != receipt.StageID {
				return NetworkObservationStageInstallationPlan{}, errors.New("network observation input ConfigMap semantics differ")
			}
			configMapName = name
		case "NetworkPolicy":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID {
				return NetworkObservationStageInstallationPlan{}, errors.New("network observation NetworkPolicy selector differs from run identity")
			}
		case "Job":
			if name != runID {
				return NetworkObservationStageInstallationPlan{}, errors.New("network observation Job and NetworkPolicy identities differ")
			}
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false {
				return NetworkObservationStageInstallationPlan{}, errors.New("network observation Job runtime identity is invalid")
			}
			if !jobMountsInputConfigMap(podSpec, configMapName) || !jobUsesManagementAuthority(podSpec, packaged.managementAuthority) || !jobUsesNetworkObservationCredentialSecrets(podSpec, packaged.ledgerCredential, packaged.managementCredential, packaged.workloadCredential) {
				return NetworkObservationStageInstallationPlan{}, errors.New("network observation Job binding differs from verified package")
			}
		}
	}
	return NetworkObservationStageInstallationPlan{
		Format: NetworkObservationStageInstallationPlanFormat, State: "VERIFIED", StageID: receipt.StageID,
		ObservationPackageDigest: receipt.PackageDigest, Authority: packaged.managementAuthority,
		Creates: creates, MutationAllowed: false,
	}, nil
}

func jobUsesNetworkObservationCredentialSecrets(podSpec map[string]any, ledger, management, workload string) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	want := map[string]struct {
		secret string
		items  map[string]string
	}{
		"ledger-credential":     {secret: ledger, items: map[string]string{"token": "token", "ca.crt": "ca.crt"}},
		"management-credential": {secret: management, items: map[string]string{"token": "token", "ca.crt": "ca.crt"}},
		"workload-credential":   {secret: workload, items: map[string]string{"token": "token", "ca.crt": "ca.crt", "binding.json": "binding.json"}},
	}
	found := map[string]bool{}
	for _, item := range volumes {
		volume, _ := item.(map[string]any)
		name, _ := volume["name"].(string)
		expected, relevant := want[name]
		if !relevant {
			continue
		}
		secret, _ := volume["secret"].(map[string]any)
		secretName, _ := secret["secretName"].(string)
		items, _ := secret["items"].([]any)
		if secretName != expected.secret || !exactCredentialSecretItems(items, expected.items) {
			return false
		}
		found[name] = true
	}
	return len(found) == len(want)
}

func exactCredentialSecretItems(items []any, expected map[string]string) bool {
	if len(items) != len(expected) {
		return false
	}
	want := make(map[string]string, len(expected))
	for key, value := range expected {
		want[key] = value
	}
	for _, item := range items {
		entry, _ := item.(map[string]any)
		key, _ := entry["key"].(string)
		path, _ := entry["path"].(string)
		if want[key] != path {
			return false
		}
		delete(want, key)
	}
	return len(want) == 0
}
