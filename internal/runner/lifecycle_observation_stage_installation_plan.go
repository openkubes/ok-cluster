package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const LifecycleObservationStageInstallationPlanFormat = "ok147-lifecycle-observation-stage-installation-plan/v1"

// LifecycleObservationStageInstallationPlan is an offline exact-create
// description. It grants no authority to perform any recorded request.
type LifecycleObservationStageInstallationPlan struct {
	Format                   string                      `json:"format"`
	State                    string                      `json:"state"`
	StageID                  string                      `json:"stageId"`
	ObservationPackageDigest string                      `json:"observationPackageDigest"`
	Authority                string                      `json:"authority"`
	Creates                  []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed          bool                        `json:"mutationAllowed"`
}

// PlanLifecycleObservationStageInstallation verifies the immutable input,
// NetworkPolicy and Job identities and derives their exact create order. It
// performs no API request and opens no credential.
func PlanLifecycleObservationStageInstallation(packaged VerifiedLifecycleObservationStagePackage) (LifecycleObservationStageInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return LifecycleObservationStageInstallationPlan{}, err
	}
	expectedKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	if !equalStringList(receipt.ObjectKinds, expectedKinds) {
		return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation package object inventory is invalid")
	}
	documents := bytes.Split(packaged.raw, []byte("\n---\n"))
	if len(documents) != len(expectedKinds) || digest.SHA256(documents[0]) != receipt.InputConfigMapDigest || digest.SHA256(bytes.Join(documents[1:], []byte("\n---\n"))) != receipt.JobEnvelopeDigest {
		return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation package component identity differs")
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
			return LifecycleObservationStageInstallationPlan{}, errors.New("decode lifecycle observation package")
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expectedKinds) {
		return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation package object count is invalid")
	}

	configMapName, runID := "", ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation package create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation package object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation package object identity is invalid")
		}
		collectionPath, objectPath, err := submissionStageCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return LifecycleObservationStageInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return LifecycleObservationStageInstallationPlan{}, errors.New("encode lifecycle observation package object")
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
				return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation input ConfigMap semantics differ")
			}
			configMapName = name
		case "NetworkPolicy":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID {
				return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation NetworkPolicy selector differs from run identity")
			}
		case "Job":
			if name != runID {
				return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation Job and NetworkPolicy identities differ")
			}
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false {
				return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation Job runtime identity is invalid")
			}
			if !jobMountsInputConfigMap(podSpec, configMapName) || !jobUsesManagementAuthority(podSpec, packaged.managementAuthority) || !jobUsesLifecycleObservationCredentialSecrets(podSpec, packaged.ledgerCredential, packaged.managementCredential) {
				return LifecycleObservationStageInstallationPlan{}, errors.New("lifecycle observation Job binding differs from verified package")
			}
		}
	}
	return LifecycleObservationStageInstallationPlan{
		Format: LifecycleObservationStageInstallationPlanFormat, State: "VERIFIED", StageID: receipt.StageID,
		ObservationPackageDigest: receipt.PackageDigest, Authority: packaged.managementAuthority,
		Creates: creates, MutationAllowed: false,
	}, nil
}

func jobUsesLifecycleObservationCredentialSecrets(podSpec map[string]any, ledger, management string) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	found := map[string]string{}
	for _, item := range volumes {
		volume, _ := item.(map[string]any)
		name, _ := volume["name"].(string)
		if name != "ledger-credential" && name != "management-credential" {
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
	return len(found) == 2 && found["ledger-credential"] == ledger && found["management-credential"] == management
}
