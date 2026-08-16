package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const EnablementStageInstallationPlanFormat = "ok147-enablement-stage-installation-plan/v1"

// EnablementStageInstallationPlan is an offline exact-create description. It
// grants no authority to perform any recorded request.
type EnablementStageInstallationPlan struct {
	Format                  string                      `json:"format"`
	State                   string                      `json:"state"`
	StageID                 string                      `json:"stageId"`
	EnablementPackageDigest string                      `json:"enablementPackageDigest"`
	Authority               string                      `json:"authority"`
	Creates                 []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed         bool                        `json:"mutationAllowed"`
}

// PlanEnablementStageInstallation verifies the immutable input,
// NetworkPolicy and Job identities and derives their exact create order. It
// performs no API request and opens no credential.
func PlanEnablementStageInstallation(packaged VerifiedEnablementStagePackage) (EnablementStageInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return EnablementStageInstallationPlan{}, err
	}
	expectedKinds := []string{"ConfigMap", "NetworkPolicy", "Job"}
	if !equalStringList(receipt.ObjectKinds, expectedKinds) {
		return EnablementStageInstallationPlan{}, errors.New("enablement package object inventory is invalid")
	}
	documents := bytes.Split(packaged.raw, []byte("\n---\n"))
	if len(documents) != len(expectedKinds) || digest.SHA256(documents[0]) != receipt.InputConfigMapDigest || digest.SHA256(bytes.Join(documents[1:], []byte("\n---\n"))) != receipt.JobEnvelopeDigest {
		return EnablementStageInstallationPlan{}, errors.New("enablement package component identity differs")
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
			return EnablementStageInstallationPlan{}, errors.New("decode enablement package")
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expectedKinds) {
		return EnablementStageInstallationPlan{}, errors.New("enablement package object count is invalid")
	}

	configMapName, runID := "", ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return EnablementStageInstallationPlan{}, errors.New("enablement package create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return EnablementStageInstallationPlan{}, errors.New("enablement package object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return EnablementStageInstallationPlan{}, errors.New("enablement package object identity is invalid")
		}
		collectionPath, objectPath, err := submissionStageCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return EnablementStageInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return EnablementStageInstallationPlan{}, errors.New("encode enablement package object")
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
				return EnablementStageInstallationPlan{}, errors.New("enablement input ConfigMap semantics differ")
			}
			configMapName = name
		case "NetworkPolicy":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID {
				return EnablementStageInstallationPlan{}, errors.New("enablement NetworkPolicy selector differs from run identity")
			}
		case "Job":
			if name != runID {
				return EnablementStageInstallationPlan{}, errors.New("enablement Job and NetworkPolicy identities differ")
			}
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			if podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" || podSpec["automountServiceAccountToken"] != false {
				return EnablementStageInstallationPlan{}, errors.New("enablement Job runtime identity is invalid")
			}
			if !jobMountsInputConfigMap(podSpec, configMapName) || !jobUsesManagementAuthority(podSpec, packaged.managementAuthority) || !jobUsesLifecycleObservationCredentialSecrets(podSpec, packaged.ledgerCredential, packaged.managementCredential) {
				return EnablementStageInstallationPlan{}, errors.New("enablement Job binding differs from verified package")
			}
		}
	}
	return EnablementStageInstallationPlan{
		Format: EnablementStageInstallationPlanFormat, State: "VERIFIED", StageID: receipt.StageID,
		EnablementPackageDigest: receipt.PackageDigest, Authority: packaged.managementAuthority,
		Creates: creates, MutationAllowed: false,
	}, nil
}
