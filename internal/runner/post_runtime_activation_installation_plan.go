package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/openkubes/ok-cluster/internal/digest"
	"gopkg.in/yaml.v3"
)

const PostRuntimeExecutionActivationInstallationPlanFormat = "ok147-post-runtime-execution-activation-installation-plan/v1"

// PostRuntimeExecutionActivationInstallationPlan is a credential-free exact
// description of the three creates that activate the verified post-runtime
// suffix. It is evidence, not create authority.
type PostRuntimeExecutionActivationInstallationPlan struct {
	Format               string                      `json:"format"`
	State                string                      `json:"state"`
	RunID                string                      `json:"runId"`
	PackageDigest        string                      `json:"packageDigest"`
	PlanDigest           string                      `json:"planDigest"`
	TargetIdentityDigest string                      `json:"targetIdentityDigest"`
	Authority            string                      `json:"authority"`
	Creates              []SubmissionStageCreatePlan `json:"creates"`
	MutationAllowed      bool                        `json:"mutationAllowed"`
}

// PlanPostRuntimeExecutionActivationInstallation derives the exact
// Secret -> NetworkPolicy -> Job absence/create sequence without opening a
// credential or contacting Kubernetes.
func PlanPostRuntimeExecutionActivationInstallation(packaged VerifiedPostRuntimeExecutionActivationPackage) (PostRuntimeExecutionActivationInstallationPlan, error) {
	receipt, err := packaged.Receipt()
	if err != nil {
		return PostRuntimeExecutionActivationInstallationPlan{}, err
	}
	expectedKinds := []string{"Secret", "NetworkPolicy", "Job"}
	if !equalStringList(receipt.ObjectKinds, expectedKinds) || packaged.managementAuthority == "" {
		return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation package inventory or authority is invalid")
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
			return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("decode post-runtime activation package")
		}
		objects = append(objects, object)
	}
	if len(objects) != len(expectedKinds) {
		return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation package object count is invalid")
	}

	runID := ""
	creates := make([]SubmissionStageCreatePlan, 0, len(objects))
	for index, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		kind, _ := object["kind"].(string)
		if kind != expectedKinds[index] {
			return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation create order is invalid")
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation object metadata is invalid")
		}
		name, _ := metadata["name"].(string)
		namespace, _ := metadata["namespace"].(string)
		if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || namespace != submissionStageInputNamespace || metadata["generateName"] != nil {
			return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation object identity is invalid")
		}
		collectionPath, objectPath, err := postRuntimeActivationCreatePaths(apiVersion, kind, namespace, name)
		if err != nil {
			return PostRuntimeExecutionActivationInstallationPlan{}, err
		}
		canonical, err := json.Marshal(object)
		if err != nil {
			return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("encode post-runtime activation object")
		}
		creates = append(creates, SubmissionStageCreatePlan{
			Order: index + 1, APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name,
			PreflightMethod: "GET", ObjectPath: objectPath, CreateMethod: "POST", CollectionPath: collectionPath,
			ObjectDigest: digest.SHA256(canonical),
		})
		switch kind {
		case "Secret":
			annotations, _ := metadata["annotations"].(map[string]any)
			labels, _ := metadata["labels"].(map[string]any)
			binaryData, _ := object["binaryData"].(map[string]any)
			if name != receipt.ActivationSecret || object["immutable"] != true || object["type"] != "Opaque" ||
				labels["openkubes.io/stage-id"] != "post-runtime" || annotations["openkubes.io/bundle-digest"] != receipt.BundleDigest ||
				annotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest || len(binaryData) != receipt.PrivateFileCount+1 {
				return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation Secret semantics differ")
			}
		case "NetworkPolicy":
			runID = name
			spec, _ := object["spec"].(map[string]any)
			selector, _ := spec["podSelector"].(map[string]any)
			matchLabels, _ := selector["matchLabels"].(map[string]any)
			if matchLabels["openkubes.io/execution-id"] != runID {
				return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation NetworkPolicy selector differs")
			}
		case "Job":
			spec, _ := object["spec"].(map[string]any)
			template, _ := spec["template"].(map[string]any)
			podSpec, _ := template["spec"].(map[string]any)
			annotations, _ := metadata["annotations"].(map[string]any)
			if name != runID || spec["backoffLimit"] != 0 || podSpec["serviceAccountName"] != "ok147-contract-executor-runtime" ||
				podSpec["automountServiceAccountToken"] != false || annotations["openkubes.io/bundle-digest"] != receipt.BundleDigest ||
				annotations["openkubes.io/manifest-digest"] != receipt.ManifestDigest || !postRuntimeJobMountsActivationSecret(podSpec, receipt.ActivationSecret, receipt.PrivateFileCount) {
				return PostRuntimeExecutionActivationInstallationPlan{}, errors.New("post-runtime activation Job binding differs")
			}
		}
	}
	return PostRuntimeExecutionActivationInstallationPlan{
		Format: PostRuntimeExecutionActivationInstallationPlanFormat, State: "VERIFIED", RunID: runID,
		PackageDigest: receipt.PackageDigest, PlanDigest: receipt.PlanDigest, TargetIdentityDigest: receipt.TargetIdentityDigest,
		Authority: packaged.managementAuthority, Creates: creates, MutationAllowed: false,
	}, nil
}

func postRuntimeActivationCreatePaths(apiVersion, kind, namespace, name string) (string, string, error) {
	if apiVersion == "v1" && kind == "Secret" {
		collection := "/api/v1/namespaces/" + namespace + "/secrets"
		return collection, collection + "/" + name, nil
	}
	return submissionStageCreatePaths(apiVersion, kind, namespace, name)
}

func postRuntimeJobMountsActivationSecret(podSpec map[string]any, name string, fileCount int) bool {
	volumes, ok := podSpec["volumes"].([]any)
	if !ok {
		return false
	}
	for _, value := range volumes {
		volume, _ := value.(map[string]any)
		if volume["name"] != "activation-source" {
			continue
		}
		secret, _ := volume["secret"].(map[string]any)
		items, _ := secret["items"].([]any)
		return secret["secretName"] == name && len(items) == fileCount+1
	}
	return false
}

func preparePostRuntimeExecutionActivationInstallation(packaged VerifiedPostRuntimeExecutionActivationPackage) (PostRuntimeExecutionActivationInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanPostRuntimeExecutionActivationInstallation(packaged)
	if err != nil {
		return PostRuntimeExecutionActivationInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]submissionStageInstallObject, 0, len(plan.Creates))
	for index := range plan.Creates {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || len(value) == 0 {
			return PostRuntimeExecutionActivationInstallationPlan{}, nil, errors.New("decode verified post-runtime activation object")
		}
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return PostRuntimeExecutionActivationInstallationPlan{}, nil, errors.New("post-runtime activation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PostRuntimeExecutionActivationInstallationPlan{}, nil, errors.New("post-runtime activation package contains trailing object")
	}
	return plan, objects, nil
}
