package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"gopkg.in/yaml.v3"
)

// prepareTargetAccessStageInstallation recovers the exact three public
// object bodies retained by a verified package and rechecks every plan digest.
func prepareTargetAccessStageInstallation(packaged VerifiedTargetAccessStagePackage) (TargetAccessStageInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanTargetAccessStageInstallation(packaged)
	if err != nil {
		return TargetAccessStageInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]submissionStageInstallObject, 0, len(plan.Creates))
	for index := range plan.Creates {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || len(value) == 0 {
			return TargetAccessStageInstallationPlan{}, nil, errors.New("decode target-access installation object")
		}
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return TargetAccessStageInstallationPlan{}, nil, errors.New("target-access installation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return TargetAccessStageInstallationPlan{}, nil, errors.New("target-access installation contains trailing object")
	}
	return plan, objects, nil
}

// prepareTargetAccessStageCredentialInstallation recovers both exact private
// Secret bodies. Only the workload writer Secret may contain the private,
// package-bound workload authority binding.
func prepareTargetAccessStageCredentialInstallation(packaged VerifiedTargetAccessStageCredentialPackage) (TargetAccessStageCredentialPackageReceipt, []submissionStageCredentialInstallObject, error) {
	if err := verifyTargetAccessStageCredentialPackage(packaged); err != nil {
		return TargetAccessStageCredentialPackageReceipt{}, nil, err
	}
	objects := make([]submissionStageCredentialInstallObject, 0, 2)
	for index, private := range packaged.objects {
		public := packaged.receipt.Credentials[index]
		var secret map[string]any
		if err := jsonstrict.Decode(private.raw, &secret); err != nil {
			return TargetAccessStageCredentialPackageReceipt{}, nil, errors.New("target-access credential object is invalid JSON")
		}
		metadata, _ := secret["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		data, _ := secret["data"].(map[string]any)
		expectedDataCount := 2
		if index == 1 {
			expectedDataCount = 3
		}
		if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["name"] != private.name || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != packaged.receipt.StageID || labels["openkubes.io/credential-role"] != private.role || annotations["openkubes.io/authority-identity"] != private.authority || annotations["openkubes.io/expires-at"] != public.ExpiresAt || len(data) != expectedDataCount {
			return TargetAccessStageCredentialPackageReceipt{}, nil, errors.New("target-access credential Secret semantics changed")
		}
		tokenEncoded, tokenOK := data["token"].(string)
		caEncoded, caOK := data["ca.crt"].(string)
		token, tokenErr := base64.StdEncoding.DecodeString(tokenEncoded)
		ca, caErr := base64.StdEncoding.DecodeString(caEncoded)
		expiresAt, timeErr := time.Parse(time.RFC3339, public.ExpiresAt)
		if !tokenOK || !caOK || tokenErr != nil || caErr != nil || len(token) == 0 || len(ca) == 0 || timeErr != nil || digest.SHA256(ca) != public.CABundleDigest {
			return TargetAccessStageCredentialPackageReceipt{}, nil, errors.New("target-access credential Secret data changed")
		}
		if index == 0 {
			if data["binding.json"] != nil {
				return TargetAccessStageCredentialPackageReceipt{}, nil, errors.New("ledger target-access credential contains a workload binding")
			}
		} else if err := verifyTargetAccessCredentialBinding(data, packaged.receipt.WorkloadBindingDigest, packaged.workloadAuthority, public.CABundleDigest); err != nil {
			return TargetAccessStageCredentialPackageReceipt{}, nil, err
		}
		collection := "/api/v1/namespaces/" + submissionStageInputNamespace + "/secrets"
		objects = append(objects, submissionStageCredentialInstallObject{
			order: index + 4, role: private.role, authority: private.authority, name: private.name,
			objectPath: collection + "/" + private.name, collectionPath: collection,
			objectDigest: public.ObjectDigest, expiresAt: expiresAt, raw: append([]byte(nil), private.raw...), token: token,
		})
	}
	return packaged.receipt, objects, nil
}

func verifyTargetAccessCredentialBinding(data map[string]any, expectedDigest, expectedAuthority, expectedCA string) error {
	bindingEncoded, ok := data["binding.json"].(string)
	if !ok {
		return errors.New("target-access workload credential binding is missing")
	}
	bindingRaw, err := base64.StdEncoding.DecodeString(bindingEncoded)
	if err != nil {
		return errors.New("target-access workload credential binding encoding is invalid")
	}
	var binding WorkloadAuthorityBinding
	if err := jsonstrict.Decode(bindingRaw, &binding); err != nil {
		return errors.New("target-access workload credential binding is invalid")
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil || bindingDigest != expectedDigest || digest.SHA256([]byte(binding.TargetClusterUID)) != expectedAuthority || binding.CABundleDigest != expectedCA {
		return errors.New("target-access workload credential binding identity changed")
	}
	return nil
}
