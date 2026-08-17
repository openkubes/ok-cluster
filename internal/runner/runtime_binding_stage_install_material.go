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

// prepareRuntimeBindingStageInstallation recovers the exact three public
// object bodies retained by a verified package and rechecks every plan digest.
func prepareRuntimeBindingStageInstallation(packaged VerifiedRuntimeBindingStagePackage) (RuntimeBindingStageInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanRuntimeBindingStageInstallation(packaged)
	if err != nil {
		return RuntimeBindingStageInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]submissionStageInstallObject, 0, len(plan.Creates))
	for index := range plan.Creates {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || len(value) == 0 {
			return RuntimeBindingStageInstallationPlan{}, nil, errors.New("decode runtime binding installation object")
		}
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return RuntimeBindingStageInstallationPlan{}, nil, errors.New("runtime binding installation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RuntimeBindingStageInstallationPlan{}, nil, errors.New("runtime binding installation contains trailing object")
	}
	return plan, objects, nil
}

// prepareRuntimeBindingStageCredentialInstallation recovers the exact private
// Secret bodies and validates their semantic data once more. Only the workload
// observer Secret may carry the package-bound private workload binding.
func prepareRuntimeBindingStageCredentialInstallation(packaged VerifiedRuntimeBindingStageCredentialPackage) (RuntimeBindingStageCredentialPackageReceipt, []submissionStageCredentialInstallObject, error) {
	if err := verifyRuntimeBindingStageCredentialPackage(packaged); err != nil {
		return RuntimeBindingStageCredentialPackageReceipt{}, nil, err
	}
	objects := make([]submissionStageCredentialInstallObject, 0, 3)
	for index, private := range packaged.objects {
		public := packaged.receipt.Credentials[index]
		var secret map[string]any
		if err := jsonstrict.Decode(private.raw, &secret); err != nil {
			return RuntimeBindingStageCredentialPackageReceipt{}, nil, errors.New("runtime binding credential object is invalid JSON")
		}
		metadata, _ := secret["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		data, _ := secret["data"].(map[string]any)
		expectedDataCount := 2
		if index == 2 {
			expectedDataCount = 3
		}
		if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["name"] != private.name || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != packaged.receipt.StageID || labels["openkubes.io/credential-role"] != private.role || annotations["openkubes.io/authority-identity"] != private.authority || annotations["openkubes.io/expires-at"] != public.ExpiresAt || len(data) != expectedDataCount {
			return RuntimeBindingStageCredentialPackageReceipt{}, nil, errors.New("runtime binding credential Secret semantics changed")
		}
		tokenEncoded, tokenOK := data["token"].(string)
		caEncoded, caOK := data["ca.crt"].(string)
		token, tokenErr := base64.StdEncoding.DecodeString(tokenEncoded)
		ca, caErr := base64.StdEncoding.DecodeString(caEncoded)
		expiresAt, timeErr := time.Parse(time.RFC3339, public.ExpiresAt)
		if !tokenOK || !caOK || tokenErr != nil || caErr != nil || len(token) == 0 || len(ca) == 0 || timeErr != nil || digest.SHA256(ca) != public.CABundleDigest {
			return RuntimeBindingStageCredentialPackageReceipt{}, nil, errors.New("runtime binding credential Secret data changed")
		}
		if index < 2 {
			if data["binding.json"] != nil {
				return RuntimeBindingStageCredentialPackageReceipt{}, nil, errors.New("management-side runtime binding credential contains a workload binding")
			}
		} else if err := verifyRuntimeBindingCredentialBinding(data, packaged.receipt.WorkloadBindingDigest, packaged.workloadAuthority, public.CABundleDigest); err != nil {
			return RuntimeBindingStageCredentialPackageReceipt{}, nil, err
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

func verifyRuntimeBindingCredentialBinding(data map[string]any, expectedDigest, expectedAuthority, expectedCA string) error {
	bindingEncoded, ok := data["binding.json"].(string)
	if !ok {
		return errors.New("runtime binding workload credential binding is missing")
	}
	bindingRaw, err := base64.StdEncoding.DecodeString(bindingEncoded)
	if err != nil {
		return errors.New("runtime binding workload credential binding encoding is invalid")
	}
	var binding WorkloadAuthorityBinding
	if err := jsonstrict.Decode(bindingRaw, &binding); err != nil {
		return errors.New("runtime binding workload credential binding is invalid")
	}
	bindingDigest, err := WorkloadAuthorityBindingDigest(binding)
	if err != nil || bindingDigest != expectedDigest || digest.SHA256([]byte(binding.TargetClusterUID)) != expectedAuthority || binding.CABundleDigest != expectedCA {
		return errors.New("runtime binding workload credential binding identity changed")
	}
	return nil
}
