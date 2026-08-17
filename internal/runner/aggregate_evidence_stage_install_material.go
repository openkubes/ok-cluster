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

// prepareAggregateEvidenceStageInstallation recovers the exact three public
// object bodies retained by the verified package.
func prepareAggregateEvidenceStageInstallation(packaged VerifiedAggregateEvidenceStagePackage) (AggregateEvidenceStageInstallationPlan, []submissionStageInstallObject, error) {
	plan, err := PlanAggregateEvidenceStageInstallation(packaged)
	if err != nil {
		return AggregateEvidenceStageInstallationPlan{}, nil, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(packaged.raw))
	objects := make([]submissionStageInstallObject, 0, len(plan.Creates))
	for index := range plan.Creates {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil || len(value) == 0 {
			return AggregateEvidenceStageInstallationPlan{}, nil, errors.New("decode aggregate evidence installation object")
		}
		raw, err := json.Marshal(value)
		if err != nil || digest.SHA256(raw) != plan.Creates[index].ObjectDigest {
			return AggregateEvidenceStageInstallationPlan{}, nil, errors.New("aggregate evidence installation object differs from plan")
		}
		objects = append(objects, submissionStageInstallObject{plan: plan.Creates[index], raw: raw})
	}
	var trailing map[string]any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return AggregateEvidenceStageInstallationPlan{}, nil, errors.New("aggregate evidence installation contains trailing object")
	}
	return plan, objects, nil
}

// prepareAggregateEvidenceStageCredentialInstallation recovers the four
// private credential Secrets and rechecks their exact semantics.
func prepareAggregateEvidenceStageCredentialInstallation(packaged VerifiedAggregateEvidenceStageCredentialPackage) (AggregateEvidenceStageCredentialPackageReceipt, []submissionStageCredentialInstallObject, error) {
	if err := verifyAggregateEvidenceStageCredentialPackage(packaged); err != nil {
		return AggregateEvidenceStageCredentialPackageReceipt{}, nil, err
	}
	objects := make([]submissionStageCredentialInstallObject, 0, 4)
	for index, private := range packaged.objects {
		public := packaged.receipt.Credentials[index]
		var secret map[string]any
		if err := jsonstrict.Decode(private.raw, &secret); err != nil {
			return AggregateEvidenceStageCredentialPackageReceipt{}, nil, errors.New("aggregate evidence credential object is invalid JSON")
		}
		metadata, _ := secret["metadata"].(map[string]any)
		labels, _ := metadata["labels"].(map[string]any)
		annotations, _ := metadata["annotations"].(map[string]any)
		data, _ := secret["data"].(map[string]any)
		if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["name"] != private.name || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != packaged.receipt.StageID || labels["openkubes.io/credential-role"] != private.role || annotations["openkubes.io/authority-identity"] != private.authority || annotations["openkubes.io/expires-at"] != public.ExpiresAt || len(data) != 2 {
			return AggregateEvidenceStageCredentialPackageReceipt{}, nil, errors.New("aggregate evidence credential Secret semantics changed")
		}
		tokenEncoded, tokenOK := data["token"].(string)
		caEncoded, caOK := data["ca.crt"].(string)
		token, tokenErr := base64.StdEncoding.DecodeString(tokenEncoded)
		ca, caErr := base64.StdEncoding.DecodeString(caEncoded)
		expiresAt, timeErr := time.Parse(time.RFC3339, public.ExpiresAt)
		if !tokenOK || !caOK || tokenErr != nil || caErr != nil || len(token) == 0 || len(ca) == 0 || timeErr != nil || digest.SHA256(ca) != public.CABundleDigest {
			return AggregateEvidenceStageCredentialPackageReceipt{}, nil, errors.New("aggregate evidence credential Secret data changed")
		}
		collection := "/api/v1/namespaces/" + submissionStageInputNamespace + "/secrets"
		objects = append(objects, submissionStageCredentialInstallObject{
			order: index + 4, role: private.role, authority: private.authority, name: private.name,
			objectPath: collection + "/" + private.name, collectionPath: collection,
			objectDigest: public.ObjectDigest, expiresAt: expiresAt,
			raw: append([]byte(nil), private.raw...), token: append([]byte(nil), token...),
		})
	}
	return packaged.receipt, objects, nil
}
