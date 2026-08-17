package runner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestBuildLifecycleObservationStageCredentialPackageBindsDistinctPrivateSecrets(t *testing.T) {
	config, ledgerToken, observerToken := lifecycleObservationCredentialConfig(t)
	packaged, err := BuildLifecycleObservationStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	observationReceipt, _ := config.Package.Receipt()
	if receipt.Format != LifecycleObservationStageCredentialPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "lifecycle-observation" || receipt.ObservationPackageDigest != observationReceipt.PackageDigest || receipt.InstallationAuthority != "ok-mgmt" || receipt.MaterializedAt != config.MaterializationTime.Format(time.RFC3339) || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || receipt.MutationAllowed || len(receipt.Credentials) != 2 {
		t.Fatalf("unexpected lifecycle observation credential receipt: %#v", receipt)
	}
	want := []struct {
		role  string
		name  string
		token []byte
	}{
		{role: "ledger", name: config.Package.ledgerCredential, token: ledgerToken},
		{role: "observer", name: config.Package.managementCredential, token: observerToken},
	}
	for index, expected := range want {
		object := packaged.objects[index]
		objectReceipt := receipt.Credentials[index]
		if object.role != expected.role || object.authority != "ok-mgmt" || object.name != expected.name || digest.SHA256(object.raw) != objectReceipt.ObjectDigest {
			t.Fatalf("private observation credential %d differs: %#v %#v", index, object, objectReceipt)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		metadata := secret["metadata"].(map[string]any)
		labels := metadata["labels"].(map[string]any)
		annotations := metadata["annotations"].(map[string]any)
		data := secret["data"].(map[string]any)
		decodedToken, err := base64.StdEncoding.DecodeString(data["token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if secret["immutable"] != true || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != "lifecycle-observation" || labels["openkubes.io/credential-role"] != expected.role || annotations["openkubes.io/authority-identity"] != "ok-mgmt" || !bytes.Equal(decodedToken, expected.token) {
			t.Fatalf("observation credential Secret %d differs: %#v", index, secret)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{string(ledgerToken), string(observerToken), config.Ledger.TokenFile, config.Ledger.CAFile, config.Ledger.ExpectedSubject, config.ManagementObserver.ExpectedSubject} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("observation credential receipt exposed private value %q", forbidden)
		}
	}
	receipt.Credentials[0].Audiences[0] = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Credentials[0].Audiences[0] == "changed" {
		t.Fatal("caller mutated retained observation credential receipt")
	}
}

func TestBuildLifecycleObservationStageCredentialPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*LifecycleObservationStageCredentialPackageConfig){
		"foreign observer authority": func(config *LifecycleObservationStageCredentialPackageConfig) {
			config.ManagementObserver.AuthorityIdentity = "ok-infra"
		},
		"shared token": func(config *LifecycleObservationStageCredentialPackageConfig) {
			config.ManagementObserver.TokenFile = config.Ledger.TokenFile
			config.ManagementObserver.TokenDigest = config.Ledger.TokenDigest
			config.ManagementObserver.ExpectedIssuer = config.Ledger.ExpectedIssuer
			config.ManagementObserver.ExpectedSubject = config.Ledger.ExpectedSubject
			config.ManagementObserver.ExpectedAudiences = append([]string(nil), config.Ledger.ExpectedAudiences...)
			config.ManagementObserver.IssuedAt = config.Ledger.IssuedAt
			config.ManagementObserver.ExpiresAt = config.Ledger.ExpiresAt
		},
		"wrong token digest": func(config *LifecycleObservationStageCredentialPackageConfig) {
			config.ManagementObserver.TokenDigest = prefixSHA("1")
		},
		"missing evidence": func(config *LifecycleObservationStageCredentialPackageConfig) {
			config.Ledger.TokenRequestEvidenceDigest = ""
		},
		"unverified package": func(config *LifecycleObservationStageCredentialPackageConfig) {
			config.Package = VerifiedLifecycleObservationStagePackage{}
		},
		"changed package identity": func(config *LifecycleObservationStageCredentialPackageConfig) {
			config.Package.receipt.PackageDigest = prefixSHA("2")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _, _ := lifecycleObservationCredentialConfig(t)
			mutate(&config)
			_, err := BuildLifecycleObservationStageCredentialPackage(config)
			if err == nil || strings.Contains(err.Error(), config.Ledger.TokenFile) || strings.Contains(err.Error(), config.ManagementObserver.TokenFile) {
				t.Fatalf("unsafe observation credential package accepted: %v", err)
			}
		})
	}
	if _, err := (VerifiedLifecycleObservationStageCredentialPackage{}).Receipt(); err == nil {
		t.Fatal("unverified lifecycle observation credential receipt was exposed")
	}
	config, _, _ := lifecycleObservationCredentialConfig(t)
	packaged, err := BuildLifecycleObservationStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.objects[1].raw = append(packaged.objects[1].raw, '\n')
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("changed private observation credential was accepted")
	}
}

func lifecycleObservationCredentialConfig(t *testing.T) (LifecycleObservationStageCredentialPackageConfig, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	issuedAt, expiresAt := now.Add(-time.Minute), now.Add(30*time.Minute)
	audiences := []string{"https://kubernetes.default.svc"}
	issuer := "https://kubernetes.default.svc.cluster.local"
	ledgerSubject := "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"
	observerSubject := "system:serviceaccount:openkubes-execution-system:ok147-lifecycle-observer"
	ledgerToken := stageCredentialJWT(t, issuer, ledgerSubject, audiences, issuedAt, expiresAt, 'c')
	observerToken := stageCredentialJWT(t, issuer, observerSubject, audiences, issuedAt, expiresAt, 'd')
	root := t.TempDir()
	ca := testCA(t)
	caPath := filepath.Join(root, "ca.crt")
	ledgerPath := filepath.Join(root, "ledger-token")
	observerPath := filepath.Join(root, "observer-token")
	for path, raw := range map[string][]byte{caPath: ca, ledgerPath: ledgerToken, observerPath: observerToken} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	source := func(tokenPath, subject, evidence string, token []byte) SubmissionStageCredentialSource {
		return SubmissionStageCredentialSource{
			AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath, TokenDigest: digest.SHA256(token),
			CAFile: caPath, CABundleDigest: digest.SHA256(ca), TokenRequestEvidenceDigest: prefixSHA(evidence),
			ExpectedIssuer: issuer, ExpectedSubject: subject, ExpectedAudiences: audiences,
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		}
	}
	observationPackage, err := BuildLifecycleObservationStagePackage(lifecycleObservationStagePackageConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	return LifecycleObservationStageCredentialPackageConfig{
		Package: observationPackage, MaterializationTime: now,
		Ledger:             source(ledgerPath, ledgerSubject, "a", ledgerToken),
		ManagementObserver: source(observerPath, observerSubject, "b", observerToken),
	}, ledgerToken, observerToken
}
