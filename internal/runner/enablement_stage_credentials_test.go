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

func TestBuildEnablementStageCredentialPackageBindsDistinctPrivateSecrets(t *testing.T) {
	config, ledgerToken, writerToken := enablementCredentialConfig(t)
	packaged, err := BuildEnablementStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	packageReceipt, _ := config.Package.Receipt()
	if receipt.Format != EnablementStageCredentialPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "enablement" || receipt.EnablementPackageDigest != packageReceipt.PackageDigest || receipt.InstallationAuthority != "ok-mgmt" || receipt.MaterializedAt != config.MaterializationTime.Format(time.RFC3339) || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || receipt.MutationAllowed || len(receipt.Credentials) != 2 {
		t.Fatalf("unexpected enablement credential receipt: %#v", receipt)
	}
	want := []struct {
		role  string
		name  string
		token []byte
	}{
		{role: "ledger", name: config.Package.ledgerCredential, token: ledgerToken},
		{role: "writer", name: config.Package.managementCredential, token: writerToken},
	}
	for index, expected := range want {
		object := packaged.objects[index]
		objectReceipt := receipt.Credentials[index]
		if object.role != expected.role || object.authority != "ok-mgmt" || object.name != expected.name || digest.SHA256(object.raw) != objectReceipt.ObjectDigest {
			t.Fatalf("private enablement credential %d differs: %#v %#v", index, object, objectReceipt)
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
		if secret["immutable"] != true || metadata["namespace"] != submissionStageInputNamespace || labels["openkubes.io/stage-id"] != "enablement" || labels["openkubes.io/credential-role"] != expected.role || annotations["openkubes.io/authority-identity"] != "ok-mgmt" || !bytes.Equal(decodedToken, expected.token) {
			t.Fatalf("enablement credential Secret %d differs: %#v", index, secret)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{string(ledgerToken), string(writerToken), config.Ledger.TokenFile, config.Ledger.CAFile, config.Ledger.ExpectedSubject, config.ManagementWriter.ExpectedSubject} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("enablement credential receipt exposed private value %q", forbidden)
		}
	}
	receipt.Credentials[0].Audiences[0] = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Credentials[0].Audiences[0] == "changed" {
		t.Fatal("caller mutated retained enablement credential receipt")
	}
}

func TestBuildEnablementStageCredentialPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*EnablementStageCredentialPackageConfig){
		"foreign writer authority": func(config *EnablementStageCredentialPackageConfig) {
			config.ManagementWriter.AuthorityIdentity = "ok-infra"
		},
		"shared token": func(config *EnablementStageCredentialPackageConfig) {
			config.ManagementWriter.TokenFile = config.Ledger.TokenFile
			config.ManagementWriter.TokenDigest = config.Ledger.TokenDigest
			config.ManagementWriter.ExpectedIssuer = config.Ledger.ExpectedIssuer
			config.ManagementWriter.ExpectedSubject = config.Ledger.ExpectedSubject
			config.ManagementWriter.ExpectedAudiences = append([]string(nil), config.Ledger.ExpectedAudiences...)
			config.ManagementWriter.IssuedAt = config.Ledger.IssuedAt
			config.ManagementWriter.ExpiresAt = config.Ledger.ExpiresAt
		},
		"wrong token digest": func(config *EnablementStageCredentialPackageConfig) {
			config.ManagementWriter.TokenDigest = prefixSHA("1")
		},
		"missing evidence": func(config *EnablementStageCredentialPackageConfig) { config.Ledger.TokenRequestEvidenceDigest = "" },
		"unverified package": func(config *EnablementStageCredentialPackageConfig) {
			config.Package = VerifiedEnablementStagePackage{}
		},
		"changed package identity": func(config *EnablementStageCredentialPackageConfig) {
			config.Package.receipt.PackageDigest = prefixSHA("2")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _, _ := enablementCredentialConfig(t)
			mutate(&config)
			_, err := BuildEnablementStageCredentialPackage(config)
			if err == nil || strings.Contains(err.Error(), config.Ledger.TokenFile) || strings.Contains(err.Error(), config.ManagementWriter.TokenFile) {
				t.Fatalf("unsafe enablement credential package accepted: %v", err)
			}
		})
	}
	if _, err := (VerifiedEnablementStageCredentialPackage{}).Receipt(); err == nil {
		t.Fatal("unverified enablement credential receipt was exposed")
	}
	config, _, _ := enablementCredentialConfig(t)
	packaged, err := BuildEnablementStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.objects[1].raw = append(packaged.objects[1].raw, '\n')
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("changed private enablement credential was accepted")
	}
}

func enablementCredentialConfig(t *testing.T) (EnablementStageCredentialPackageConfig, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	issuedAt, expiresAt := now.Add(-time.Minute), now.Add(30*time.Minute)
	audiences := []string{"https://kubernetes.default.svc"}
	issuer := "https://kubernetes.default.svc.cluster.local"
	ledgerSubject := "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"
	writerSubject := "system:serviceaccount:openkubes-execution-system:ok147-enablement-writer"
	ledgerToken := stageCredentialJWT(t, issuer, ledgerSubject, audiences, issuedAt, expiresAt, 'e')
	writerToken := stageCredentialJWT(t, issuer, writerSubject, audiences, issuedAt, expiresAt, 'f')
	root := t.TempDir()
	ca := testCA(t)
	caPath := filepath.Join(root, "ca.crt")
	ledgerPath := filepath.Join(root, "ledger-token")
	writerPath := filepath.Join(root, "writer-token")
	for path, raw := range map[string][]byte{caPath: ca, ledgerPath: ledgerToken, writerPath: writerToken} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixture := enablementBundleFixture(t)
	enablementPackage, err := BuildEnablementStagePackage(enablementStagePackageConfig(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	source := func(tokenPath, subject, evidence string, token []byte) SubmissionStageCredentialSource {
		return SubmissionStageCredentialSource{
			AuthorityIdentity: "ok-mgmt", TokenFile: tokenPath, TokenDigest: digest.SHA256(token),
			CAFile: caPath, CABundleDigest: digest.SHA256(ca), TokenRequestEvidenceDigest: prefixSHA(evidence),
			ExpectedIssuer: issuer, ExpectedSubject: subject, ExpectedAudiences: audiences,
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		}
	}
	return EnablementStageCredentialPackageConfig{
		Package: enablementPackage, MaterializationTime: now,
		Ledger: source(ledgerPath, ledgerSubject, "a", ledgerToken), ManagementWriter: source(writerPath, writerSubject, "b", writerToken),
	}, ledgerToken, writerToken
}
