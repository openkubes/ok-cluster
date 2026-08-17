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

func TestBuildTargetAccessStageCredentialPackageBindsTwoPrivateSecrets(t *testing.T) {
	config, tokens := targetAccessCredentialConfig(t)
	packaged, err := BuildTargetAccessStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := config.Package.Receipt()
	if receipt.Format != TargetAccessStageCredentialPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "target-access" || receipt.TargetAccessPackageDigest != stageReceipt.PackageDigest || receipt.WorkloadBindingDigest != stageReceipt.WorkloadBindingDigest || receipt.InstallationAuthority != "ok-shared" || receipt.MaterializedAt != config.MaterializationTime.Format(time.RFC3339) || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || receipt.MutationAllowed || len(receipt.Credentials) != 2 {
		t.Fatalf("unexpected target-access credential receipt: %#v", receipt)
	}
	want := []struct {
		role      string
		name      string
		authority string
	}{
		{role: "ledger-writer", name: config.Package.ledgerCredential, authority: "ok-mgmt"},
		{role: "workload-writer", name: config.Package.workloadCredential, authority: config.Package.workloadAuthority},
	}
	for index, expected := range want {
		object := packaged.objects[index]
		objectReceipt := receipt.Credentials[index]
		if object.role != expected.role || object.authority != expected.authority || object.name != expected.name || digest.SHA256(object.raw) != objectReceipt.ObjectDigest {
			t.Fatalf("private target-access credential %d differs: %#v %#v", index, object, objectReceipt)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		data := secret["data"].(map[string]any)
		decodedToken, err := base64.StdEncoding.DecodeString(data["token"].(string))
		if err != nil || !bytes.Equal(decodedToken, tokens[index]) {
			t.Fatalf("private target-access token %d differs", index)
		}
		_, hasBinding := data["binding.json"]
		if hasBinding != (index == 1) {
			t.Fatalf("credential %d workload-binding presence differs", index)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		string(tokens[0]), string(tokens[1]), config.WorkloadBindingPath,
		config.LedgerWriter.TokenFile, config.WorkloadWriter.TokenFile,
		config.LedgerWriter.ExpectedSubject, config.WorkloadWriter.ExpectedSubject,
	} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("target-access credential receipt exposed private value %q", forbidden)
		}
	}
	receipt.Credentials[0].Audiences[0] = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Credentials[0].Audiences[0] == "changed" {
		t.Fatal("caller mutated retained target-access credential receipt")
	}
}

func TestBuildTargetAccessStageCredentialPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*TargetAccessStageCredentialPackageConfig){
		"foreign ledger authority": func(config *TargetAccessStageCredentialPackageConfig) {
			config.LedgerWriter.AuthorityIdentity = "ok-infra"
		},
		"foreign workload authority": func(config *TargetAccessStageCredentialPackageConfig) {
			config.WorkloadWriter.AuthorityIdentity = prefixSHA("f")
		},
		"workload CA differs from binding": func(config *TargetAccessStageCredentialPackageConfig) {
			config.WorkloadWriter.CABundleDigest = prefixSHA("e")
		},
		"shared token": func(config *TargetAccessStageCredentialPackageConfig) {
			config.WorkloadWriter.TokenFile = config.LedgerWriter.TokenFile
			config.WorkloadWriter.TokenDigest = config.LedgerWriter.TokenDigest
			config.WorkloadWriter.ExpectedIssuer = config.LedgerWriter.ExpectedIssuer
			config.WorkloadWriter.ExpectedSubject = config.LedgerWriter.ExpectedSubject
			config.WorkloadWriter.ExpectedAudiences = append([]string(nil), config.LedgerWriter.ExpectedAudiences...)
			config.WorkloadWriter.IssuedAt = config.LedgerWriter.IssuedAt
			config.WorkloadWriter.ExpiresAt = config.LedgerWriter.ExpiresAt
		},
		"missing TokenRequest evidence": func(config *TargetAccessStageCredentialPackageConfig) {
			config.LedgerWriter.TokenRequestEvidenceDigest = ""
		},
		"unverified package": func(config *TargetAccessStageCredentialPackageConfig) {
			config.Package = VerifiedTargetAccessStagePackage{}
		},
		"changed package identity": func(config *TargetAccessStageCredentialPackageConfig) {
			config.Package.receipt.PackageDigest = prefixSHA("d")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := targetAccessCredentialConfig(t)
			mutate(&config)
			_, err := BuildTargetAccessStageCredentialPackage(config)
			if err == nil || strings.Contains(err.Error(), config.WorkloadBindingPath) || strings.Contains(err.Error(), config.WorkloadWriter.TokenFile) {
				t.Fatalf("unsafe target-access credential package accepted: %v", err)
			}
		})
	}
	if _, err := (VerifiedTargetAccessStageCredentialPackage{}).Receipt(); err == nil {
		t.Fatal("unverified target-access credential receipt was exposed")
	}
	config, _ := targetAccessCredentialConfig(t)
	packaged, err := BuildTargetAccessStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.objects[1].raw = append(packaged.objects[1].raw, '\n')
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("changed private target-access credential was accepted")
	}
}

func targetAccessCredentialConfig(t *testing.T) (TargetAccessStageCredentialPackageConfig, [][]byte) {
	config, _, tokens := targetAccessCredentialInputs(t)
	return config, tokens
}

func targetAccessCredentialInputs(t *testing.T) (TargetAccessStageCredentialPackageConfig, TargetAccessStagePackageConfig, [][]byte) {
	t.Helper()
	now := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)
	issuedAt, expiresAt := now.Add(-time.Minute), now.Add(30*time.Minute)
	audiences := []string{"https://kubernetes.default.svc"}
	issuer := "https://kubernetes.default.svc.cluster.local"
	root := t.TempDir()
	managementCA, workloadCA := testCA(t), testCA(t)
	managementCAPath, workloadCAPath := filepath.Join(root, "management-ca.crt"), filepath.Join(root, "workload-ca.crt")
	if err := os.WriteFile(managementCAPath, managementCA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workloadCAPath, workloadCA, 0o600); err != nil {
		t.Fatal(err)
	}
	packageConfig := targetAccessStagePackageConfig(t)
	binding, err := loadWorkloadAuthorityBinding(packageConfig.WorkloadBindingPath, packageConfig.ExpectedWorkloadBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding.CABundleDigest = digest.SHA256(workloadCA)
	if err := os.WriteFile(packageConfig.WorkloadBindingPath, mustJSON(t, binding), 0o600); err != nil {
		t.Fatal(err)
	}
	packageConfig.ExpectedWorkloadBindingDigest, err = WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := BuildTargetAccessStagePackage(packageConfig)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []string{
		"system:serviceaccount:openkubes-execution-system:ok147-target-ledger-writer",
		"system:serviceaccount:openkubes-execution-system:ok147-target-workload-writer",
	}
	tokens := [][]byte{
		stageCredentialJWT(t, issuer, subjects[0], audiences, issuedAt, expiresAt, 'e'),
		stageCredentialJWT(t, issuer, subjects[1], audiences, issuedAt, expiresAt, 'f'),
	}
	tokenPaths := make([]string, len(tokens))
	for index, token := range tokens {
		tokenPaths[index] = filepath.Join(root, "token-"+string(rune('0'+index)))
		if err := os.WriteFile(tokenPaths[index], token, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	source := func(authority, tokenPath, subject, evidence, caPath string, token, ca []byte) SubmissionStageCredentialSource {
		return SubmissionStageCredentialSource{
			AuthorityIdentity: authority, TokenFile: tokenPath, TokenDigest: digest.SHA256(token),
			CAFile: caPath, CABundleDigest: digest.SHA256(ca), TokenRequestEvidenceDigest: prefixSHA(evidence),
			ExpectedIssuer: issuer, ExpectedSubject: subject, ExpectedAudiences: audiences,
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		}
	}
	return TargetAccessStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: now, WorkloadBindingPath: packageConfig.WorkloadBindingPath,
		LedgerWriter:   source("ok-mgmt", tokenPaths[0], subjects[0], "1", managementCAPath, tokens[0], managementCA),
		WorkloadWriter: source(digest.SHA256([]byte(binding.TargetClusterUID)), tokenPaths[1], subjects[1], "2", workloadCAPath, tokens[1], workloadCA),
	}, packageConfig, tokens
}
