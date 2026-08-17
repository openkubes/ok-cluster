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

func TestBuildRuntimeBindingStageCredentialPackageBindsThreePrivateSecrets(t *testing.T) {
	config, tokens := runtimeBindingCredentialConfig(t)
	packaged, err := BuildRuntimeBindingStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := config.Package.Receipt()
	if receipt.Format != RuntimeBindingStageCredentialPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "runtime-binding" || receipt.StagePackageDigest != stageReceipt.PackageDigest || receipt.WorkloadBindingDigest != stageReceipt.WorkloadBindingDigest || receipt.InstallationAuthority != "ok-mgmt" || receipt.MaterializedAt != config.MaterializationTime.Format(time.RFC3339) || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || receipt.MutationAllowed || len(receipt.Credentials) != 3 {
		t.Fatalf("unexpected runtime binding credential receipt: %#v", receipt)
	}
	want := []struct {
		role      string
		name      string
		authority string
	}{
		{role: "ledger-writer", name: config.Package.ledgerCredential, authority: "ok-mgmt"},
		{role: "persistence-writer", name: config.Package.persistenceCredential, authority: "ok-mgmt"},
		{role: "workload-observer", name: config.Package.workloadCredential, authority: config.Package.workloadAuthority},
	}
	for index, expected := range want {
		object := packaged.objects[index]
		objectReceipt := receipt.Credentials[index]
		if object.role != expected.role || object.authority != expected.authority || object.name != expected.name || digest.SHA256(object.raw) != objectReceipt.ObjectDigest {
			t.Fatalf("private runtime binding credential %d differs: %#v %#v", index, object, objectReceipt)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		data := secret["data"].(map[string]any)
		decodedToken, err := base64.StdEncoding.DecodeString(data["token"].(string))
		if err != nil || !bytes.Equal(decodedToken, tokens[index]) {
			t.Fatalf("private runtime binding token %d differs", index)
		}
		_, hasBinding := data["binding.json"]
		if hasBinding != (index == 2) {
			t.Fatalf("credential %d workload-binding presence differs", index)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		string(tokens[0]), string(tokens[1]), string(tokens[2]), config.WorkloadBindingPath,
		config.LedgerWriter.TokenFile, config.PersistenceWriter.TokenFile, config.WorkloadObserver.TokenFile,
		config.LedgerWriter.ExpectedSubject, config.PersistenceWriter.ExpectedSubject, config.WorkloadObserver.ExpectedSubject,
	} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("runtime binding credential receipt exposed private value %q", forbidden)
		}
	}
	receipt.Credentials[0].Audiences[0] = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Credentials[0].Audiences[0] == "changed" {
		t.Fatal("caller mutated retained runtime binding credential receipt")
	}
}

func TestBuildRuntimeBindingStageCredentialPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeBindingStageCredentialPackageConfig){
		"foreign persistence authority": func(config *RuntimeBindingStageCredentialPackageConfig) {
			config.PersistenceWriter.AuthorityIdentity = "ok-infra"
		},
		"foreign workload authority": func(config *RuntimeBindingStageCredentialPackageConfig) {
			config.WorkloadObserver.AuthorityIdentity = prefixSHA("f")
		},
		"workload CA differs from binding": func(config *RuntimeBindingStageCredentialPackageConfig) {
			config.WorkloadObserver.CABundleDigest = prefixSHA("e")
		},
		"shared token": func(config *RuntimeBindingStageCredentialPackageConfig) {
			config.PersistenceWriter.TokenFile = config.LedgerWriter.TokenFile
			config.PersistenceWriter.TokenDigest = config.LedgerWriter.TokenDigest
			config.PersistenceWriter.ExpectedIssuer = config.LedgerWriter.ExpectedIssuer
			config.PersistenceWriter.ExpectedSubject = config.LedgerWriter.ExpectedSubject
			config.PersistenceWriter.ExpectedAudiences = append([]string(nil), config.LedgerWriter.ExpectedAudiences...)
			config.PersistenceWriter.IssuedAt = config.LedgerWriter.IssuedAt
			config.PersistenceWriter.ExpiresAt = config.LedgerWriter.ExpiresAt
		},
		"missing TokenRequest evidence": func(config *RuntimeBindingStageCredentialPackageConfig) {
			config.LedgerWriter.TokenRequestEvidenceDigest = ""
		},
		"unverified package": func(config *RuntimeBindingStageCredentialPackageConfig) {
			config.Package = VerifiedRuntimeBindingStagePackage{}
		},
		"changed package identity": func(config *RuntimeBindingStageCredentialPackageConfig) {
			config.Package.receipt.PackageDigest = prefixSHA("d")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := runtimeBindingCredentialConfig(t)
			mutate(&config)
			_, err := BuildRuntimeBindingStageCredentialPackage(config)
			if err == nil || strings.Contains(err.Error(), config.WorkloadBindingPath) || strings.Contains(err.Error(), config.WorkloadObserver.TokenFile) {
				t.Fatalf("unsafe runtime binding credential package accepted: %v", err)
			}
		})
	}
	if _, err := (VerifiedRuntimeBindingStageCredentialPackage{}).Receipt(); err == nil {
		t.Fatal("unverified runtime binding credential receipt was exposed")
	}
	config, _ := runtimeBindingCredentialConfig(t)
	packaged, err := BuildRuntimeBindingStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.objects[2].raw = append(packaged.objects[2].raw, '\n')
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("changed private runtime binding credential was accepted")
	}
}

func runtimeBindingCredentialConfig(t *testing.T) (RuntimeBindingStageCredentialPackageConfig, [][]byte) {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	issuedAt, expiresAt := now.Add(-time.Minute), now.Add(30*time.Minute)
	audiences := []string{"https://kubernetes.default.svc"}
	issuer := "https://kubernetes.default.svc.cluster.local"
	root := t.TempDir()
	managementCA, workloadCA := testCA(t), testCA(t)
	managementCAPath := filepath.Join(root, "management-ca.crt")
	workloadCAPath := filepath.Join(root, "workload-ca.crt")
	if err := os.WriteFile(managementCAPath, managementCA, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workloadCAPath, workloadCA, 0o600); err != nil {
		t.Fatal(err)
	}
	packageConfig := runtimeBindingStagePackageConfig(t)
	binding, err := loadWorkloadAuthorityBinding(packageConfig.WorkloadBindingPath, packageConfig.ExpectedWorkloadBindingDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding.CABundleDigest = digest.SHA256(workloadCA)
	bindingRaw := mustJSON(t, binding)
	if err := os.WriteFile(packageConfig.WorkloadBindingPath, bindingRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	packageConfig.ExpectedWorkloadBindingDigest, err = WorkloadAuthorityBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	packaged, err := BuildRuntimeBindingStagePackage(packageConfig)
	if err != nil {
		t.Fatal(err)
	}

	subjects := []string{
		"system:serviceaccount:openkubes-execution-system:ok147-runtime-ledger-writer",
		"system:serviceaccount:openkubes-execution-system:ok147-runtime-persistence-writer",
		"system:serviceaccount:openkubes-execution-system:ok147-runtime-workload-observer",
	}
	tokens := [][]byte{
		stageCredentialJWT(t, issuer, subjects[0], audiences, issuedAt, expiresAt, 'b'),
		stageCredentialJWT(t, issuer, subjects[1], audiences, issuedAt, expiresAt, 'c'),
		stageCredentialJWT(t, issuer, subjects[2], audiences, issuedAt, expiresAt, 'd'),
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
	return RuntimeBindingStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: now, WorkloadBindingPath: packageConfig.WorkloadBindingPath,
		LedgerWriter:      source("ok-mgmt", tokenPaths[0], subjects[0], "4", managementCAPath, tokens[0], managementCA),
		PersistenceWriter: source("ok-mgmt", tokenPaths[1], subjects[1], "5", managementCAPath, tokens[1], managementCA),
		WorkloadObserver:  source(digest.SHA256([]byte(binding.TargetClusterUID)), tokenPaths[2], subjects[2], "6", workloadCAPath, tokens[2], workloadCA),
	}, tokens
}
