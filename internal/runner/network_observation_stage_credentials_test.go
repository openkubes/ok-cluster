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

func TestBuildNetworkObservationStageCredentialPackageBindsThreePrivateSecrets(t *testing.T) {
	config, tokens := networkObservationCredentialConfig(t)
	packaged, err := BuildNetworkObservationStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	observationReceipt, _ := config.Package.Receipt()
	if receipt.Format != NetworkObservationStageCredentialPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "network-observation" || receipt.ObservationPackageDigest != observationReceipt.PackageDigest || receipt.WorkloadBindingDigest != observationReceipt.WorkloadBindingDigest || receipt.InstallationAuthority != "ok-mgmt" || receipt.MaterializedAt != config.MaterializationTime.Format(time.RFC3339) || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || receipt.MutationAllowed || len(receipt.Credentials) != 3 {
		t.Fatalf("unexpected network observation credential receipt: %#v", receipt)
	}
	want := []struct {
		role      string
		name      string
		authority string
	}{
		{role: "ledger", name: config.Package.ledgerCredential, authority: "ok-mgmt"},
		{role: "management-observer", name: config.Package.managementCredential, authority: "ok-mgmt"},
		{role: "workload-observer", name: config.Package.workloadCredential, authority: config.Package.workloadAuthority},
	}
	for index, expected := range want {
		object := packaged.objects[index]
		objectReceipt := receipt.Credentials[index]
		if object.role != expected.role || object.authority != expected.authority || object.name != expected.name || digest.SHA256(object.raw) != objectReceipt.ObjectDigest {
			t.Fatalf("private network credential %d differs: %#v %#v", index, object, objectReceipt)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		data := secret["data"].(map[string]any)
		decodedToken, err := base64.StdEncoding.DecodeString(data["token"].(string))
		if err != nil || !bytes.Equal(decodedToken, tokens[index]) {
			t.Fatalf("private network token %d differs", index)
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
		config.Ledger.TokenFile, config.ManagementObserver.TokenFile, config.WorkloadObserver.TokenFile,
		config.Ledger.ExpectedSubject, config.ManagementObserver.ExpectedSubject, config.WorkloadObserver.ExpectedSubject,
	} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("network observation credential receipt exposed private value %q", forbidden)
		}
	}
	receipt.Credentials[0].Audiences[0] = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Credentials[0].Audiences[0] == "changed" {
		t.Fatal("caller mutated retained network observation credential receipt")
	}
}

func TestBuildNetworkObservationStageCredentialPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*NetworkObservationStageCredentialPackageConfig){
		"foreign management authority": func(config *NetworkObservationStageCredentialPackageConfig) {
			config.ManagementObserver.AuthorityIdentity = "ok-infra"
		},
		"foreign workload authority": func(config *NetworkObservationStageCredentialPackageConfig) {
			config.WorkloadObserver.AuthorityIdentity = prefixSHA("f")
		},
		"workload CA differs from binding": func(config *NetworkObservationStageCredentialPackageConfig) {
			config.WorkloadObserver.CABundleDigest = prefixSHA("e")
		},
		"shared token": func(config *NetworkObservationStageCredentialPackageConfig) {
			config.WorkloadObserver.TokenFile = config.ManagementObserver.TokenFile
			config.WorkloadObserver.TokenDigest = config.ManagementObserver.TokenDigest
			config.WorkloadObserver.ExpectedIssuer = config.ManagementObserver.ExpectedIssuer
			config.WorkloadObserver.ExpectedSubject = config.ManagementObserver.ExpectedSubject
			config.WorkloadObserver.ExpectedAudiences = append([]string(nil), config.ManagementObserver.ExpectedAudiences...)
			config.WorkloadObserver.IssuedAt = config.ManagementObserver.IssuedAt
			config.WorkloadObserver.ExpiresAt = config.ManagementObserver.ExpiresAt
		},
		"missing TokenRequest evidence": func(config *NetworkObservationStageCredentialPackageConfig) {
			config.Ledger.TokenRequestEvidenceDigest = ""
		},
		"unverified package": func(config *NetworkObservationStageCredentialPackageConfig) {
			config.Package = VerifiedNetworkObservationStagePackage{}
		},
		"changed package identity": func(config *NetworkObservationStageCredentialPackageConfig) {
			config.Package.receipt.PackageDigest = prefixSHA("d")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := networkObservationCredentialConfig(t)
			mutate(&config)
			_, err := BuildNetworkObservationStageCredentialPackage(config)
			if err == nil || strings.Contains(err.Error(), config.WorkloadBindingPath) || strings.Contains(err.Error(), config.WorkloadObserver.TokenFile) {
				t.Fatalf("unsafe network observation credential package accepted: %v", err)
			}
		})
	}
	if _, err := (VerifiedNetworkObservationStageCredentialPackage{}).Receipt(); err == nil {
		t.Fatal("unverified network observation credential receipt was exposed")
	}
	config, _ := networkObservationCredentialConfig(t)
	packaged, err := BuildNetworkObservationStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.objects[2].raw = append(packaged.objects[2].raw, '\n')
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("changed private network observation credential was accepted")
	}
}

func networkObservationCredentialConfig(t *testing.T) (NetworkObservationStageCredentialPackageConfig, [][]byte) {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
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
	packageConfig := networkObservationStagePackageConfig(t)
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
	packaged, err := BuildNetworkObservationStagePackage(packageConfig)
	if err != nil {
		t.Fatal(err)
	}

	subjects := []string{
		"system:serviceaccount:openkubes-execution-system:ok147-ledger-writer",
		"system:serviceaccount:openkubes-execution-system:ok147-network-management-observer",
		"system:serviceaccount:openkubes-execution-system:ok147-network-workload-observer",
	}
	tokens := [][]byte{
		stageCredentialJWT(t, issuer, subjects[0], audiences, issuedAt, expiresAt, 'e'),
		stageCredentialJWT(t, issuer, subjects[1], audiences, issuedAt, expiresAt, 'f'),
		stageCredentialJWT(t, issuer, subjects[2], audiences, issuedAt, expiresAt, 'a'),
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
	return NetworkObservationStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: now, WorkloadBindingPath: packageConfig.WorkloadBindingPath,
		Ledger:             source("ok-mgmt", tokenPaths[0], subjects[0], "1", managementCAPath, tokens[0], managementCA),
		ManagementObserver: source("ok-mgmt", tokenPaths[1], subjects[1], "2", managementCAPath, tokens[1], managementCA),
		WorkloadObserver:   source(digest.SHA256([]byte(binding.TargetClusterUID)), tokenPaths[2], subjects[2], "3", workloadCAPath, tokens[2], workloadCA),
	}, tokens
}
