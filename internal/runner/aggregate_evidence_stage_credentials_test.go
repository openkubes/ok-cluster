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
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

func TestBuildAggregateEvidenceStageCredentialPackageBindsFourPrivateSecrets(t *testing.T) {
	config, tokens := aggregateEvidenceCredentialConfig(t)
	packaged, err := BuildAggregateEvidenceStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, _ := config.Package.Receipt()
	if receipt.Format != AggregateEvidenceStageCredentialPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "aggregate-evidence" || receipt.StagePackageDigest != stageReceipt.PackageDigest || receipt.InstallationAuthority != "ok-mgmt" || receipt.MaterializedAt != config.MaterializationTime.Format(time.RFC3339) || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || receipt.MutationAllowed || len(receipt.Credentials) != 4 {
		t.Fatalf("unexpected aggregate evidence credential receipt: %#v", receipt)
	}
	want := []struct {
		role      string
		name      string
		authority string
	}{
		{role: "ledger", name: config.Package.ledgerCredential, authority: "ok-mgmt"},
		{role: "management-observer", name: config.Package.managementCredential, authority: "ok-mgmt"},
		{role: "workload-observer", name: config.Package.workloadCredential, authority: config.Package.workloadAuthority},
		{role: "argo-observer", name: config.Package.argoCredential, authority: "ok-shared"},
	}
	for index, expected := range want {
		object := packaged.objects[index]
		objectReceipt := receipt.Credentials[index]
		if object.role != expected.role || object.authority != expected.authority || object.name != expected.name || digest.SHA256(object.raw) != objectReceipt.ObjectDigest {
			t.Fatalf("private aggregate credential %d differs: %#v %#v", index, object, objectReceipt)
		}
		var secret map[string]any
		if err := json.Unmarshal(object.raw, &secret); err != nil {
			t.Fatal(err)
		}
		data := secret["data"].(map[string]any)
		decodedToken, err := base64.StdEncoding.DecodeString(data["token"].(string))
		if err != nil || !bytes.Equal(decodedToken, tokens[index]) || len(data) != 2 {
			t.Fatalf("private aggregate token %d differs", index)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		string(tokens[0]), string(tokens[1]), string(tokens[2]), string(tokens[3]),
		config.Ledger.TokenFile, config.ManagementObserver.TokenFile,
		config.WorkloadObserver.TokenFile, config.ArgoObserver.TokenFile,
		config.Ledger.ExpectedSubject, config.ManagementObserver.ExpectedSubject,
		config.WorkloadObserver.ExpectedSubject, config.ArgoObserver.ExpectedSubject,
	} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("aggregate evidence credential receipt exposed private value %q", forbidden)
		}
	}
	receipt.Credentials[0].Audiences[0] = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Credentials[0].Audiences[0] == "changed" {
		t.Fatal("caller mutated retained aggregate evidence credential receipt")
	}
}

func TestBuildAggregateEvidenceStageCredentialPackageFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*AggregateEvidenceStageCredentialPackageConfig){
		"foreign management authority": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.ManagementObserver.AuthorityIdentity = "ok-infra"
		},
		"management CA differs": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.ManagementObserver.CABundleDigest = prefixSHA("d")
		},
		"foreign workload authority": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.WorkloadObserver.AuthorityIdentity = prefixSHA("f")
		},
		"workload CA differs from runtime": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.WorkloadObserver.CABundleDigest = prefixSHA("e")
		},
		"foreign Argo authority": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.ArgoObserver.AuthorityIdentity = "ok-mgmt"
		},
		"shared token": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.ArgoObserver.TokenFile = config.WorkloadObserver.TokenFile
			config.ArgoObserver.TokenDigest = config.WorkloadObserver.TokenDigest
			config.ArgoObserver.ExpectedIssuer = config.WorkloadObserver.ExpectedIssuer
			config.ArgoObserver.ExpectedSubject = config.WorkloadObserver.ExpectedSubject
			config.ArgoObserver.ExpectedAudiences = append([]string(nil), config.WorkloadObserver.ExpectedAudiences...)
			config.ArgoObserver.IssuedAt = config.WorkloadObserver.IssuedAt
			config.ArgoObserver.ExpiresAt = config.WorkloadObserver.ExpiresAt
		},
		"missing TokenRequest evidence": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.Ledger.TokenRequestEvidenceDigest = ""
		},
		"unverified package": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.Package = VerifiedAggregateEvidenceStagePackage{}
		},
		"changed package identity": func(config *AggregateEvidenceStageCredentialPackageConfig) {
			config.Package.receipt.PackageDigest = prefixSHA("c")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := aggregateEvidenceCredentialConfig(t)
			mutate(&config)
			_, err := BuildAggregateEvidenceStageCredentialPackage(config)
			if err == nil || strings.Contains(err.Error(), config.WorkloadObserver.TokenFile) {
				t.Fatalf("unsafe aggregate evidence credential package accepted: %v", err)
			}
		})
	}
	if _, err := (VerifiedAggregateEvidenceStageCredentialPackage{}).Receipt(); err == nil {
		t.Fatal("unverified aggregate evidence credential receipt was exposed")
	}
	config, _ := aggregateEvidenceCredentialConfig(t)
	packaged, err := BuildAggregateEvidenceStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packaged.objects[3].raw = append(packaged.objects[3].raw, '\n')
	if _, err := packaged.Receipt(); err == nil {
		t.Fatal("changed private aggregate evidence credential was accepted")
	}
}

func aggregateEvidenceCredentialConfig(t *testing.T) (AggregateEvidenceStageCredentialPackageConfig, [][]byte) {
	t.Helper()
	return aggregateEvidenceCredentialConfigForPackage(t, aggregateEvidenceStagePackageConfig(t))
}

func aggregateEvidenceCredentialConfigForPackage(t *testing.T, packageConfig AggregateEvidenceStagePackageConfig) (AggregateEvidenceStageCredentialPackageConfig, [][]byte) {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	issuedAt, expiresAt := now.Add(-time.Minute), now.Add(30*time.Minute)
	audiences := []string{"https://kubernetes.default.svc"}
	issuer := "https://kubernetes.default.svc.cluster.local"
	root := t.TempDir()
	managementCA, argoCA := testCA(t), testCA(t)
	managementCAPath := writeBundleFile(t, root, "management-ca.crt", managementCA)
	argoCAPath := writeBundleFile(t, root, "argo-ca.crt", argoCA)

	var runtime RuntimeBindingMaterial
	runtimeRaw, err := os.ReadFile(packageConfig.RuntimeBindingMaterialPath)
	if err != nil || jsonstrict.Decode(runtimeRaw, &runtime) != nil {
		t.Fatal("read aggregate runtime fixture")
	}
	workloadCA, err := base64.StdEncoding.DecodeString(runtime.Target.WorkloadAPICAData)
	if err != nil {
		t.Fatal(err)
	}
	workloadCAPath := writeBundleFile(t, root, "workload-ca.crt", workloadCA)
	packaged, err := BuildAggregateEvidenceStagePackage(packageConfig)
	if err != nil {
		t.Fatal(err)
	}

	subjects := []string{
		"system:serviceaccount:openkubes-execution-system:ok147-ledger-writer",
		"system:serviceaccount:openkubes-execution-system:ok147-aggregate-management-observer",
		"system:serviceaccount:openkubes-execution-system:ok147-aggregate-workload-observer",
		"system:serviceaccount:openkubes-execution-system:ok147-aggregate-argo-observer",
	}
	tokens := [][]byte{
		stageCredentialJWT(t, issuer, subjects[0], audiences, issuedAt, expiresAt, 'b'),
		stageCredentialJWT(t, issuer, subjects[1], audiences, issuedAt, expiresAt, 'c'),
		stageCredentialJWT(t, issuer, subjects[2], audiences, issuedAt, expiresAt, 'd'),
		stageCredentialJWT(t, issuer, subjects[3], audiences, issuedAt, expiresAt, 'e'),
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
	return AggregateEvidenceStageCredentialPackageConfig{
		Package: packaged, MaterializationTime: now,
		Ledger:             source("ok-mgmt", tokenPaths[0], subjects[0], "1", managementCAPath, tokens[0], managementCA),
		ManagementObserver: source("ok-mgmt", tokenPaths[1], subjects[1], "2", managementCAPath, tokens[1], managementCA),
		WorkloadObserver:   source(packaged.workloadAuthority, tokenPaths[2], subjects[2], "3", workloadCAPath, tokens[2], workloadCA),
		ArgoObserver:       source("ok-shared", tokenPaths[3], subjects[3], "4", argoCAPath, tokens[3], argoCA),
	}, tokens
}
