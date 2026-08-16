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

func TestBuildSubmissionStageCredentialPackageBindsTwoPrivateImmutableSecrets(t *testing.T) {
	config, ledgerToken, authorityToken := submissionStageCredentialConfig(t)
	packaged, err := BuildSubmissionStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	stageReceipt, err := config.Package.Receipt()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != SubmissionStageCredentialPackageFormat || receipt.State != "VERIFIED" || receipt.StageID != "provider-prerequisites" || receipt.StagePackageDigest != stageReceipt.PackageDigest || receipt.MaterializedAt != config.MaterializationTime.Format(time.RFC3339) || !stageReceiptPrefixDigestPattern.MatchString(receipt.PackageDigest) || receipt.MutationAllowed || len(receipt.Credentials) != 2 {
		t.Fatalf("unexpected credential receipt: %#v", receipt)
	}
	want := []struct {
		role      string
		authority string
		name      string
		token     []byte
	}{
		{role: "ledger", authority: "ok-mgmt", name: config.Package.ledgerCredential, token: ledgerToken},
		{role: "authority", authority: "ok-infra", name: config.Package.selectedCredential, token: authorityToken},
	}
	for index, expected := range want {
		object := packaged.objects[index]
		objectReceipt := receipt.Credentials[index]
		if object.role != expected.role || object.authority != expected.authority || object.name != expected.name || digest.SHA256(object.raw) != objectReceipt.ObjectDigest {
			t.Fatalf("private credential object %d differs: %#v %#v", index, object, objectReceipt)
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
		if secret["apiVersion"] != "v1" || secret["kind"] != "Secret" || secret["immutable"] != true || secret["type"] != "Opaque" || metadata["namespace"] != submissionStageInputNamespace || metadata["name"] != expected.name || labels["openkubes.io/stage-id"] != "provider-prerequisites" || labels["openkubes.io/credential-role"] != expected.role || annotations["openkubes.io/authority-identity"] != expected.authority || !bytes.Equal(decodedToken, expected.token) || data["ca.crt"] == "" || len(data) != 2 {
			t.Fatalf("credential Secret %d differs from exact binding: %#v", index, secret)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{string(ledgerToken), string(authorityToken), config.Ledger.TokenFile, config.Ledger.CAFile, config.Ledger.ExpectedSubject, config.SelectedAuthority.ExpectedSubject} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatalf("credential receipt exposed private source %q", forbidden)
		}
	}

	receipt.Credentials[0].Audiences[0] = "changed"
	again, err := packaged.Receipt()
	if err != nil || again.Credentials[0].Audiences[0] == "changed" {
		t.Fatal("caller mutated retained credential receipt")
	}
}

func TestBuildSubmissionStageCredentialPackageRejectsUnsafeSources(t *testing.T) {
	for name, mutate := range map[string]func(*SubmissionStageCredentialPackageConfig){
		"foreign authority": func(config *SubmissionStageCredentialPackageConfig) {
			config.SelectedAuthority.AuthorityIdentity = "ok-mgmt"
		},
		"wrong token digest": func(config *SubmissionStageCredentialPackageConfig) {
			config.Ledger.TokenDigest = prefixSHA("f")
		},
		"wrong CA digest": func(config *SubmissionStageCredentialPackageConfig) {
			config.Ledger.CABundleDigest = prefixSHA("e")
		},
		"wrong audience": func(config *SubmissionStageCredentialPackageConfig) {
			config.Ledger.ExpectedAudiences = []string{"foreign-audience"}
		},
		"wrong subject": func(config *SubmissionStageCredentialPackageConfig) {
			config.Ledger.ExpectedSubject = "system:serviceaccount:default:foreign"
		},
		"expired": func(config *SubmissionStageCredentialPackageConfig) {
			config.MaterializationTime = config.Ledger.ExpiresAt.Add(-time.Minute)
		},
		"lifetime too long": func(config *SubmissionStageCredentialPackageConfig) {
			config.Ledger.ExpiresAt = config.Ledger.IssuedAt.Add(2 * time.Hour)
		},
		"missing TokenRequest evidence": func(config *SubmissionStageCredentialPackageConfig) {
			config.Ledger.TokenRequestEvidenceDigest = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _, _ := submissionStageCredentialConfig(t)
			mutate(&config)
			_, err := BuildSubmissionStageCredentialPackage(config)
			if err == nil || strings.Contains(err.Error(), config.Ledger.TokenFile) || strings.Contains(err.Error(), config.Ledger.CAFile) || strings.Contains(err.Error(), config.SelectedAuthority.TokenFile) || strings.Contains(err.Error(), config.SelectedAuthority.CAFile) {
				t.Fatalf("unsafe credential source accepted: %v", err)
			}
		})
	}
}

func TestBuildSubmissionStageCredentialPackageSelectsManagementForLifecycleStage(t *testing.T) {
	config, _, _ := submissionStageCredentialConfig(t)
	fixture := submissionBundleFixture(t, true, "")
	stagePackage, err := BuildSubmissionStagePackage(submissionStagePackageConfig(t, fixture, "cluster-lifecycle"))
	if err != nil {
		t.Fatal(err)
	}
	config.Package = stagePackage
	config.SelectedAuthority.AuthorityIdentity = "ok-mgmt"
	packaged, err := BuildSubmissionStageCredentialPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := packaged.Receipt()
	if err != nil || receipt.StageID != "cluster-lifecycle" || receipt.Credentials[0].Authority != "ok-mgmt" || receipt.Credentials[1].Authority != "ok-mgmt" {
		t.Fatalf("lifecycle credential authorities differ: %#v %v", receipt, err)
	}
}

func TestBuildSubmissionStageCredentialPackageRejectsSharedTokenAndSymlink(t *testing.T) {
	config, _, _ := submissionStageCredentialConfig(t)
	config.SelectedAuthority.TokenFile = config.Ledger.TokenFile
	config.SelectedAuthority.TokenDigest = config.Ledger.TokenDigest
	config.SelectedAuthority.ExpectedIssuer = config.Ledger.ExpectedIssuer
	config.SelectedAuthority.ExpectedSubject = config.Ledger.ExpectedSubject
	config.SelectedAuthority.ExpectedAudiences = append([]string(nil), config.Ledger.ExpectedAudiences...)
	config.SelectedAuthority.IssuedAt = config.Ledger.IssuedAt
	config.SelectedAuthority.ExpiresAt = config.Ledger.ExpiresAt
	if _, err := BuildSubmissionStageCredentialPackage(config); err == nil {
		t.Fatal("shared ledger/authority token was accepted")
	}

	config, _, _ = submissionStageCredentialConfig(t)
	symlink := filepath.Join(filepath.Dir(config.Ledger.TokenFile), "token-link")
	if err := os.Symlink(config.Ledger.TokenFile, symlink); err != nil {
		t.Fatal(err)
	}
	config.Ledger.TokenFile = symlink
	if _, err := BuildSubmissionStageCredentialPackage(config); err == nil || strings.Contains(err.Error(), symlink) {
		t.Fatalf("symlink accepted or source path exposed: %v", err)
	}
}

func TestBuildSubmissionStageCredentialPackageRejectsUnsignedJWT(t *testing.T) {
	config, _, _ := submissionStageCredentialConfig(t)
	token, err := os.ReadFile(config.Ledger.TokenFile)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(token), ".")
	header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	parts[0] = base64.RawURLEncoding.EncodeToString(header)
	unsafe := []byte(strings.Join(parts, "."))
	if err := os.WriteFile(config.Ledger.TokenFile, unsafe, 0o600); err != nil {
		t.Fatal(err)
	}
	config.Ledger.TokenDigest = digest.SHA256(unsafe)
	if _, err := BuildSubmissionStageCredentialPackage(config); err == nil {
		t.Fatal("unsigned JWT algorithm was accepted")
	}
}

func submissionStageCredentialConfig(t *testing.T) (SubmissionStageCredentialPackageConfig, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	issuedAt, expiresAt := now.Add(-time.Minute), now.Add(30*time.Minute)
	audience := []string{"https://kubernetes.default.svc"}
	issuer := "https://kubernetes.default.svc.cluster.local"
	ledgerSubject := "system:serviceaccount:openkubes-execution-system:ok147-ledger-writer"
	authoritySubject := "system:serviceaccount:openkubes-execution-system:ok147-provider-writer"
	ledgerToken := stageCredentialJWT(t, issuer, ledgerSubject, audience, issuedAt, expiresAt, 'a')
	authorityToken := stageCredentialJWT(t, issuer, authoritySubject, audience, issuedAt, expiresAt, 'b')
	root := t.TempDir()
	ca := testCA(t)
	caPath := filepath.Join(root, "ca.crt")
	ledgerPath := filepath.Join(root, "ledger-token")
	authorityPath := filepath.Join(root, "authority-token")
	for path, raw := range map[string][]byte{caPath: ca, ledgerPath: ledgerToken, authorityPath: authorityToken} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixture := submissionBundleFixture(t, false, "")
	stagePackage, err := BuildSubmissionStagePackage(submissionStagePackageConfig(t, fixture, "provider-prerequisites"))
	if err != nil {
		t.Fatal(err)
	}
	source := func(authority, tokenPath, subject, evidence string, token []byte) SubmissionStageCredentialSource {
		return SubmissionStageCredentialSource{
			AuthorityIdentity: authority, TokenFile: tokenPath, TokenDigest: digest.SHA256(token),
			CAFile: caPath, CABundleDigest: digest.SHA256(ca), TokenRequestEvidenceDigest: prefixSHA(evidence),
			ExpectedIssuer: issuer, ExpectedSubject: subject, ExpectedAudiences: audience,
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		}
	}
	return SubmissionStageCredentialPackageConfig{
		Package: stagePackage, MaterializationTime: now,
		Ledger:            source("ok-mgmt", ledgerPath, ledgerSubject, "8", ledgerToken),
		SelectedAuthority: source("ok-infra", authorityPath, authoritySubject, "9", authorityToken),
	}, ledgerToken, authorityToken
}

func stageCredentialJWT(t *testing.T, issuer, subject string, audiences []string, issuedAt, expiresAt time.Time, signatureByte byte) []byte {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "ok147-test-key"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": issuer, "sub": subject, "aud": audiences,
		"iat": issuedAt.Unix(), "nbf": issuedAt.Unix(), "exp": expiresAt.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := bytes.Repeat([]byte{signatureByte}, 64)
	return []byte(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + base64.RawURLEncoding.EncodeToString(signature))
}
