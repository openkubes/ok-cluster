package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/digest"
	"github.com/openkubes/ok-cluster/internal/stageauthority"
)

func TestAuthorityStageServeOpensBoundedRuntime(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := stageauthority.Policy{
		Format: stageauthority.PolicyFormat, PlanDigest: cliAuthorityDigest("1"),
		ContractIdentity: contract.Identity{Namespace: "disposable-ok147", Name: "disposable-ok147"},
		ContractRevision: cliAuthorityDigest("2"), EnablementRevision: cliAuthorityDigest("3"),
		PlatformRevision: cliAuthorityDigest("4"), ExecutionFixture: cliAuthorityDigest("5"),
		Stages: []stageauthority.StagePolicy{{
			StageID: "provider-prerequisites", StageOrder: 1, StageDigest: cliAuthorityDigest("6"),
			Operation: "CreateProviderPrerequisites", Authority: "infrastructure", Requires: []string{},
		}},
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := cliAuthorityWrite(t, root, "policy.json", policyRaw, 0o600)
	privatePath := cliAuthorityWrite(t, root, "authority.key", []byte(base64.StdEncoding.EncodeToString(privateKey)), 0o600)
	tokenPath := cliAuthorityWrite(t, root, "token", []byte("private-token-0123456789abcdefghijkl"), 0o600)
	certPath := cliAuthorityWrite(t, root, "tls.crt", []byte("certificate-placeholder"), 0o644)
	tlsKeyPath := cliAuthorityWrite(t, root, "tls.key", []byte("private-key-placeholder"), 0o600)

	original := serveBoundedStageAuthority
	defer func() { serveBoundedStageAuthority = original }()
	called := false
	serveBoundedStageAuthority = func(_ context.Context, address string, handler http.Handler, cert, key []byte) error {
		called = address == "127.0.0.1:8443" && handler != nil && string(cert) == "certificate-placeholder" && string(key) == "private-key-placeholder"
		return nil
	}
	stdout := &bytes.Buffer{}
	err = run([]string{
		"authority", "stage", "serve", "--policy", policyPath, "--expected-policy-digest", cliAuthoritySHA(policyRaw), "--private-key", privatePath,
		"--token-file", tokenPath, "--state-directory", state, "--listen", "127.0.0.1:8443",
		"--tls-cert", certPath, "--tls-key", tlsKeyPath, "--grant-valid-for", "10m",
	}, stdout, &bytes.Buffer{})
	if err != nil || !called {
		t.Fatalf("serve failed: %v called=%v", err, called)
	}
	var receipt stageauthority.Receipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil || receipt.State != "VERIFIED" || receipt.StageCount != 1 || receipt.MutationAllowed {
		t.Fatalf("unexpected receipt: %#v %v", receipt, err)
	}
}

func TestAuthorityStageServeRejectsUnsafeActivation(t *testing.T) {
	if err := run([]string{"authority", "stage", "serve"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing activation was accepted")
	}
	if err := validateAuthorityListenAddress("authority.example:8443"); err == nil {
		t.Fatal("hostname listener was accepted")
	}
}

func cliAuthorityWrite(t *testing.T, root, name string, raw []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func cliAuthorityDigest(value string) string { return "sha256:" + strings.Repeat(value, 64) }

func cliAuthoritySHA(raw []byte) string {
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		panic(err)
	}
	canonical, err := contract.JCS(generic)
	if err != nil {
		panic(err)
	}
	return digest.SHA256(canonical)
}
