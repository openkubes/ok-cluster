package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/digest"
)

func TestPlanFullRunExecutionActivationInstallationBindsExactOrder(t *testing.T) {
	packaged := fullRunActivationLauncherPackage(t)
	plan, err := PlanFullRunExecutionActivationInstallation(packaged)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Format != FullRunExecutionActivationInstallationPlanFormat || plan.State != "VERIFIED" ||
		plan.RunID != "ok147-full-run-01" || plan.Authority != "ok-mgmt" || plan.MutationAllowed || len(plan.Creates) != 4 {
		t.Fatalf("unexpected full-run activation plan: %#v", plan)
	}
	for index, kind := range []string{"Secret", "Secret", "NetworkPolicy", "Job"} {
		create := plan.Creates[index]
		if create.Order != index+1 || create.Kind != kind || create.Namespace != submissionStageInputNamespace ||
			create.PreflightMethod != http.MethodGet || create.CreateMethod != http.MethodPost || create.ObjectPath == "" ||
			create.CollectionPath == "" || !stageReceiptPrefixDigestPattern.MatchString(create.ObjectDigest) {
			t.Fatalf("create %d differs: %#v", index, create)
		}
	}
	public, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"bearer", "token", "certificate", "/private/"} {
		if strings.Contains(strings.ToLower(string(public)), forbidden) {
			t.Fatalf("installation plan exposed %q", forbidden)
		}
	}
}

func TestPlanFullRunExecutionActivationInstallationFailsClosed(t *testing.T) {
	packaged := fullRunActivationLauncherPackage(t)
	for name, mutate := range map[string]func(*VerifiedFullRunExecutionActivationPackage){
		"raw":       func(value *VerifiedFullRunExecutionActivationPackage) { value.raw[0] ^= 0xff },
		"authority": func(value *VerifiedFullRunExecutionActivationPackage) { value.managementAuthority = "ok-infra" },
		"inventory": func(value *VerifiedFullRunExecutionActivationPackage) { value.receipt.ObjectKinds[1] = "ConfigMap" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := packaged
			candidate.raw = append([]byte(nil), packaged.raw...)
			candidate.receipt.ObjectKinds = append([]string(nil), packaged.receipt.ObjectKinds...)
			mutate(&candidate)
			if _, err := PlanFullRunExecutionActivationInstallation(candidate); err == nil {
				t.Fatal("changed full-run package produced an installation plan")
			}
		})
	}
}

func TestFullRunExecutionActivationLauncherPreflightsThenCreates(t *testing.T) {
	packaged := fullRunActivationLauncherPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	launcher := newFullRunActivationLauncher(t, packaged, api.client())
	receipt, err := launcher.Launch(context.Background())
	if err != nil || receipt.State != "ACTIVATED" || receipt.MutationState != "ATTEMPTED" || len(receipt.Results) != 4 {
		t.Fatalf("full-run activation failed: %#v %v", receipt, err)
	}
	plan, _ := PlanFullRunExecutionActivationInstallation(packaged)
	if receipt.Format != FullRunExecutionActivationLaunchReceiptFormat || receipt.PackageDigest != plan.PackageDigest ||
		receipt.PlanDigest != plan.PlanDigest || receipt.RunID != plan.RunID || receipt.Authority != "ok-mgmt" {
		t.Fatalf("activation receipt identity differs: %#v", receipt)
	}
	if len(api.requests) != 8 {
		t.Fatalf("requests=%d, want four GETs then four POSTs: %#v", len(api.requests), api.requests)
	}
	for index, create := range plan.Creates {
		preflight, submission := api.requests[index], api.requests[index+4]
		if preflight.method != http.MethodGet || preflight.path != create.ObjectPath || len(preflight.body) != 0 {
			t.Fatalf("preflight %d differs: %#v", index, preflight)
		}
		if submission.method != http.MethodPost || submission.path != create.CollectionPath || digest.SHA256(submission.body) != create.ObjectDigest {
			t.Fatalf("submission %d differs: %#v", index, submission)
		}
	}
	public, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte("short-lived-installer-token")) || bytes.Contains(public, []byte("created-stage-uid")) {
		t.Fatal("activation receipt disclosed credential or raw runtime identity")
	}
}

func TestFullRunExecutionActivationLauncherStopsZeroWriteOnExistingObject(t *testing.T) {
	packaged := fullRunActivationLauncherPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	plan, _ := PlanFullRunExecutionActivationInstallation(packaged)
	api.objects[plan.Creates[3].ObjectPath] = map[string]any{"kind": "Job"}
	launcher := newFullRunActivationLauncher(t, packaged, api.client())
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_ZERO_WRITE" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 || len(api.requests) != 4 {
		t.Fatalf("existing activation object did not stop zero-write: %#v requests=%d posts=%d err=%v", receipt, len(api.requests), api.posts, err)
	}
}

func TestFullRunExecutionActivationLauncherPreservesPartialAndCannotRetry(t *testing.T) {
	packaged := fullRunActivationLauncherPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	api.failPost = 3
	launcher := newFullRunActivationLauncher(t, packaged, api.client())
	receipt, err := launcher.Launch(context.Background())
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" ||
		len(receipt.Results) != 2 || receipt.Results[0].Kind != "Secret" || receipt.Results[1].Kind != "Secret" {
		t.Fatalf("partial activation prefix differs: %#v %v", receipt, err)
	}
	requestCount := len(api.requests)
	retry, retryErr := launcher.Launch(context.Background())
	if retryErr == nil || retry.State != "STOPPED_ZERO_WRITE" || retry.MutationState != "NOT_ATTEMPTED" || len(api.requests) != requestCount {
		t.Fatalf("single-use activation boundary failed: %#v requests=%d/%d err=%v", retry, len(api.requests), requestCount, retryErr)
	}
}

func TestOpenFullRunExecutionActivationLauncherRequiresExactPackageBeforeCredential(t *testing.T) {
	packaged := fullRunActivationLauncherPackage(t)
	if _, err := OpenKubernetesFullRunExecutionActivationLauncher(FullRunExecutionActivationLauncherConfig{
		Authority: KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.10:6443", AuthorityIdentity: "ok-mgmt",
			TokenFile: "/private/tmp/must-not-open-token", CAFile: "/private/tmp/must-not-open-ca", CABundleDigest: bundleSHA("a"),
		},
		ExpectedPackageDigest: bundleSHA("f"),
	}, packaged); err == nil || !strings.Contains(err.Error(), "expected identity") {
		t.Fatalf("foreign activation package identity reached credential opening: %v", err)
	}
}

func TestFullRunExecutionActivationLauncherRejectsForeignAuthorityAndUnboundedEndpoint(t *testing.T) {
	packaged := fullRunActivationLauncherPackage(t)
	api := newSubmissionStageInstallerAPI(t)
	for _, test := range []submissionStageInstallerClientConfig{
		{Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-infra", Client: api.client()},
		{Endpoint: "https://ok-mgmt.example:6443", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: api.client()},
		{Endpoint: "https://192.0.2.10:6443/path", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: api.client()},
	} {
		if _, err := newKubernetesFullRunExecutionActivationLauncher(test, packaged); err == nil {
			t.Fatalf("unsafe full-run launcher config accepted: %#v", test)
		}
	}
}

func fullRunActivationLauncherPackage(t *testing.T) VerifiedFullRunExecutionActivationPackage {
	t.Helper()
	config := fullRunExecutionActivationPackageFixture(t)
	packaged, err := BuildFullRunExecutionActivationPackage(config)
	if err != nil {
		t.Fatal(err)
	}
	return packaged
}

func newFullRunActivationLauncher(t *testing.T, packaged VerifiedFullRunExecutionActivationPackage, client *http.Client) *KubernetesFullRunExecutionActivationLauncher {
	t.Helper()
	launcher, err := newKubernetesFullRunExecutionActivationLauncher(submissionStageInstallerClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-installer-token", AuthorityIdentity: "ok-mgmt", Client: client,
	}, packaged)
	if err != nil {
		t.Fatal(err)
	}
	return launcher
}
