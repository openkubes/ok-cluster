package runner

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

type fakeCollectorRuntimeLauncher struct {
	receipt ObservabilityCollectorRuntimeLaunchReceipt
	err     error
	calls   int
}

func (launcher *fakeCollectorRuntimeLauncher) Launch(context.Context) (ObservabilityCollectorRuntimeLaunchReceipt, error) {
	launcher.calls++
	return launcher.receipt, launcher.err
}

func TestObservabilityCollectorPostPrefixBuildsAndLaunchesFreshBindingOnce(t *testing.T) {
	config := observabilityCollectorRuntimePackageFixture(t)
	packaged, err := BuildObservabilityCollectorRuntimePackage(config)
	if err != nil {
		t.Fatal(err)
	}
	packageReceipt, _ := packaged.Receipt()
	target := digest.SHA256([]byte("collector-target-cluster-uid"))
	activator, err := NewKubernetesObservabilityCollectorPostPrefix(ObservabilityCollectorPostPrefixConfig{
		Package: config, Clock: func() time.Time { return config.Activation.MaterializationTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	buildCalls, openCalls := 0, 0
	launcher := &fakeCollectorRuntimeLauncher{receipt: ObservabilityCollectorRuntimeLaunchReceipt{
		Format: ObservabilityCollectorRuntimeLaunchReceiptFormat, State: "ACTIVATED",
		Results: make([]SubmissionStageInstalledObject, 4),
	}}
	activator.build = func(received ObservabilityCollectorRuntimePackageConfig) (VerifiedObservabilityCollectorRuntimePackage, error) {
		buildCalls++
		if len(received.Activation.RuntimeBinding.Bundle.Receipts) != 6 || received.Activation.ObserverCredential.AuthorityIdentity != target {
			t.Fatalf("fresh prefix was not bound into package: %#v", received.Activation)
		}
		return packaged, nil
	}
	activator.resolve = func(WorkloadAuthorityFileResolverConfig) (WorkloadAuthorityBinding, KubernetesAuthorityConfig, error) {
		return WorkloadAuthorityBinding{TargetClusterUID: "collector-target-cluster-uid"}, KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.147:6443", CABundleDigest: config.Activation.ObserverCredential.CABundleDigest,
		}, nil
	}
	credential := collectorInstallerCredentialFixture(t, target, config.Activation.ObserverCredential.CABundleDigest, config.Activation.MaterializationTime)
	activator.issue = func(_ context.Context, received ObservabilityCollectorInstallerCredentialConfig) (VerifiedObservabilityCollectorInstallerCredential, error) {
		if received.ExpectedTargetDigest != target || received.Clock == nil {
			t.Fatalf("credential binding differs: %#v", received)
		}
		return credential, nil
	}
	activator.open = func(received submissionStageInstallerClientConfig, value VerifiedObservabilityCollectorRuntimePackage) (observabilityCollectorRuntimeLauncher, error) {
		openCalls++
		if received.AuthorityIdentity != target || received.BearerToken != string(credential.token) || received.Client == nil {
			t.Fatalf("launcher identity differs: %#v", received)
		}
		return launcher, nil
	}
	prefix := FullRunPostPrefixActivation{
		ReceiptPrefix: make([]StageReceiptSource, 7), TargetIdentity: target,
		Workload: WorkloadAuthorityFileResolverConfig{CAFile: config.Activation.ObserverCredential.CAFile},
	}
	if err := activator.ActivateFullRunPostPrefix(context.Background(), prefix); err != nil {
		t.Fatal(err)
	}
	receipt := activator.Receipt()
	if receipt.State != "ACTIVATED" || receipt.PackageDigest != packageReceipt.PackageDigest || receipt.CreatedObjects != 4 ||
		!stageReceiptPrefixDigestPattern.MatchString(receipt.CredentialReceiptDigest) || buildCalls != 1 || openCalls != 1 || launcher.calls != 1 {
		t.Fatalf("unexpected post-prefix receipt: %#v calls=%d/%d/%d", receipt, buildCalls, openCalls, launcher.calls)
	}
	if err := activator.ActivateFullRunPostPrefix(context.Background(), prefix); err == nil || buildCalls != 1 || launcher.calls != 1 {
		t.Fatal("post-prefix activation was replayed")
	}
}

func TestObservabilityCollectorPostPrefixStopsBeforeBuildOnForeignRuntime(t *testing.T) {
	config := observabilityCollectorRuntimePackageFixture(t)
	activator, err := NewKubernetesObservabilityCollectorPostPrefix(ObservabilityCollectorPostPrefixConfig{
		Package: config, Clock: func() time.Time { return config.Activation.MaterializationTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	buildCalls := 0
	activator.build = func(ObservabilityCollectorRuntimePackageConfig) (VerifiedObservabilityCollectorRuntimePackage, error) {
		buildCalls++
		return VerifiedObservabilityCollectorRuntimePackage{}, errors.New("must not build")
	}
	activator.resolve = func(WorkloadAuthorityFileResolverConfig) (WorkloadAuthorityBinding, KubernetesAuthorityConfig, error) {
		return WorkloadAuthorityBinding{TargetClusterUID: "foreign-target"}, KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.147:6443", CABundleDigest: config.Activation.ObserverCredential.CABundleDigest,
		}, nil
	}
	err = activator.ActivateFullRunPostPrefix(context.Background(), FullRunPostPrefixActivation{
		ReceiptPrefix: make([]StageReceiptSource, 7), TargetIdentity: digest.SHA256([]byte("collector-target-cluster-uid")),
		Workload: WorkloadAuthorityFileResolverConfig{CAFile: config.Activation.ObserverCredential.CAFile},
	})
	if err == nil || buildCalls != 0 || activator.Receipt().State != "STOPPED" {
		t.Fatalf("foreign runtime reached package build: calls=%d receipt=%#v err=%v", buildCalls, activator.Receipt(), err)
	}
}

func collectorInstallerCredentialFixture(t *testing.T, target, caDigest string, now time.Time) VerifiedObservabilityCollectorInstallerCredential {
	t.Helper()
	material := VerifiedObservabilityCollectorInstallerCredential{
		token: bytes.Repeat([]byte("t"), 100), endpoint: "http://127.0.0.1:12345", targetIdentity: target,
		caBundleDigest: caDigest, client: &http.Client{}, expiresAt: now.Add(observabilityCollectorInstallerLifetime), verified: true,
		receipt: ObservabilityCollectorInstallerCredentialReceipt{
			Format: ObservabilityCollectorInstallerCredentialReceiptFormat, State: "ISSUED",
			TargetIdentityDigest:         target,
			ServiceAccountIdentityDigest: digest.SHA256([]byte("system:serviceaccount:" + observabilityCollectorInstallerNamespace + ":" + observabilityCollectorInstallerServiceAccount)),
			RequestDigest:                digest.SHA256([]byte("collector-token-request")), CABundleDigest: caDigest,
			AudienceMode: "server-default", IssuedAt: now.UTC().Format(time.RFC3339),
			ExpiresAt:       now.Add(observabilityCollectorInstallerLifetime).UTC().Format(time.RFC3339),
			LifetimeSeconds: int64(observabilityCollectorInstallerLifetime / time.Second), CredentialBytesInReceipt: false, MutationState: "ATTEMPTED",
		},
	}
	var err error
	material.privateDigest, err = observabilityCollectorInstallerPrivateDigest(material)
	if err != nil {
		t.Fatal(err)
	}
	return material
}
