package runner

import (
	"context"
	"errors"
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
	installerToken := writeBundleFile(t, t.TempDir(), "installer-token", []byte("distinct-installer-token"))
	activator, err := NewKubernetesObservabilityCollectorPostPrefix(ObservabilityCollectorPostPrefixConfig{
		Package: config, Installer: KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.147:6443", TokenFile: installerToken,
			CAFile: config.Activation.ObserverCredential.CAFile, CABundleDigest: config.Activation.ObserverCredential.CABundleDigest,
		}, Clock: func() time.Time { return config.Activation.MaterializationTime },
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
	activator.open = func(received ObservabilityCollectorRuntimeLauncherConfig, value VerifiedObservabilityCollectorRuntimePackage) (observabilityCollectorRuntimeLauncher, error) {
		openCalls++
		if received.ExpectedPackageDigest != packageReceipt.PackageDigest || received.Authority.AuthorityIdentity != target {
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
		buildCalls != 1 || openCalls != 1 || launcher.calls != 1 {
		t.Fatalf("unexpected post-prefix receipt: %#v calls=%d/%d/%d", receipt, buildCalls, openCalls, launcher.calls)
	}
	if err := activator.ActivateFullRunPostPrefix(context.Background(), prefix); err == nil || buildCalls != 1 || launcher.calls != 1 {
		t.Fatal("post-prefix activation was replayed")
	}
}

func TestObservabilityCollectorPostPrefixStopsBeforeBuildOnForeignRuntime(t *testing.T) {
	config := observabilityCollectorRuntimePackageFixture(t)
	installerToken := writeBundleFile(t, t.TempDir(), "installer-token", []byte("distinct-installer-token"))
	activator, err := NewKubernetesObservabilityCollectorPostPrefix(ObservabilityCollectorPostPrefixConfig{
		Package: config, Installer: KubernetesAuthorityConfig{
			Endpoint: "https://192.0.2.147:6443", TokenFile: installerToken,
			CAFile: config.Activation.ObserverCredential.CAFile, CABundleDigest: config.Activation.ObserverCredential.CABundleDigest,
		}, Clock: func() time.Time { return config.Activation.MaterializationTime },
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
