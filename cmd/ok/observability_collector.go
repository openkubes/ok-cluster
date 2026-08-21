package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

var serveBoundedObservabilityCollector = func(ctx context.Context, address string, handler http.Handler, certRaw, keyRaw []byte) error {
	return serveStageAuthorityTLS(ctx, address, handler, certRaw, keyRaw)
}

type observabilityCollectorActivationRunner interface {
	Receipt() (runner.ObservabilityIndependentEvidenceCollectorServerReceipt, error)
	Serve(context.Context, runner.ObservabilityCollectorServeFunc) error
}

var openObservabilityCollectorActivation = func(path string) (observabilityCollectorActivationRunner, error) {
	return runner.OpenObservabilityCollectorActivation(path, runner.ObservabilityCollectorActivationRuntime{Clock: time.Now})
}

func runEvidenceObservabilityServe(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok evidence observability serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	webhookTokenFile := flags.String("webhook-token-file", "", "private Alertmanager webhook bearer token")
	queryTokenFile := flags.String("query-token-file", "", "private evidence query bearer token")
	stateDirectory := flags.String("state-directory", "", "private create-only alert delivery state")
	workloadEndpoint := flags.String("workload-endpoint", "", "exact disposable workload Kubernetes API endpoint")
	workloadTokenFile := flags.String("workload-token-file", "", "private read-only workload bearer token")
	workloadCAFile := flags.String("workload-ca-file", "", "pinned workload Kubernetes API CA")
	workloadCADigest := flags.String("workload-ca-digest", "", "expected workload CA SHA-256 identity")
	targetClusterUID := flags.String("target-cluster-uid", "", "exact runtime CAPI Cluster UID")
	maximumRecordAge := flags.Duration("maximum-record-age", 0, "delivery freshness between one and thirty minutes")
	listenAddress := flags.String("listen", "", "literal IP and port to serve")
	tlsCertPath := flags.String("tls-cert", "", "TLS server certificate")
	tlsKeyPath := flags.String("tls-key", "", "private TLS server key")
	activationPath := flags.String("activation", "", "canonical private collector activation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if *activationPath != "" {
		for _, input := range []string{
			*webhookTokenFile, *queryTokenFile, *stateDirectory, *workloadEndpoint, *workloadTokenFile,
			*workloadCAFile, *workloadCADigest, *targetClusterUID, *listenAddress, *tlsCertPath, *tlsKeyPath,
		} {
			if input != "" {
				return errors.New("collector activation cannot be combined with individual serving flags")
			}
		}
		if *maximumRecordAge != 0 {
			return errors.New("collector activation cannot be combined with individual serving flags")
		}
		execution, err := openObservabilityCollectorActivation(*activationPath)
		if err != nil {
			return err
		}
		receipt, err := execution.Receipt()
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(receipt); err != nil {
			return err
		}
		return execution.Serve(ctx, serveBoundedObservabilityCollector)
	}
	for _, input := range []string{
		*webhookTokenFile, *queryTokenFile, *stateDirectory, *workloadEndpoint, *workloadTokenFile,
		*workloadCAFile, *workloadCADigest, *targetClusterUID, *listenAddress, *tlsCertPath, *tlsKeyPath,
	} {
		if input == "" {
			return errors.New("all bounded observability collector inputs are required")
		}
	}
	if err := validateAuthorityListenAddress(*listenAddress); err != nil {
		return err
	}
	certRaw, err := readBoundedLocalFile(*tlsCertPath, 128*1024)
	if err != nil {
		return errors.New("read observability collector TLS certificate")
	}
	keyRaw, err := readPrivateAuthorityFile(*tlsKeyPath, 128*1024)
	if err != nil {
		return errors.New("observability collector TLS key is invalid")
	}
	profile, err := runner.StandardObservabilityCapabilityCheckProfile("ok-observability")
	if err != nil {
		return err
	}
	autonomy, err := runner.OpenKubernetesObservabilityAutonomyObserver(runner.KubernetesObservabilityAutonomyObserverConfig{
		Endpoint: *workloadEndpoint, TokenFile: *workloadTokenFile, CAFile: *workloadCAFile,
		CABundleDigest: *workloadCADigest, TargetClusterUID: *targetClusterUID, Profile: profile,
	})
	if err != nil {
		return err
	}
	collector, err := runner.OpenObservabilityIndependentEvidenceCollectorServer(runner.ObservabilityIndependentEvidenceCollectorServerConfig{
		WebhookTokenFile: *webhookTokenFile, QueryTokenFile: *queryTokenFile, StateDirectory: *stateDirectory,
		ReceiverName: "ok147-independent-evidence", Profile: profile, MaximumRecordAge: *maximumRecordAge,
		Clock: time.Now, AutonomyObserver: autonomy,
	})
	if err != nil {
		return err
	}
	receipt, err := collector.Receipt()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		return err
	}
	return serveBoundedObservabilityCollector(ctx, *listenAddress, collector, certRaw, keyRaw)
}
