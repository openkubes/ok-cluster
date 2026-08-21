package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/openkubes/ok-cluster/internal/runner"
)

var materializeObservabilityCollectorRuntimePackage = func(config runner.ObservabilityCollectorRuntimePackageConfig) ([]byte, runner.ObservabilityCollectorRuntimePackageReceipt, error) {
	packaged, err := runner.BuildObservabilityCollectorRuntimePackage(config)
	if err != nil {
		return nil, runner.ObservabilityCollectorRuntimePackageReceipt{}, err
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		return nil, runner.ObservabilityCollectorRuntimePackageReceipt{}, err
	}
	receipt, err := packaged.Receipt()
	return raw, receipt, err
}

var materializeObservabilityCollectorActivation = runner.MaterializeObservabilityCollectorActivation

func runClusterStageEvidenceObservabilityCollectorPackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability collector package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resumeFlags := addStageResumeFlags(flags)
	manifestPath := flags.String("manifest", "", "private full-run execution manifest")
	expectedManifestDigest := flags.String("expected-manifest-digest", "", "exact full-run manifest digest")
	manifestReceipt := flags.String("manifest-receipt", "", "stored verified full-run manifest receipt")
	expectedManifestReceiptDigest := flags.String("expected-manifest-receipt-digest", "", "exact stored manifest-receipt digest")
	runtimeMaterial := flags.String("runtime-binding-material", "", "private runtime-binding material")
	runtimeReceipt := flags.String("runtime-binding-receipt", "", "verified runtime-binding receipt")
	activationSecret := flags.String("activation-secret", "", "immutable collector activation Secret name")
	materializationTime := flags.String("materialization-time", "", "exact RFC3339 materialization time")
	observerAuthority := flags.String("observer-authority", "", "runtime CAPI Cluster UID digest")
	observerToken := flags.String("observer-token-file", "", "short-lived autonomy-observer token")
	observerTokenDigest := flags.String("observer-token-digest", "", "exact autonomy-observer token digest")
	observerCA := flags.String("observer-ca-file", "", "pinned workload API CA")
	observerCADigest := flags.String("observer-ca-digest", "", "exact workload API CA digest")
	observerEvidence := flags.String("observer-tokenrequest-evidence-digest", "", "redacted TokenRequest evidence digest")
	observerIssuer := flags.String("observer-issuer", "", "expected workload token issuer")
	observerSubject := flags.String("observer-subject", "", "exact autonomy-observer subject")
	observerAudience := flags.String("observer-audience", "", "exact workload token audience")
	observerIssuedAt := flags.String("observer-issued-at", "", "exact RFC3339 token issue time")
	observerExpiresAt := flags.String("observer-expires-at", "", "exact RFC3339 token expiry")
	webhookToken := flags.String("webhook-token-file", "", "distinct private webhook authority")
	queryToken := flags.String("query-token-file", "", "distinct private query authority")
	publicEndpoint := flags.String("public-endpoint", "", "literal HTTPS collector endpoint")
	listenAddress := flags.String("listen", "", "literal collector listen IP and port")
	tlsCertificate := flags.String("tls-cert", "", "collector TLS certificate")
	tlsPrivateKey := flags.String("tls-key", "", "private collector TLS key")
	maximumRecordAge := flags.Duration("maximum-record-age", 0, "delivery freshness from one through thirty minutes")
	jobTemplate := flags.String("job-template", "", "bounded collector Service/NetworkPolicy/Job template")
	jobTemplateDigest := flags.String("job-template-digest", "", "exact collector runtime template digest")
	runID := flags.String("run-id", "", "bounded collector Job and Service identity")
	imageDigest := flags.String("image", "", "immutable runner image digest")
	workloadAPICIDR := flags.String("workload-api-cidr", "", "single-address workload API CIDR")
	alertSourceCIDR := flags.String("alert-source-cidr", "", "bounded workload alert-source CIDR")
	output := flags.String("output", "", "new private 0600 collector activation package")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for _, input := range []struct{ name, value string }{
		{"--manifest", *manifestPath}, {"--manifest-receipt", *manifestReceipt},
		{"--runtime-binding-material", *runtimeMaterial}, {"--runtime-binding-receipt", *runtimeReceipt},
		{"--activation-secret", *activationSecret}, {"--materialization-time", *materializationTime},
		{"--observer-authority", *observerAuthority}, {"--observer-token-file", *observerToken},
		{"--observer-ca-file", *observerCA}, {"--observer-issuer", *observerIssuer},
		{"--observer-subject", *observerSubject}, {"--observer-audience", *observerAudience},
		{"--observer-issued-at", *observerIssuedAt}, {"--observer-expires-at", *observerExpiresAt},
		{"--webhook-token-file", *webhookToken}, {"--query-token-file", *queryToken},
		{"--public-endpoint", *publicEndpoint}, {"--listen", *listenAddress},
		{"--tls-cert", *tlsCertificate}, {"--tls-key", *tlsPrivateKey},
		{"--job-template", *jobTemplate}, {"--run-id", *runID}, {"--image", *imageDigest},
		{"--workload-api-cidr", *workloadAPICIDR}, {"--alert-source-cidr", *alertSourceCIDR}, {"--output", *output},
	} {
		if input.value == "" {
			return fmt.Errorf("%s is required", input.name)
		}
	}
	for _, value := range []string{
		*expectedManifestDigest, *expectedManifestReceiptDigest, *observerAuthority, *observerTokenDigest,
		*observerCADigest, *observerEvidence, *jobTemplateDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			return errors.New("collector activation digests must be lowercase SHA-256 identities")
		}
	}
	materializedAt, materializedErr := time.Parse(time.RFC3339, *materializationTime)
	issuedAt, issuedErr := time.Parse(time.RFC3339, *observerIssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339, *observerExpiresAt)
	if materializedErr != nil || issuedErr != nil || expiresErr != nil ||
		*materializationTime != materializedAt.UTC().Format(time.RFC3339) ||
		*observerIssuedAt != issuedAt.UTC().Format(time.RFC3339) ||
		*observerExpiresAt != expiresAt.UTC().Format(time.RFC3339) {
		return errors.New("collector activation times must be canonical UTC RFC3339")
	}
	resume, err := resumeFlags.config()
	if err != nil {
		return err
	}
	activation := runner.ObservabilityCollectorActivationPackageConfig{
		ManifestPath: *manifestPath, ExpectedManifestDigest: *expectedManifestDigest,
		ManifestReceiptPath: *manifestReceipt, ExpectedReceiptDigest: *expectedManifestReceiptDigest,
		RuntimeBinding: runner.RuntimeBindingMaterialFileConfig{
			Bundle: resume, MaterialPath: *runtimeMaterial, ReceiptPath: *runtimeReceipt,
		},
		ActivationSecret: *activationSecret, MaterializationTime: materializedAt,
		ObserverCredential: runner.SubmissionStageCredentialSource{
			AuthorityIdentity: *observerAuthority, TokenFile: *observerToken, TokenDigest: *observerTokenDigest,
			CAFile: *observerCA, CABundleDigest: *observerCADigest, TokenRequestEvidenceDigest: *observerEvidence,
			ExpectedIssuer: *observerIssuer, ExpectedSubject: *observerSubject, ExpectedAudiences: []string{*observerAudience},
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		},
		WebhookTokenPath: *webhookToken, QueryTokenPath: *queryToken,
		PublicEndpoint: *publicEndpoint, ListenAddress: *listenAddress,
		TLSCertificatePath: *tlsCertificate, TLSPrivateKeyPath: *tlsPrivateKey,
		MaximumRecordAge: *maximumRecordAge,
	}
	templateRaw, err := readBoundedLocalFile(*jobTemplate, 1024*1024)
	if err != nil {
		return errors.New("read observability collector runtime template")
	}
	raw, receipt, err := materializeObservabilityCollectorRuntimePackage(runner.ObservabilityCollectorRuntimePackageConfig{
		Activation: activation, JobTemplate: templateRaw, JobTemplateDigest: *jobTemplateDigest,
		RunID: *runID, ImageDigest: *imageDigest, WorkloadAPICIDR: *workloadAPICIDR, AlertSourceCIDR: *alertSourceCIDR,
	})
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return errors.New("write private observability collector activation package")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runClusterStageEvidenceObservabilityCollectorMaterialize(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok cluster stage evidence observability collector materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "projected immutable collector activation Secret directory")
	destination := flags.String("destination", "", "fixed private collector activation directory")
	state := flags.String("state-directory", "", "fixed private collector delivery-state directory")
	activationDigest := flags.String("expected-activation-digest", "", "exact canonical collector activation digest")
	manifestDigest := flags.String("expected-manifest-digest", "", "exact full-run manifest digest")
	runtimeBindingDigest := flags.String("expected-runtime-binding-digest", "", "exact private runtime-binding digest")
	publicEndpointDigest := flags.String("expected-public-endpoint-digest", "", "exact redacted public-endpoint digest")
	materialize := flags.Bool("materialize", false, "create the private collector runtime")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !*materialize || *source == "" || *destination == "" || *state == "" {
		return errors.New("observability collector materialization input is incomplete")
	}
	for _, value := range []string{*activationDigest, *manifestDigest, *runtimeBindingDigest, *publicEndpointDigest} {
		if !sha256DigestPattern.MatchString(value) {
			return errors.New("collector materialization digests must be lowercase SHA-256 identities")
		}
	}
	receipt, err := materializeObservabilityCollectorActivation(runner.ObservabilityCollectorActivationMaterializationConfig{
		SourceDirectory: *source, DestinationDirectory: *destination, StateDirectory: *state,
		ExpectedActivationDigest: *activationDigest, ExpectedManifestDigest: *manifestDigest,
		ExpectedRuntimeBinding: *runtimeBindingDigest, ExpectedPublicEndpoint: *publicEndpointDigest,
	})
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(receipt); encodeErr != nil {
		return encodeErr
	}
	return err
}
