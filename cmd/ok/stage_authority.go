package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/contract"
	"github.com/openkubes/ok-cluster/internal/stageauthority"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

var serveBoundedStageAuthority = serveStageAuthorityTLS

func runAuthorityStagePackage(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok authority stage package", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "exact bounded stage-authority policy")
	expectedPolicyDigest := flags.String("expected-policy-digest", "", "reviewed bounded policy SHA-256 identity")
	privateKeyPath := flags.String("private-key", "", "private base64 Ed25519 signing key")
	tokenFile := flags.String("token-file", "", "private bearer-token file")
	tlsCertPath := flags.String("tls-cert", "", "TLS server certificate")
	tlsKeyPath := flags.String("tls-key", "", "private TLS server key")
	templatePath := flags.String("template", "", "bounded runtime template")
	templateDigest := flags.String("template-digest", "", "expected runtime template SHA-256 identity")
	imageDigest := flags.String("image", "", "digest-pinned ok runner image")
	storageClass := flags.String("storage-class", "", "bounded DEV storage class")
	storageRequest := flags.String("storage-request", "", "bounded durable claim size")
	serviceIP := flags.String("service-ip", "", "exact private ClusterIP for the bounded authority Service")
	output := flags.String("output", "", "new private 0600 runtime package")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for _, input := range []string{
		*policyPath, *expectedPolicyDigest, *privateKeyPath, *tokenFile, *tlsCertPath, *tlsKeyPath,
		*templatePath, *templateDigest, *imageDigest, *storageClass, *storageRequest, *serviceIP, *output,
	} {
		if input == "" {
			return errors.New("all bounded stage-authority package inputs are required")
		}
	}
	template, err := readBoundedLocalFile(*templatePath, 512*1024)
	if err != nil {
		return errors.New("read bounded stage-authority runtime template")
	}
	packaged, err := stageauthority.BuildRuntimePackage(stageauthority.RuntimePackageConfig{
		PolicyPath: *policyPath, ExpectedPolicyDigest: *expectedPolicyDigest, PrivateKeyPath: *privateKeyPath,
		TokenFile: *tokenFile, TLSCertPath: *tlsCertPath, TLSKeyPath: *tlsKeyPath,
		Template: template, TemplateDigest: *templateDigest, ImageDigest: *imageDigest,
		Namespace: "openkubes-execution-system", Name: "ok147-stage-authority", PrivateSecret: "ok147-stage-authority-private",
		StorageClass: *storageClass, StorageRequest: *storageRequest, ServiceIP: *serviceIP,
	})
	if err != nil {
		return err
	}
	raw, err := packaged.PrivateBytes()
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return errors.New("write private bounded stage-authority runtime package")
	}
	receipt, err := packaged.Receipt()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runAuthorityStageMaterialize(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok authority stage materialize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	source := flags.String("source", "", "projected bounded stage-authority Secret directory")
	destination := flags.String("destination", "", "empty private destination directory")
	stateDirectory := flags.String("state-directory", "", "private durable single-use state directory")
	expectedPolicyDigest := flags.String("expected-policy-digest", "", "reviewed bounded policy SHA-256 identity")
	expectedKeyID := flags.String("expected-key-id", "", "reviewed Ed25519 public-key identity")
	materialize := flags.Bool("materialize", false, "copy the exact projected set create-only")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !*materialize || *source == "" || *destination == "" || *stateDirectory == "" || *expectedPolicyDigest == "" || *expectedKeyID == "" {
		return errors.New("bounded stage-authority materialization requires all bindings and explicit --materialize")
	}
	receipt, materializeErr := stageauthority.Materialize(stageauthority.MaterializationConfig{
		SourceDirectory: *source, DestinationDirectory: *destination, StateDirectory: *stateDirectory,
		ExpectedPolicyDigest: *expectedPolicyDigest, ExpectedKeyID: *expectedKeyID,
	})
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		return err
	}
	return materializeErr
}

func runAuthorityStagePolicy(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok authority stage policy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "path to the bounded staged execution plan")
	contractNamespace := flags.String("contract-namespace", "", "expected Contract namespace")
	contractName := flags.String("contract-name", "", "expected Contract name")
	intentRevision := flags.String("intent-revision", "", "expected normalized Contract revision R")
	enablementRevision := flags.String("enablement-revision", "", "expected Enablement revision E")
	platformRevision := flags.String("platform-revision", "", "expected Platform revision P")
	executionFixture := flags.String("execution-fixture", "", "expected execution FixtureDigest")
	infrastructureAuthority := flags.String("infrastructure-authority", "", "expected infrastructure authority")
	managementAuthority := flags.String("management-authority", "", "expected management authority")
	gitOpsAuthority := flags.String("gitops-authority", "", "expected GitOps authority")
	output := flags.String("output", "", "new canonical bounded policy file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for _, input := range []string{
		*planPath, *contractNamespace, *contractName, *intentRevision, *enablementRevision,
		*platformRevision, *executionFixture, *infrastructureAuthority, *managementAuthority, *gitOpsAuthority, *output,
	} {
		if input == "" {
			return errors.New("all bounded stage-authority policy inputs are required")
		}
	}
	plan, err := stageplan.Load(*planPath, stageplan.Expected{
		ContractIdentity: contract.Identity{Namespace: *contractNamespace, Name: *contractName},
		IntentRevision:   *intentRevision, EnablementRevision: *enablementRevision,
		PlatformRevision: *platformRevision, ExecutionFixture: *executionFixture,
		InfrastructureAuthority: *infrastructureAuthority, ManagementAuthority: *managementAuthority, GitOpsAuthority: *gitOpsAuthority,
	})
	if err != nil {
		return err
	}
	raw, receipt, err := stageauthority.FromPlan(plan)
	if err != nil {
		return err
	}
	if err := writeNewLocalFile(*output, raw); err != nil {
		return errors.New("write bounded stage-authority policy")
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(receipt)
}

func runAuthorityStageServe(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ok authority stage serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	policyPath := flags.String("policy", "", "exact bounded stage-authority policy")
	expectedPolicyDigest := flags.String("expected-policy-digest", "", "reviewed bounded policy SHA-256 identity")
	privateKeyPath := flags.String("private-key", "", "private base64 Ed25519 signing key")
	tokenFile := flags.String("token-file", "", "private bearer-token file")
	stateDirectory := flags.String("state-directory", "", "private create-only single-use state directory")
	listenAddress := flags.String("listen", "", "literal IP and port to serve")
	tlsCertPath := flags.String("tls-cert", "", "TLS server certificate")
	tlsKeyPath := flags.String("tls-key", "", "private TLS server key")
	grantValidFor := flags.Duration("grant-valid-for", 0, "bounded grant validity between one and thirty minutes")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	for _, input := range []string{*policyPath, *expectedPolicyDigest, *privateKeyPath, *tokenFile, *stateDirectory, *listenAddress, *tlsCertPath, *tlsKeyPath} {
		if input == "" {
			return errors.New("all bounded stage-authority paths and --listen are required")
		}
	}
	if err := validateAuthorityListenAddress(*listenAddress); err != nil {
		return err
	}
	certRaw, err := readBoundedLocalFile(*tlsCertPath, 128*1024)
	if err != nil {
		return errors.New("read bounded stage-authority TLS certificate")
	}
	keyRaw, err := readPrivateAuthorityFile(*tlsKeyPath, 128*1024)
	if err != nil {
		return errors.New("bounded stage-authority TLS key is invalid")
	}
	authority, receipt, err := stageauthority.Open(stageauthority.Config{
		PolicyPath: *policyPath, ExpectedPolicyDigest: *expectedPolicyDigest, PrivateKeyPath: *privateKeyPath, TokenFile: *tokenFile,
		StateDirectory: *stateDirectory, GrantValidFor: *grantValidFor, Clock: time.Now,
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		return err
	}
	return serveBoundedStageAuthority(ctx, *listenAddress, authority, certRaw, keyRaw)
}

func serveStageAuthorityTLS(ctx context.Context, address string, handler http.Handler, certRaw, keyRaw []byte) error {
	certificate, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		return errors.New("load bounded stage-authority TLS identity")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.New("listen for bounded stage authority")
	}
	defer listener.Close()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 * 1024,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}},
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-done:
		}
	}()
	err = server.Serve(tls.NewListener(listener, server.TLSConfig))
	close(done)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

func validateAuthorityListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || port == "" || strings.ContainsAny(address, "\r\n") {
		return errors.New("--listen must be a literal IP and port")
	}
	return nil
}

func readPrivateAuthorityFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("private file metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 || opened.Size() <= 0 || opened.Size() > maximum {
		return nil, errors.New("private file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("read bounded private file")
	}
	return raw, nil
}
