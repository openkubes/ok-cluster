package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openkubes/ok-cluster/internal/targetadmission"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("ok-target-admission", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	bundlePath := flags.String("bundle-file", "", "private signed Stage-7 policy bundle file")
	publicKeyPath := flags.String("policy-public-key-file", "", "out-of-band pinned 32-byte Ed25519 public key file")
	apiEndpoint := flags.String("target-api-endpoint", "", "explicit target Kubernetes API HTTPS endpoint")
	apiCAPath := flags.String("target-api-ca-file", "", "pinned target Kubernetes API CA PEM file")
	apiTokenPath := flags.String("target-read-token-file", "", "short-lived read-only token file for kube-system Namespace and /version GETs")
	servingCertPath := flags.String("tls-certificate-file", "", "webhook serving certificate PEM file")
	servingKeyPath := flags.String("tls-private-key-file", "", "private webhook serving key file")
	webhookCAPath := flags.String("webhook-ca-file", "", "CA bundle pinned by the API server webhook configuration")
	serviceDNS := flags.String("service-dns", "", "exact Kubernetes Service DNS SAN: "+targetadmission.InstallServiceDNS)
	listenAddress := flags.String("listen", "127.0.0.1:8443", "HTTPS listen address (loopback by default; set explicitly for cluster deployment)")
	renderInstall := flags.Bool("render-install-set", false, "print the six-resource local install plan; no API contact or apply")
	renderActivation := flags.Bool("render-activation-plan", false, "print a signed-policy-bound local plan; target checks and apply remain separate")
	verifyActivationPlan := flags.String("verify-activation-plan-file", "", "verify a saved plan against signed policy sources; offline only")
	preflightTarget := flags.Bool("preflight-target", false, "perform exactly two TLS-pinned, read-only target API GETs; no mutation")
	activationPlanPath := flags.String("activation-plan-file", "", "saved offline activation plan (preflight mode only)")
	imageRef := flags.String("image-ref", "", "fully qualified immutable sha256 image reference (render mode only)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errors.New("invalid target admission server arguments")
	}
	listenWasSet := false
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == "listen" {
			listenWasSet = true
		}
	})
	if *preflightTarget {
		if *renderInstall || *renderActivation || *verifyActivationPlan != "" || flags.NArg() != 0 || *imageRef != "" ||
			*activationPlanPath == "" || *bundlePath == "" || *publicKeyPath == "" || *webhookCAPath == "" ||
			*apiEndpoint == "" || *apiCAPath == "" || *apiTokenPath == "" || *servingCertPath != "" ||
			*servingKeyPath != "" || *serviceDNS != "" || listenWasSet {
			return errors.New("preflight-target requires an activation plan, signed policy sources and read-only target API inputs only; no server or mutation inputs")
		}
		return preflightTargetReadOnly(*activationPlanPath, *bundlePath, *publicKeyPath, *webhookCAPath, *apiEndpoint, *apiCAPath, *apiTokenPath)
	}
	if *renderInstall {
		if *renderActivation || *verifyActivationPlan != "" || *activationPlanPath != "" || flags.NArg() != 0 || *bundlePath != "" || *publicKeyPath != "" || *apiEndpoint != "" || *apiCAPath != "" || *apiTokenPath != "" || *servingCertPath != "" || *servingKeyPath != "" || *webhookCAPath != "" || *serviceDNS != "" {
			return errors.New("render-install-set accepts only --image-ref and no server inputs")
		}
		return renderInstallSet(*imageRef)
	}
	if *verifyActivationPlan != "" {
		if *renderActivation || *activationPlanPath != "" || flags.NArg() != 0 || *bundlePath == "" || *publicKeyPath == "" || *webhookCAPath == "" || *imageRef != "" ||
			*apiEndpoint != "" || *apiCAPath != "" || *apiTokenPath != "" || *servingCertPath != "" || *servingKeyPath != "" || *serviceDNS != "" {
			return errors.New("verify-activation-plan-file requires only a saved plan, signed bundle, public-key pin, and webhook CA; no API or server inputs")
		}
		return verifyActivationPlanFile(*verifyActivationPlan, *bundlePath, *publicKeyPath, *webhookCAPath)
	}
	if *renderActivation {
		if *activationPlanPath != "" || flags.NArg() != 0 || *bundlePath == "" || *publicKeyPath == "" || *webhookCAPath == "" || *imageRef == "" ||
			*apiEndpoint != "" || *apiCAPath != "" || *apiTokenPath != "" || *servingCertPath != "" || *servingKeyPath != "" || *serviceDNS != "" {
			return errors.New("render-activation-plan requires only --bundle-file, --policy-public-key-file, --webhook-ca-file, and --image-ref; no server or API inputs")
		}
		return renderActivationPlan(*bundlePath, *publicKeyPath, *webhookCAPath, *imageRef)
	}
	if *activationPlanPath != "" || flags.NArg() != 0 || *imageRef != "" || *bundlePath == "" || *publicKeyPath == "" || *apiEndpoint == "" || *apiCAPath == "" || *apiTokenPath == "" || *servingCertPath == "" || *servingKeyPath == "" || *webhookCAPath == "" || *serviceDNS == "" {
		return errors.New("all policy, target identity, TLS, and service inputs must be explicit")
	}
	if _, _, err := net.SplitHostPort(*listenAddress); err != nil {
		return errors.New("HTTPS listen address must include a valid host and port")
	}

	bundle, err := readInput(*bundlePath, targetadmission.MaxPolicyBytes+1, true)
	if err != nil {
		return errors.New("read private signed policy bundle")
	}
	publicKeyBytes, err := readInput(*publicKeyPath, ed25519.PublicKeySize, false)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		return errors.New("read pinned Ed25519 policy public key")
	}
	apiCA, err := readInput(*apiCAPath, 1024*1024, false)
	if err != nil {
		return errors.New("read pinned target API CA")
	}
	apiToken, err := readInput(*apiTokenPath, 64*1024, true)
	if err != nil {
		return errors.New("read private target read-only token")
	}
	servingCert, err := readInput(*servingCertPath, 1024*1024, false)
	if err != nil {
		return errors.New("read webhook serving certificate")
	}
	servingKey, err := readInput(*servingKeyPath, 1024*1024, true)
	if err != nil {
		return errors.New("read private webhook serving key")
	}
	webhookCA, err := readInput(*webhookCAPath, 1024*1024, false)
	if err != nil {
		return errors.New("read webhook CA bundle")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server, policyDigest, err := targetadmission.NewBoundTLSServer(ctx, bundle, ed25519.PublicKey(publicKeyBytes), *apiEndpoint, apiCA, apiToken, servingCert, servingKey, webhookCA, *serviceDNS)
	if err != nil {
		return errors.New("signed policy, live target binding, or TLS identity verification failed; server not started")
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return errors.New("open target admission HTTPS listener")
	}
	defer listener.Close()
	fmt.Fprintf(os.Stdout, "READY policy=%s signer=%s\n", policyDigest, targetadmission.PublicKeyFingerprint(ed25519.PublicKey(publicKeyBytes)))

	serveResult := make(chan error, 1)
	go func() { serveResult <- server.ServeTLS(listener, "", "") }()
	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("target admission HTTPS server stopped unexpectedly")
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return errors.New("target admission HTTPS server shutdown was incomplete")
		}
		if err := <-serveResult; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("target admission HTTPS server shutdown failed")
		}
		return nil
	}
}

func preflightTargetReadOnly(planPath, bundlePath, publicKeyPath, webhookCAPath, apiEndpoint, apiCAPath, apiTokenPath string) error {
	rawPlan, err := readInput(planPath, targetadmission.MaxActivationPlanBytes, false)
	if err != nil {
		return errors.New("read saved activation plan")
	}
	bundle, err := readInput(bundlePath, targetadmission.MaxPolicyBytes+1, true)
	if err != nil {
		return errors.New("read private signed policy bundle")
	}
	publicKeyBytes, err := readInput(publicKeyPath, ed25519.PublicKeySize, false)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		return errors.New("read pinned Ed25519 policy public key")
	}
	webhookCA, err := readInput(webhookCAPath, 1024*1024, false)
	if err != nil {
		return errors.New("read webhook CA bundle")
	}
	apiCA, err := readInput(apiCAPath, 1024*1024, false)
	if err != nil {
		return errors.New("read pinned target API CA")
	}
	apiToken, err := readInput(apiTokenPath, 64*1024, true)
	if err != nil {
		return errors.New("read private target read-only token")
	}
	plan, err := targetadmission.VerifyOfflineActivationPlanDocument(rawPlan, bundle, ed25519.PublicKey(publicKeyBytes), webhookCA)
	if err != nil {
		return errors.New("saved activation plan failed offline signed-source verification")
	}
	evidence, err := targetadmission.VerifyTargetActivationReadOnly(context.Background(), plan, bundle, ed25519.PublicKey(publicKeyBytes), webhookCA, apiEndpoint, apiCA, apiToken, time.Now())
	if err != nil {
		return errors.New("read-only target identity or version preflight failed")
	}
	if err := json.NewEncoder(os.Stdout).Encode(evidence); err != nil {
		return errors.New("write read-only target preflight evidence")
	}
	return nil
}

func renderInstallSet(image string) error {
	if image == "" {
		return errors.New("--image-ref is required with --render-install-set")
	}
	set, err := targetadmission.RenderInstallSet(image)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(os.Stdout, "# Local install plan only; secrets, webhook activation, and apply are excluded."); err != nil {
		return errors.New("write target admission plan")
	}
	for index, object := range set.Objects {
		if index > 0 {
			if _, err := fmt.Fprintln(os.Stdout, "---"); err != nil {
				return errors.New("write target admission plan")
			}
		}
		if _, err := fmt.Fprintf(os.Stdout, "# object-digest: %s\n", object.Digest); err != nil {
			return errors.New("write target admission plan")
		}
		if _, err := os.Stdout.Write(object.Raw); err != nil {
			return errors.New("write target admission plan")
		}
	}
	return nil
}

func renderActivationPlan(bundlePath, publicKeyPath, webhookCAPath, image string) error {
	bundle, err := readInput(bundlePath, targetadmission.MaxPolicyBytes+1, true)
	if err != nil {
		return errors.New("read private signed policy bundle")
	}
	publicKey, err := readInput(publicKeyPath, ed25519.PublicKeySize, false)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("read pinned Ed25519 policy public key")
	}
	webhookCA, err := readInput(webhookCAPath, 1024*1024, false)
	if err != nil {
		return errors.New("read webhook CA bundle")
	}
	plan, err := targetadmission.BuildOfflineActivationPlan(bundle, ed25519.PublicKey(publicKey), webhookCA, image)
	if err != nil {
		return errors.New("offline target admission plan could not be built")
	}
	encoded, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return errors.New("encode offline target admission plan")
	}
	if _, err := fmt.Fprintln(os.Stdout, string(encoded)); err != nil {
		return errors.New("write offline target admission plan")
	}
	return nil
}

func verifyActivationPlanFile(planPath, bundlePath, publicKeyPath, webhookCAPath string) error {
	rawPlan, err := readInput(planPath, targetadmission.MaxActivationPlanBytes, false)
	if err != nil {
		return errors.New("read saved activation plan")
	}
	bundle, err := readInput(bundlePath, targetadmission.MaxPolicyBytes+1, true)
	if err != nil {
		return errors.New("read private signed policy bundle")
	}
	publicKey, err := readInput(publicKeyPath, ed25519.PublicKeySize, false)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("read pinned Ed25519 policy public key")
	}
	webhookCA, err := readInput(webhookCAPath, 1024*1024, false)
	if err != nil {
		return errors.New("read webhook CA bundle")
	}
	plan, err := targetadmission.VerifyOfflineActivationPlanDocument(rawPlan, bundle, ed25519.PublicKey(publicKey), webhookCA)
	if err != nil {
		return errors.New("saved activation plan failed offline signed-source verification")
	}
	receipt := struct {
		Format                      string `json:"format"`
		State                       string `json:"state"`
		PlanDigest                  string `json:"planDigest"`
		APIAccessed                 bool   `json:"apiAccessed"`
		MutationAllowed             bool   `json:"mutationAllowed"`
		WebhookActive               bool   `json:"webhookActive"`
		TargetIdentityRecheckNeeded bool   `json:"targetIdentityRecheckNeeded"`
	}{"ok147-target-admission-plan-verification/v1", "VERIFIED_OFFLINE_PLAN_ONLY_NO_GO", plan.PlanDigest, false, false, false, true}
	if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
		return errors.New("write offline plan verification receipt")
	}
	return nil
}

func readInput(path string, maxBytes int64, requirePrivate bool) ([]byte, error) {
	if strings.TrimSpace(path) != path || path == "" || maxBytes <= 0 {
		return nil, errors.New("input path is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open input file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxBytes {
		return nil, errors.New("input file is not a bounded regular file")
	}
	if requirePrivate && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private input file permissions are too broad")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, errors.New("read input file")
	}
	if len(contents) == 0 || int64(len(contents)) > maxBytes {
		return nil, errors.New("input file size is invalid")
	}
	return contents, nil
}
