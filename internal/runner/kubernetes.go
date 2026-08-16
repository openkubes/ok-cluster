// Package runner contains execution-environment adapters for the bounded
// Contract Executor. It does not own contract projection or lifecycle state.
package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/ledger"
)

const (
	maximumTokenBytes = 64 * 1024
	maximumCABytes    = 1024 * 1024
)

// KubernetesLedgerConfig binds the only credential and API inputs used by the
// Job preflight. Source paths never appear in receipts or returned errors.
type KubernetesLedgerConfig struct {
	Endpoint  string
	Namespace string
	TokenFile string
	CAFile    string
}

// InspectKubernetesLedger performs a read-only restart decision. It does not
// claim the grant and therefore cannot authorize a later mutation by itself.
func InspectKubernetesLedger(ctx context.Context, grant authorization.VerifiedGrant, config KubernetesLedgerConfig) (ledger.Inspection, error) {
	store, err := OpenKubernetesLedger(config)
	if err != nil {
		return ledger.Inspection{}, err
	}
	return store.Inspect(ctx, grant)
}

// OpenKubernetesLedger materializes a TLS-only, redirect-denying client from
// bounded projected files. The caller is responsible for using a short-lived
// token with the dedicated ledger ServiceAccount.
func OpenKubernetesLedger(config KubernetesLedgerConfig) (*ledger.Ledger, error) {
	if config.Endpoint == "" || config.Namespace == "" || config.TokenFile == "" || config.CAFile == "" {
		return nil, errors.New("Kubernetes ledger endpoint, namespace, token file, and CA file are required")
	}
	tokenRaw, err := readBoundedRegular(config.TokenFile, maximumTokenBytes)
	if err != nil {
		return nil, errors.New("read projected Kubernetes ledger token")
	}
	token := string(tokenRaw)
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("projected Kubernetes ledger token is invalid")
	}
	caRaw, err := readBoundedRegular(config.CAFile, maximumCABytes)
	if err != nil {
		return nil, errors.New("read projected Kubernetes API CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return nil, errors.New("projected Kubernetes API CA contains no certificate")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:              nil,
			DisableCompression: true,
			ForceAttemptHTTP2:  true,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
			},
		},
	}
	backend, err := ledger.NewKubernetesStore(ledger.KubernetesStoreConfig{
		Endpoint: config.Endpoint, Namespace: config.Namespace, BearerToken: token, Client: client,
	})
	if err != nil {
		return nil, err
	}
	return ledger.New(backend)
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("projected file metadata is invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, errors.New("projected file exceeds size limit")
	}
	return raw, nil
}
