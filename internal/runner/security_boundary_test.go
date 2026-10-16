package runner

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/authorization"
	"github.com/openkubes/ok-cluster/internal/execution"
	"github.com/openkubes/ok-cluster/internal/ledger"
	"github.com/openkubes/ok-cluster/internal/stagecursor"
	"github.com/openkubes/ok-cluster/internal/stageplan"
)

func TestNoClientCertificateProfileIsImplicitlyAuthorized(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		name       string
		subject    pkix.Name
		start, end time.Time
	}{
		// Synthetic reproduction of the retained CAPI credential format. Never
		// copy the real kubeconfig, certificate, key or endpoints into fixtures.
		{"capi-admin-year", pkix.Name{CommonName: "kubernetes-admin", Organization: []string{"system:masters"}}, now.Add(-time.Second), now.Add(365*24*time.Hour + time.Second)},
		{"short-admin", pkix.Name{CommonName: "kubernetes-admin", Organization: []string{"system:masters"}}, now.Add(-time.Minute), now.Add(10 * time.Minute)},
		{"unapproved-client", pkix.Name{CommonName: "ok147-workload-client"}, now.Add(-time.Minute), now.Add(10 * time.Minute)},
		{"extra-group", pkix.Name{CommonName: "observer", Organization: []string{"observers", "system:masters"}}, now.Add(-time.Minute), now.Add(10 * time.Minute)},
		{"duplicate-group", pkix.Name{CommonName: "observer", Organization: []string{"observers", "observers"}}, now.Add(-time.Minute), now.Add(10 * time.Minute)},
		{"missing-cn", pkix.Name{}, now.Add(-time.Minute), now.Add(10 * time.Minute)},
		{"expired", pkix.Name{CommonName: "observer"}, now.Add(-time.Hour), now.Add(-time.Minute)},
		{"future", pkix.Name{CommonName: "observer"}, now.Add(time.Hour), now.Add(2 * time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ca, cert, key := testClientCredentialWithPolicy(t, test.subject, test.start, test.end)
			transport, err := parseBoundedKubernetesKubeconfig(testClientKubeconfig("https://192.0.2.90:6443", ca, cert, key), "https://192.0.2.90:6443", ca)
			if !errors.Is(err, ErrClientCertificateDisabled) || transport.client != nil || transport.clientCertificate || transport.credentialIdentity != "" {
				t.Fatalf("certificate implicitly authorized: %v", err)
			}
		})
	}
	if _, err := openBoundedKubernetesKubeconfigTransport("/absent/credential", "https://192.0.2.90:6443", "/absent/ca"); !errors.Is(err, ErrClientCertificateDisabled) {
		t.Fatalf("certificate rejection read credential files: %v", err)
	}
}

// These capabilities panic on *any* use, including ledger reads and Binding.
// Rejection must precede credentials, claims, observers, binding and mutation.
type forbiddenRecoveryStore struct{}

func (forbiddenRecoveryStore) Get(context.Context, string, string) ([]byte, error) {
	panic("recovery ledger read")
}
func (forbiddenRecoveryStore) Create(context.Context, string, string, []byte) error {
	panic("recovery ledger write")
}

type forbiddenRecoveryObserver struct{}

func (forbiddenRecoveryObserver) Binding() execution.StageObservationBinding {
	panic("observer binding")
}
func (forbiddenRecoveryObserver) Observe(context.Context) (execution.StageObservationResult, error) {
	panic("observe")
}

type forbiddenRecoveryBinder struct{}

func (forbiddenRecoveryBinder) Binding() execution.StageBinderBinding { panic("binder binding") }
func (forbiddenRecoveryBinder) Bind(context.Context) (execution.StageBindingResult, error) {
	panic("bind")
}

type forbiddenRecoveryMutator struct{}

func (forbiddenRecoveryMutator) Binding() execution.StageMutationBinding { panic("mutator binding") }
func (forbiddenRecoveryMutator) Mutate(context.Context, execution.StageMutationRequest) (execution.StageMutationResult, error) {
	panic("mutate")
}

func assertRecoveryExecutionDenied(t *testing.T, plan stageplan.Binding, cursor stagecursor.Cursor) {
	t.Helper()
	l, err := ledger.New(forbiddenRecoveryStore{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, observationErr := (execution.ObservationStageOperation{Ledger: l, Observer: forbiddenRecoveryObserver{}}).Run(context.Background(), plan, cursor)
			_, bindingErr := (execution.BindingStageOperation{Ledger: l, Binder: forbiddenRecoveryBinder{}}).Run(context.Background(), plan, cursor)
			_, mutationErr := (execution.StagedOperation{Ledger: l, Mutator: forbiddenRecoveryMutator{}, Clock: time.Now}).Run(context.Background(), plan, cursor, authorization.VerifiedStageGrant{})
			for _, err := range []error{observationErr, bindingErr, mutationErr} {
				if !errors.Is(err, stageplan.ErrRecoveryExecutionDisabled) {
					t.Errorf("recovery reached capability: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	// An exported field cannot strip the verified plan's recovery identity.
	plan.RecoverySourcePlanDigest = ""
	if err := plan.RequireExecutionEnabled(); !errors.Is(err, stageplan.ErrRecoveryExecutionDisabled) {
		t.Fatalf("stripped recovery identity enabled execution: %v", err)
	}
}
