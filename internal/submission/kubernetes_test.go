package submission

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestKubernetesSubmitIsExactCreateOnlyAndIdempotent(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeObjectAPI(t)
	client := newSubmissionClient(t, "ok-infra", api.client())

	first, err := client.Submit(context.Background(), plan.Infrastructure)
	if err != nil || first.State != "SUBMITTED" || first.MutationState != "ATTEMPTED" || len(first.Results) != 1 || first.Results[0].State != "CREATED" {
		t.Fatalf("first submission: %#v %v", first, err)
	}
	second, err := client.Submit(context.Background(), plan.Infrastructure)
	if err != nil || second.MutationState != "NOT_ATTEMPTED" || second.Results[0].State != "UNCHANGED" {
		t.Fatalf("second submission: %#v %v", second, err)
	}
	if api.posts != 1 {
		t.Fatalf("POST count=%d, want 1", api.posts)
	}
	for _, request := range api.requests {
		if request.method != http.MethodGet && request.method != http.MethodPost {
			t.Fatalf("unbounded method observed: %#v", request)
		}
		if strings.Contains(request.path, "?") || strings.HasSuffix(request.path, "/namespaces") && request.method == http.MethodGet {
			t.Fatalf("collection GET observed: %#v", request)
		}
	}
}

func TestKubernetesSubmitFailsClosedForDriftConflictAndAuthority(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong authority", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		client := newSubmissionClient(t, "ok-mgmt", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || len(api.requests) != 0 {
			t.Fatalf("authority mismatch did not fail locally: %#v %v", receipt, err)
		}
	})

	t.Run("existing drift", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, plan.Infrastructure.Objects[0].Raw)
		metadata := object["metadata"].(map[string]any)
		metadata["name"] = "different"
		api.objects[plan.Infrastructure.Objects[0].ObjectPath] = object
		client := newSubmissionClient(t, "ok-infra", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if err == nil || !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_METADATA_MISMATCH_CONVERGENCE_EXHAUSTED_AT_01" || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || api.posts != 0 {
			t.Fatalf("drift accepted: %#v %v", receipt, err)
		}
		evidence := receipt.MismatchEvidence
		if evidence == nil || evidence.FirstCategory != "SUBMISSION_OBJECT_METADATA_MISMATCH" || evidence.LastCategory != evidence.FirstCategory || evidence.ObservationCount != api.gets-1 || evidence.ExpectedDigest != plan.Infrastructure.Objects[0].Digest || evidence.LastObservedDigest == "" || !evidence.RuntimeIdentityStable {
			t.Fatalf("bounded mismatch evidence was not retained safely: %#v", evidence)
		}
		encoded, _ := json.Marshal(evidence)
		if strings.Contains(string(encoded), "different") || strings.Contains(string(encoded), plan.Infrastructure.Objects[0].ObjectPath) {
			t.Fatalf("private mismatch detail escaped: %s", encoded)
		}
	})

	t.Run("terminating existing object", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, plan.Infrastructure.Objects[0].Raw)
		object["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-29T14:00:00Z"
		api.objects[plan.Infrastructure.Objects[0].ObjectPath] = object
		client := newSubmissionClient(t, "ok-infra", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if err == nil || !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_TERMINATING_AT_01" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 {
			t.Fatalf("terminating object was not distinguished: %#v %v", receipt, err)
		}
	})

	t.Run("create response mismatch", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		api.mutateCreateResponse = func(object map[string]any) { object["apiVersion"] = "private-value" }
		client := newSubmissionClient(t, "ok-infra", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if err == nil || !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_CREATE_RESPONSE_IDENTITY_MISMATCH_AT_01" || receipt.MutationState != "ATTEMPTED" || api.posts != 1 || strings.Contains(err.Error(), "private") {
			t.Fatalf("create response mismatch was not phase-bound: %#v %v", receipt, err)
		}
	})

	t.Run("create conflict after absence", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		api.conflict = true
		client := newSubmissionClient(t, "ok-infra", api.client())
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if err == nil || !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_CONFLICT_STOPPED" || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.MutationState != "ATTEMPTED" || strings.Contains(err.Error(), "conflicted") {
			t.Fatalf("conflict accepted: %#v %v", receipt, err)
		}
	})

	t.Run("redirect is not followed", func(t *testing.T) {
		calls := 0
		client := newSubmissionClient(t, "ok-infra", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return jsonResponse(http.StatusTemporaryRedirect, nil, map[string]string{"Location": "http://127.0.0.1:12346/redirected"}), nil
		})})
		_, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if err == nil || !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_HTTP_REJECTED" || calls != 1 {
			t.Fatalf("redirect followed or accepted: calls=%d err=%v", calls, err)
		}
	})

	t.Run("transport detail is redacted", func(t *testing.T) {
		client := newSubmissionClient(t, "ok-infra", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("private endpoint detail")
		})})
		_, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if err == nil || !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_TRANSPORT_STOPPED" || strings.Contains(err.Error(), "private") {
			t.Fatalf("transport stop was not safely categorized: %v", err)
		}
	})
}

func TestKubernetesSubmitObservesExistingMismatchWithinBoundedConvergence(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	objectPlan := plan.Infrastructure.Objects[0]

	t.Run("disappears then create", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		api.beforeGet = func(count int, path string, api *fakeObjectAPI) {
			if count == 2 {
				delete(api.objects, path)
			}
		}
		receipt, err := newSubmissionClient(t, "ok-infra", api.client()).Submit(context.Background(), plan.Infrastructure)
		if err != nil || receipt.Results[0].State != "CREATED" || api.gets != 2 || api.posts != 1 {
			t.Fatalf("disappearance did not converge to one create: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("converges without create", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		api.beforeGet = func(count int, path string, api *fakeObjectAPI) {
			if count == 2 {
				api.objects[path] = apiObject(t, objectPlan.Raw)
			}
		}
		receipt, err := newSubmissionClient(t, "ok-infra", api.client()).Submit(context.Background(), plan.Infrastructure)
		if err != nil || receipt.Results[0].State != "UNCHANGED" || api.gets != 2 || api.posts != 0 {
			t.Fatalf("convergence performed a write: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("disappears after multiple bounded observations", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		api.beforeGet = func(count int, path string, api *fakeObjectAPI) {
			if count == 3 {
				delete(api.objects, path)
			}
		}
		client := newSubmissionClientWithMismatchAttempts(t, "ok-infra", api.client(), 3)
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		if err != nil || receipt.Results[0].State != "CREATED" || api.gets != 3 || api.posts != 1 {
			t.Fatalf("bounded disappearance did not converge to one create: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("stable drift exhausts finite observation cap", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		client := newSubmissionClientWithMismatchAttempts(t, "ok-infra", api.client(), 3)
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_METADATA_MISMATCH_CONVERGENCE_EXHAUSTED_AT_01" || receipt.MutationState != "NOT_ATTEMPTED" || api.gets != 4 || api.posts != 0 {
			t.Fatalf("bounded stable drift did not stop: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("final no-wait observation can reach exact absence", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		api.beforeGet = func(count int, path string, api *fakeObjectAPI) {
			if count == 4 {
				delete(api.objects, path)
			}
		}
		client := newSubmissionClientWithMismatchAttempts(t, "ok-infra", api.client(), 3)
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		if err != nil || receipt.Results[0].State != "CREATED" || api.gets != 4 || api.posts != 1 {
			t.Fatalf("final no-wait observation did not reach one create: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("stable drift remains terminal", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		receipt, err := newSubmissionClient(t, "ok-infra", api.client()).Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_METADATA_MISMATCH_CONVERGENCE_EXHAUSTED_AT_01" || receipt.MutationState != "NOT_ATTEMPTED" || api.gets != 2 || api.posts != 0 {
			t.Fatalf("stable drift did not stop: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("uid turnover remains terminal", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		api.beforeGet = func(count int, path string, api *fakeObjectAPI) {
			if count == 2 {
				api.objects[path]["metadata"].(map[string]any)["uid"] = "replacement-uid"
			}
		}
		receipt, err := newSubmissionClient(t, "ok-infra", api.client()).Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_RUNTIME_IDENTITY_INVALID_AT_01" || receipt.MutationState != "NOT_ATTEMPTED" || api.posts != 0 {
			t.Fatalf("uid turnover was accepted: receipt=%#v err=%v", receipt, err)
		}
	})

	t.Run("terminating confirmation remains terminal", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		api.beforeGet = func(count int, path string, api *fakeObjectAPI) {
			if count == 2 {
				api.objects[path]["metadata"].(map[string]any)["deletionTimestamp"] = "2026-09-30T00:00:00Z"
			}
		}
		receipt, err := newSubmissionClient(t, "ok-infra", api.client()).Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_TERMINATING_AT_01" || receipt.MutationState != "NOT_ATTEMPTED" || api.gets != 2 || api.posts != 0 {
			t.Fatalf("terminating confirmation was accepted: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("HTTP rejection during confirmation remains terminal", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		api.beforeGet = func(count int, _ string, api *fakeObjectAPI) {
			if count == 2 {
				api.failStatus = http.StatusForbidden
			}
		}
		receipt, err := newSubmissionClientWithMismatchAttempts(t, "ok-infra", api.client(), 2).Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_HTTP_FORBIDDEN" || receipt.MutationState != "NOT_ATTEMPTED" || api.gets != 2 || api.posts != 0 {
			t.Fatalf("HTTP rejection during confirmation was retried or accepted: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("cancelled confirmation remains terminal", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		client, err := NewKubernetesClient(KubernetesClientConfig{
			Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: "ok-infra", Client: api.client(),
			MismatchConfirmationDelay: time.Millisecond, Wait: func(context.Context, time.Duration) error { return context.Canceled },
		})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_RESPONSE_INVALID_AT_01" || receipt.MutationState != "NOT_ATTEMPTED" || api.gets != 1 || api.posts != 0 {
			t.Fatalf("cancelled confirmation was not terminal: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})

	t.Run("bounded deadline exhaustion retains mismatch category", func(t *testing.T) {
		api := newFakeObjectAPI(t)
		object := apiObject(t, objectPlan.Raw)
		object["metadata"].(map[string]any)["name"] = "different"
		api.objects[objectPlan.ObjectPath] = object
		client, err := NewKubernetesClient(KubernetesClientConfig{
			Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: "ok-infra", Client: api.client(),
			MismatchConfirmationDelay: time.Millisecond, MismatchConfirmationAttempts: 3,
			Wait: func(context.Context, time.Duration) error { return context.DeadlineExceeded },
		})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := client.Submit(context.Background(), plan.Infrastructure)
		var stopped *SubmissionError
		if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_METADATA_MISMATCH_CONVERGENCE_EXHAUSTED_AT_01" || receipt.MutationState != "NOT_ATTEMPTED" || api.gets != 1 || api.posts != 0 {
			t.Fatalf("bounded deadline exhaustion lost the original mismatch: receipt=%#v gets=%d posts=%d err=%v", receipt, api.gets, api.posts, err)
		}
	})
}

func TestSubmissionObjectOrdinalIsBoundWithoutIdentityDisclosure(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	api := newFakeObjectAPI(t)
	object := apiObject(t, plan.Infrastructure.Objects[0].Raw)
	object["metadata"].(map[string]any)["name"] = "private-object-name"
	api.objects[plan.Infrastructure.Objects[0].ObjectPath] = object
	client := newSubmissionClient(t, "ok-infra", api.client())
	_, err = client.Submit(context.Background(), plan.Infrastructure)
	var stopped *SubmissionError
	if !errors.As(err, &stopped) || stopped.RedactedStopCategory() != "SUBMISSION_OBJECT_METADATA_MISMATCH_CONVERGENCE_EXHAUSTED_AT_01" || strings.Contains(stopped.RedactedStopCategory(), "private") || strings.Contains(err.Error(), "private") {
		t.Fatalf("ordinal category was not redaction-safe: %v", err)
	}
}

func TestObservedObjectMismatchCategoriesAreRedactedAndPhaseSpecific(t *testing.T) {
	desired := Object{Raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"bound"},"spec":{"mode":"bound"},"data":{"key":"bound"}}`)}
	tests := []struct {
		name     string
		observed string
		want     string
	}{
		{name: "response", observed: `{`, want: "SUBMISSION_OBJECT_RESPONSE_INVALID"},
		{name: "identity", observed: `{"apiVersion":"v2","kind":"ConfigMap","metadata":{"name":"bound","uid":"u","resourceVersion":"1"},"spec":{"mode":"bound"},"data":{"key":"bound"}}`, want: "SUBMISSION_OBJECT_IDENTITY_MISMATCH"},
		{name: "metadata", observed: `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"other","uid":"u","resourceVersion":"1"},"spec":{"mode":"bound"},"data":{"key":"bound"}}`, want: "SUBMISSION_OBJECT_METADATA_MISMATCH"},
		{name: "spec", observed: `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"bound","uid":"u","resourceVersion":"1"},"spec":{"mode":"other"},"data":{"key":"bound"}}`, want: "SUBMISSION_OBJECT_SPEC_MISMATCH"},
		{name: "content", observed: `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"bound","uid":"u","resourceVersion":"1"},"spec":{"mode":"bound"},"data":{"key":"other"}}`, want: "SUBMISSION_OBJECT_CONTENT_DATA_MISMATCH"},
		{name: "runtime identity", observed: `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"bound"},"spec":{"mode":"bound"},"data":{"key":"bound"}}`, want: "SUBMISSION_OBJECT_RUNTIME_IDENTITY_INVALID"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := verifyObservedObject([]byte(test.observed), desired)
			var categorized interface{ RedactedStopCategory() string }
			if err == nil || !errors.As(err, &categorized) || categorized.RedactedStopCategory() != test.want || strings.Contains(strings.ToLower(categorized.RedactedStopCategory()), "bound") {
				t.Fatalf("category=%v err=%v, want %s", categorized, err, test.want)
			}
		})
	}
}

func TestObservedObjectMismatchExhaustionCategoriesAreRedactedAndPhaseSpecific(t *testing.T) {
	for _, category := range []string{
		"SUBMISSION_OBJECT_MISMATCH",
		"SUBMISSION_OBJECT_IDENTITY_MISMATCH",
		"SUBMISSION_OBJECT_METADATA_MISMATCH",
		"SUBMISSION_OBJECT_SPEC_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_DATA_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_STRING_DATA_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_RULES_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_SUBJECTS_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_ROLE_REF_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_TYPE_MISMATCH",
		"SUBMISSION_OBJECT_CONTENT_OTHER_MISMATCH",
	} {
		err := existingObjectMismatchConvergenceExhausted(newCategorizedSubmissionError(category, "private detail"), nil)
		var categorized interface{ RedactedStopCategory() string }
		if !errors.As(err, &categorized) || categorized.RedactedStopCategory() != category+"_CONVERGENCE_EXHAUSTED" || strings.Contains(err.Error(), "private") {
			t.Fatalf("exhaustion category was not redaction-safe: category=%q err=%v", category, err)
		}
	}
}

func TestObjectMismatchCategoryRejectsImpossibleEnvelopeOnlyContentMismatch(t *testing.T) {
	expected := map[string]any{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "metadata": map[string]any{"name": "bound"}, "spec": map[string]any{"mode": "bound"}}
	observed := map[string]any{"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "Cluster", "metadata": map[string]any{"name": "bound"}, "spec": map[string]any{"mode": "bound"}}
	if got := objectMismatchCategory(expected, observed); got != "SUBMISSION_OBJECT_COMPARATOR_INCONSISTENT" {
		t.Fatalf("category=%q", got)
	}
}

func TestObjectMismatchCategoryUsesTheActuallyMismatchedTopLevelScope(t *testing.T) {
	expected := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
		"metadata": map[string]any{"name": "bound"},
		"data":     map[string]any{"stable": "value"},
		"roleRef":  map[string]any{"kind": "Role", "name": "expected"},
	}
	observed := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
		"metadata": map[string]any{"name": "bound"},
		"data":     map[string]any{"stable": "value"},
		"roleRef":  map[string]any{"kind": "Role", "name": "other"},
	}
	if got := objectMismatchCategory(expected, observed); got != "SUBMISSION_OBJECT_CONTENT_ROLE_REF_MISMATCH" {
		t.Fatalf("category followed a matching field instead of the mismatch: %s", got)
	}
}

func TestKubernetesClientAcceptsOnlyNamedOrDigestAuthority(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, nil, nil), nil
	})}
	if _, err := NewKubernetesClient(KubernetesClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token",
		AuthorityIdentity: strings.Repeat("a", 64), Client: client,
	}); err == nil {
		t.Fatal("untyped long authority identity was accepted")
	}
	if _, err := NewKubernetesClient(KubernetesClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token",
		AuthorityIdentity: "sha256:" + strings.Repeat("a", 64), Client: client,
	}); err != nil {
		t.Fatalf("redacted digest authority was rejected: %v", err)
	}
}

func TestKubernetesClientBoundsMismatchConfirmationDelay(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, nil, nil), nil
	})}
	for _, delay := range []time.Duration{-time.Nanosecond, maximumMismatchConfirmationDelay + time.Nanosecond} {
		if _, err := NewKubernetesClient(KubernetesClientConfig{
			Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: "ok-infra", Client: client,
			MismatchConfirmationDelay: delay,
		}); err == nil {
			t.Fatalf("unbounded mismatch confirmation delay %s was accepted", delay)
		}
	}
}

func TestKubernetesClientBoundsMismatchConfirmationAttempts(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusNotFound, nil, nil), nil
	})}
	for _, attempts := range []int{-1, objectMismatchMaximumAttempts + 1} {
		if _, err := NewKubernetesClient(KubernetesClientConfig{
			Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: "ok-infra", Client: client,
			MismatchConfirmationAttempts: attempts,
		}); err == nil {
			t.Fatalf("unbounded mismatch confirmation attempt count %d was accepted", attempts)
		}
	}
}

func TestSubmissionTransportStopCategoriesArePhaseSpecificAndRedacted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "dns", err: &net.DNSError{Err: "private", Name: "private.example"}, want: "SUBMISSION_DNS_STOPPED"},
		{name: "connect", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("private address")}, want: "SUBMISSION_CONNECT_STOPPED"},
		{name: "tls", err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "private.example"}, want: "SUBMISSION_TLS_STOPPED"},
		{name: "timeout", err: context.DeadlineExceeded, want: "SUBMISSION_TIMEOUT_STOPPED"},
		{name: "other", err: errors.New("private transport detail"), want: "SUBMISSION_TRANSPORT_STOPPED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := submissionTransportStopCategory(test.err); got != test.want || strings.Contains(got, "private") {
				t.Fatalf("category=%q want=%q", got, test.want)
			}
		})
	}
}

func TestSubmissionHTTPStopCategoriesAreSpecificAndRedacted(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{status: http.StatusUnauthorized, want: "SUBMISSION_HTTP_UNAUTHORIZED"},
		{status: http.StatusForbidden, want: "SUBMISSION_HTTP_FORBIDDEN"},
		{status: http.StatusTooManyRequests, want: "SUBMISSION_HTTP_RATE_LIMITED"},
		{status: http.StatusInternalServerError, want: "SUBMISSION_HTTP_SERVER_ERROR"},
		{status: http.StatusBadGateway, want: "SUBMISSION_HTTP_SERVER_ERROR"},
		{status: http.StatusServiceUnavailable, want: "SUBMISSION_HTTP_SERVER_ERROR"},
		{status: http.StatusGatewayTimeout, want: "SUBMISSION_HTTP_SERVER_ERROR"},
		{status: http.StatusNotImplemented, want: "SUBMISSION_HTTP_REJECTED"},
		{status: http.StatusTemporaryRedirect, want: "SUBMISSION_HTTP_REJECTED"},
	}
	for _, test := range tests {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			private := []byte(`{"reason":"private provider detail","message":"private endpoint"}`)
			err := apiStatusError(http.MethodGet, test.status, private)
			var categorized interface{ RedactedStopCategory() string }
			if !errors.As(err, &categorized) || categorized.RedactedStopCategory() != test.want {
				t.Fatalf("category=%q want=%q", categorized.RedactedStopCategory(), test.want)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), http.MethodGet) || strings.Contains(err.Error(), http.StatusText(test.status)) {
				t.Fatalf("HTTP stop exposed request or response detail: %q", err)
			}
		})
	}
}

func TestExecutorPreservesAuthorityOrderAndPartialReceipt(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	infraAPI := newFakeObjectAPI(t)
	mgmtAPI := newFakeObjectAPI(t)
	mgmtAPI.failStatus = http.StatusForbidden
	executor := Executor{
		Infrastructure: newSubmissionClient(t, "ok-infra", infraAPI.client()),
		Management:     newSubmissionClient(t, "ok-mgmt", mgmtAPI.client()),
	}
	receipt, err := executor.Execute(context.Background(), plan)
	if err == nil || receipt.State != "STOPPED_PARTIAL_OR_UNKNOWN" || receipt.Infrastructure == nil || receipt.Management == nil {
		t.Fatalf("partial execution receipt: %#v %v", receipt, err)
	}
	if receipt.MutationState != "ATTEMPTED" || receipt.Infrastructure.State != "SUBMITTED" || receipt.Management.State != "STOPPED_PARTIAL_OR_UNKNOWN" || infraAPI.posts != 1 || mgmtAPI.posts != 0 {
		t.Fatalf("authority order/stop differs: %#v infraPosts=%d mgmtPosts=%d", receipt, infraAPI.posts, mgmtAPI.posts)
	}
}

func TestExecutorSuccessfulReceiptIsNotLifecycleSuccess(t *testing.T) {
	root, binding := validProjection(t)
	plan, err := Load(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	executor := Executor{
		Infrastructure: newSubmissionClient(t, "ok-infra", newFakeObjectAPI(t).client()),
		Management:     newSubmissionClient(t, "ok-mgmt", newFakeObjectAPI(t).client()),
	}
	receipt, err := executor.Execute(context.Background(), plan)
	if err != nil || receipt.State != "SUBMITTED_OBSERVATION_PENDING" {
		t.Fatalf("submission outcome incorrectly classified: %#v %v", receipt, err)
	}
}

type recordedRequest struct {
	method string
	path   string
}

type fakeObjectAPI struct {
	t                    *testing.T
	mu                   sync.Mutex
	objects              map[string]map[string]any
	requests             []recordedRequest
	posts                int
	gets                 int
	conflict             bool
	failStatus           int
	mutateCreateResponse func(map[string]any)
	beforeGet            func(int, string, *fakeObjectAPI)
}

func newFakeObjectAPI(t *testing.T) *fakeObjectAPI {
	t.Helper()
	return &fakeObjectAPI{t: t, objects: map[string]map[string]any{}}
}

func (api *fakeObjectAPI) client() *http.Client {
	return &http.Client{Transport: roundTripFunc(api.roundTrip)}
}

func (api *fakeObjectAPI) roundTrip(request *http.Request) (*http.Response, error) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.requests = append(api.requests, recordedRequest{method: request.Method, path: request.URL.Path})
	if request.Header.Get("Authorization") != "Bearer short-lived-test-token" {
		return jsonResponse(http.StatusUnauthorized, nil, nil), nil
	}
	if api.failStatus != 0 {
		return jsonResponse(api.failStatus, map[string]any{"reason": "Denied"}, nil), nil
	}
	switch request.Method {
	case http.MethodGet:
		api.gets++
		if api.beforeGet != nil {
			api.beforeGet(api.gets, request.URL.Path, api)
		}
		object, ok := api.objects[request.URL.Path]
		if !ok {
			return jsonResponse(http.StatusNotFound, map[string]any{"reason": "NotFound"}, nil), nil
		}
		return jsonResponse(http.StatusOK, object, nil), nil
	case http.MethodPost:
		api.posts++
		if api.conflict {
			return jsonResponse(http.StatusConflict, map[string]any{"reason": "AlreadyExists"}, nil), nil
		}
		var object map[string]any
		decoder := json.NewDecoder(request.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			api.t.Error(err)
			return jsonResponse(http.StatusBadRequest, nil, nil), nil
		}
		metadata := object["metadata"].(map[string]any)
		metadata["uid"] = "test-uid"
		metadata["resourceVersion"] = "1"
		if api.mutateCreateResponse != nil {
			api.mutateCreateResponse(object)
		}
		name := metadata["name"].(string)
		path := request.URL.Path + "/" + name
		api.objects[path] = object
		return jsonResponse(http.StatusCreated, object, nil), nil
	default:
		return jsonResponse(http.StatusMethodNotAllowed, nil, nil), nil
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, value any, headers map[string]string) *http.Response {
	var raw []byte
	if value != nil {
		raw, _ = json.Marshal(value)
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(raw))}
}

func apiObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	metadata := value["metadata"].(map[string]any)
	metadata["uid"] = "existing-uid"
	metadata["resourceVersion"] = "7"
	return value
}

func newSubmissionClient(t *testing.T, authority string, client *http.Client) *KubernetesClient {
	return newSubmissionClientWithMismatchAttempts(t, authority, client, 1)
}

func newSubmissionClientWithMismatchAttempts(t *testing.T, authority string, client *http.Client, attempts int) *KubernetesClient {
	t.Helper()
	result, err := NewKubernetesClient(KubernetesClientConfig{
		Endpoint: "http://127.0.0.1:12345", BearerToken: "short-lived-test-token", AuthorityIdentity: authority, Client: client,
		MismatchConfirmationDelay: time.Millisecond, MismatchConfirmationAttempts: attempts, Wait: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
