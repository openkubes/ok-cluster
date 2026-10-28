package bootstrapauthority

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKubernetesSourceHTTPGettersPinIdentityAndNegotiateMetadata(t *testing.T) {
	metadataBody := `{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{"name":"ca","namespace":"issuer","uid":"uid-1","resourceVersion":"7"}}`
	secretBody := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"ca"},"type":"Opaque","data":{}}`
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/issuer/secrets/ca" {
			t.Fatalf("unexpected request target: %s %s", r.Method, r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Header.Get("Accept") {
		case partialMetadataAccept:
			w.Write([]byte(metadataBody))
		case "application/json":
			w.Write([]byte(secretBody))
		default:
			t.Fatalf("unexpected Accept header: %q", r.Header.Get("Accept"))
		}
	}))
	defer server.Close()
	metadata, secret, err := NewKubernetesSourceHTTPGetters(server.URL, "issuer", "ca", server.Client())
	if err != nil {
		t.Fatal("constructor rejected trusted test endpoint")
	}
	gotMeta, err := metadata(context.Background(), "issuer", "ca")
	if err != nil || string(gotMeta) != metadataBody {
		t.Fatalf("metadata GET mismatch: body=%s err=%v", gotMeta, err)
	}
	gotSecret, err := secret(context.Background(), "issuer", "ca")
	if err != nil || string(gotSecret) != secretBody || calls != 2 {
		t.Fatalf("secret GET mismatch: body=%s calls=%d err=%v", gotSecret, calls, err)
	}
	if _, err := metadata(context.Background(), "other", "ca"); err == nil || calls != 2 {
		t.Fatal("getter allowed callback arguments to select another object")
	}
}

func TestKubernetesSourceHTTPGettersDoNotFollowRedirectOrReturnErrorBody(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if strings.HasSuffix(r.URL.Path, "/ca") {
			http.Redirect(w, r, "/other", http.StatusTemporaryRedirect)
			return
		}
		t.Fatalf("redirect was followed to %s", r.URL.Path)
	}))
	defer server.Close()
	metadata, _, err := NewKubernetesSourceHTTPGetters(server.URL, "issuer", "ca", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	body, err := metadata(context.Background(), "issuer", "ca")
	if err == nil || len(body) != 0 || calls != 1 {
		t.Fatalf("redirect did not fail closed: calls=%d body=%q err=%v", calls, body, err)
	}
}

func TestKubernetesSourceHTTPGettersRejectUnsafeConstruction(t *testing.T) {
	client := &http.Client{}
	for _, tc := range []struct{ server, namespace, name string }{
		{"http://example.invalid", "issuer", "ca"},
		{"https://user:pass@example.invalid", "issuer", "ca"},
		{"https://example.invalid/path", "issuer", "ca"},
		{"https://example.invalid", "bad/namespace", "ca"},
		{"https://example.invalid", "issuer", "../ca"},
		{"https://example.invalid", "issuer", "ca?x=y"},
	} {
		if _, _, err := NewKubernetesSourceHTTPGetters(tc.server, tc.namespace, tc.name, client); err == nil {
			t.Fatalf("unsafe source endpoint accepted: %#v", tc)
		}
	}
	if _, _, err := NewKubernetesSourceHTTPGetters("https://example.invalid", "issuer", "ca", nil); err == nil {
		t.Fatal("nil HTTP client accepted")
	}
}
