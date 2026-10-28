package bootstrapauthority

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

func sourceReaderFixture(t *testing.T, mutate func([]byte) []byte) (*KubernetesSourceReader, bootstrapcheck.Binding, *int, *int) {
	t.Helper()
	f := newFixture(t)
	source := newSourceContractFixture(t, f)
	metadataCalls, secretCalls := 0, 0
	fullMetadata := json.RawMessage{}
	var metadataObject struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(source.metadata, &metadataObject); err != nil {
		t.Fatal(err)
	}
	fullMetadata = append(fullMetadata, metadataObject.Metadata...)
	secret := struct {
		APIVersion string                     `json:"apiVersion"`
		Kind       string                     `json:"kind"`
		Metadata   json.RawMessage            `json:"metadata"`
		Type       string                     `json:"type"`
		Data       map[string]json.RawMessage `json:"data"`
	}{
		APIVersion: "v1", Kind: "Secret", Metadata: fullMetadata, Type: "Opaque",
		Data: map[string]json.RawMessage{
			"ca.der": rawSecretData(t, source.caDER), "ca.key": rawSecretData(t, source.keyPEM),
		},
	}
	secretRaw, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		secretRaw = mutate(secretRaw)
	}
	reader, err := NewKubernetesSourceReader(KubernetesSourceReaderConfig{
		Expected: f.inputs.Expected, Owner: source.owner, SecretType: "Opaque",
		CertificateDataKey: "ca.der", PrivateKeyDataKey: "ca.key", CertificateEncoding: "DER",
		ReadMetadata: func(_ context.Context, namespace, name string) ([]byte, error) {
			metadataCalls++
			if namespace != f.inputs.Expected.SourceNamespace || name != f.inputs.Expected.SourceName {
				return nil, errors.New("unexpected source selector")
			}
			return append([]byte(nil), source.metadata...), nil
		},
		ReadSecret: func(_ context.Context, namespace, name string) ([]byte, error) {
			secretCalls++
			if namespace != f.inputs.Expected.SourceNamespace || name != f.inputs.Expected.SourceName {
				return nil, errors.New("unexpected source selector")
			}
			return append([]byte(nil), secretRaw...), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reader, f.inputs.Expected, &metadataCalls, &secretCalls
}

func TestKubernetesSourceReaderReadsExactBoundSourceAndChecksSnapshotTwice(t *testing.T) {
	reader, expected, metadataCalls, secretCalls := sourceReaderFixture(t, nil)
	got, err := reader.ReadSource(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	if *metadataCalls != 1 || *secretCalls != 1 || len(got.CertificateDER) == 0 || len(got.PrivateKeyPEM) == 0 {
		t.Fatalf("reader did not perform exactly the two bound reads: metadata=%d secret=%d", *metadataCalls, *secretCalls)
	}
	if _, err := x509.ParseCertificate(got.CertificateDER); err != nil {
		t.Fatal("returned certificate is not DER X.509")
	}
}

func TestKubernetesSourceReaderEndToEndThroughPinnedHTTPSGetters(t *testing.T) {
	f := newFixture(t)
	source := newSourceContractFixture(t, f)
	var metadataFields struct {
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(source.metadata, &metadataFields); err != nil {
		t.Fatal(err)
	}
	secretBody, err := json.Marshal(struct {
		APIVersion string                     `json:"apiVersion"`
		Kind       string                     `json:"kind"`
		Metadata   json.RawMessage            `json:"metadata"`
		Type       string                     `json:"type"`
		Data       map[string]json.RawMessage `json:"data"`
	}{"v1", "Secret", metadataFields.Metadata, "Opaque", map[string]json.RawMessage{
		"ca.der": rawSecretData(t, source.caDER), "ca.key": rawSecretData(t, source.keyPEM),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/"+f.inputs.Expected.SourceNamespace+"/secrets/"+f.inputs.Expected.SourceName {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Header.Get("Accept") {
		case partialMetadataAccept:
			seen = append(seen, "metadata")
			_, _ = w.Write(source.metadata)
		case "application/json":
			seen = append(seen, "secret")
			_, _ = w.Write(secretBody)
		default:
			w.WriteHeader(http.StatusNotAcceptable)
		}
	}))
	defer server.Close()
	metadataGetter, secretGetter, err := NewKubernetesSourceHTTPGetters(server.URL, f.inputs.Expected.SourceNamespace, f.inputs.Expected.SourceName, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewKubernetesSourceReader(KubernetesSourceReaderConfig{
		Expected: f.inputs.Expected, Owner: source.owner, SecretType: "Opaque",
		CertificateDataKey: "ca.der", PrivateKeyDataKey: "ca.key", CertificateEncoding: "DER",
		ReadMetadata: metadataGetter, ReadSecret: secretGetter,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadSource(context.Background(), f.inputs.Expected)
	if err != nil || len(got.CertificateDER) == 0 || len(got.PrivateKeyPEM) == 0 {
		t.Fatalf("bound HTTPS source flow did not complete: material=(%d,%d), err=%v", len(got.CertificateDER), len(got.PrivateKeyPEM), err)
	}
	if len(seen) != 2 || seen[0] != "metadata" || seen[1] != "secret" {
		t.Fatalf("API reads were not metadata-first and exact: %v", seen)
	}
}

func TestKubernetesSourceReaderWipesSecretResponseBuffer(t *testing.T) {
	reader, expected, _, _ := sourceReaderFixture(t, nil)
	original := reader.config.ReadSecret
	var responseBuffer []byte
	reader.config.ReadSecret = func(ctx context.Context, namespace, name string) ([]byte, error) {
		body, err := original(ctx, namespace, name)
		responseBuffer = body
		return body, err
	}
	if _, err := reader.ReadSource(context.Background(), expected); err != nil {
		t.Fatal(err)
	}
	if len(responseBuffer) == 0 {
		t.Fatal("test did not capture the source response buffer")
	}
	for _, value := range responseBuffer {
		if value != 0 {
			t.Fatal("source response buffer retained Secret bytes after processing")
		}
	}
}

func TestKubernetesSourceReaderStopsBeforeSecretReadOnWrongBindingOrMetadata(t *testing.T) {
	for _, name := range []string{"wrong binding", "metadata-only response contains Secret fields", "metadata adapter failure"} {
		t.Run(name, func(t *testing.T) {
			reader, expected, metadataCalls, secretCalls := sourceReaderFixture(t, nil)
			requested := expected
			if name == "wrong binding" {
				requested.SourceUID = "foreign-uid"
			}
			if name == "metadata-only response contains Secret fields" || name == "metadata adapter failure" {
				reader.config.ReadMetadata = func(context.Context, string, string) ([]byte, error) {
					*metadataCalls++
					if name == "metadata adapter failure" {
						return nil, errors.New("sensitive adapter detail")
					}
					return []byte(`{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{},"data":{"leak":"secret"}}`), nil
				}
			}
			_, err := reader.ReadSource(context.Background(), requested)
			if !errors.Is(err, ErrStop) || strings.Contains(err.Error(), "sensitive") || *secretCalls != 0 {
				t.Fatalf("untrusted source reached full read or leaked diagnostics: calls=(%d,%d), err=%v", *metadataCalls, *secretCalls, err)
			}
		})
	}
}

func TestKubernetesSourceReaderRejectsSecretIdentityAndPayloadDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"resourceVersion drift", func(raw []byte) []byte {
			var object map[string]any
			if json.Unmarshal(raw, &object) != nil {
				return raw
			}
			metadata := object["metadata"].(map[string]any)
			metadata["resourceVersion"] = "new-rv"
			changed, _ := json.Marshal(object)
			return changed
		}},
		{"unexpected key", func(raw []byte) []byte { return bytesReplaceOnce(raw, `"ca.key":`, `"other.key":`) }},
		{"stringData present", func(raw []byte) []byte {
			return bytesReplaceOnce(raw, `"type":"Opaque"`, `"type":"Opaque","stringData":{}`)
		}},
		{"wrong type", func(raw []byte) []byte { return bytesReplaceOnce(raw, `"type":"Opaque"`, `"type":"kubernetes.io/tls"`) }},
		{"invalid certificate", func(raw []byte) []byte { return bytesReplaceOnce(raw, `"ca.der":"`, `"ca.der":"bm90LWNlcnQ`) }},
		{"escaped base64 representation", func(raw []byte) []byte { return bytesReplaceOnce(raw, `"ca.der":"`, `"ca.der":"\u0061`) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, expected, metadataCalls, secretCalls := sourceReaderFixture(t, tt.mutate)
			got, err := reader.ReadSource(context.Background(), expected)
			if !errors.Is(err, ErrStop) || len(got.Metadata) != 0 || len(got.CertificateDER) != 0 || len(got.PrivateKeyPEM) != 0 || *metadataCalls != 1 || *secretCalls != 1 {
				t.Fatalf("drift was not stopped with empty result: calls=(%d,%d), err=%v", *metadataCalls, *secretCalls, err)
			}
		})
	}
}

func TestKubernetesSourceReaderRejectsUnsafeConfigurationBeforeAdapters(t *testing.T) {
	f := newFixture(t)
	source := newSourceContractFixture(t, f)
	calls := 0
	base := KubernetesSourceReaderConfig{
		Expected: f.inputs.Expected, Owner: source.owner, SecretType: "Opaque",
		CertificateDataKey: "ca.der", PrivateKeyDataKey: "ca.key", CertificateEncoding: "DER",
		ReadMetadata: func(context.Context, string, string) ([]byte, error) { calls++; return nil, nil },
		ReadSecret:   func(context.Context, string, string) ([]byte, error) { calls++; return nil, nil },
	}
	for _, key := range []string{"bad/key", "has space", "unicode-ä", "", strings.Repeat("a", 254)} {
		bad := base
		bad.CertificateDataKey = key
		if _, err := NewKubernetesSourceReader(bad); err == nil {
			t.Fatalf("unsafe key %q was accepted", key)
		}
	}
	if calls != 0 {
		t.Fatal("invalid reader config invoked an adapter")
	}
}

func bytesReplaceOnce(raw []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(raw), old, replacement, 1))
}

func rawSecretData(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(encodeSecretData(raw))
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
