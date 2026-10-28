package bootstrapauthority

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

func TestSignedRequestWireRoundTripIsCanonicalAndBounded(t *testing.T) {
	fixture := newObserverTaskFixture(t, "network-observer")
	raw, err := EncodeSignedRequest(fixture.f.r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedRequest(raw)
	if err != nil || !reflect.DeepEqual(decoded, fixture.f.r) {
		t.Fatalf("signed request wire round trip differs: equal=%v err=%v", reflect.DeepEqual(decoded, fixture.f.r), err)
	}
	mutated := append([]byte(nil), raw...)
	mutated[0] = ' '
	if _, err := DecodeSignedRequest(mutated); err == nil {
		t.Fatal("noncanonical leading whitespace was accepted")
	}
	for name, invalid := range map[string][]byte{
		"unknown field":   append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"extra":true}`)...),
		"duplicate field": bytes.Replace(raw, []byte(`{"format":`), []byte(`{"format":"duplicate","format":`), 1),
		"oversize":        bytes.Repeat([]byte("x"), MaximumSignedRequestWireBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSignedRequest(invalid); err == nil {
				t.Fatal("invalid signed request wire document was accepted")
			}
		})
	}
}

func TestSignedResultWireRoundTripContainsOnlyPublicCertificate(t *testing.T) {
	fixture := newObserverTaskFixture(t, "network-observer")
	requestDigest, err := bootstrapcheck.RequestDigest(fixture.f.r.Request)
	if err != nil {
		t.Fatal(err)
	}
	result := SignedResult{
		Audience: ResultAudience, KeyID: digest([]byte("result-key")),
		SlotDigest: digest([]byte("slot")), ClaimDigest: digest([]byte("claim")),
		AuthorizationDigest: digest([]byte("authorization")),
		Result:              bootstrapcheck.Result{RequestDigest: requestDigest, CertificateDER: []byte("public leaf certificate DER")},
		IssuedAt:            fixture.f.now.UTC(), Signature: bytes.Repeat([]byte{0x7a}, ed25519.SignatureSize),
	}
	raw, err := EncodeSignedResult(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedResult(raw)
	if err != nil || !reflect.DeepEqual(decoded, result) {
		t.Fatalf("signed result wire round trip differs: equal=%v err=%v", reflect.DeepEqual(decoded, result), err)
	}
	if bytes.Contains(raw, []byte("privateKey")) || bytes.Contains(raw, []byte("private key")) {
		t.Fatal("result wire unexpectedly contains private-key material")
	}
	for name, invalid := range map[string][]byte{
		"unknown field":     append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"extra":true}`)...),
		"duplicate field":   bytes.Replace(raw, []byte(`{"format":`), []byte(`{"format":"duplicate","format":`), 1),
		"non-UTC timestamp": bytes.Replace(raw, []byte(fixture.f.now.UTC().Format(time.RFC3339Nano)), []byte(fixture.f.now.In(time.FixedZone("test", 3600)).Format(time.RFC3339Nano)), 1),
		"oversize":          bytes.Repeat([]byte("x"), MaximumSignedResultWireBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSignedResult(invalid); err == nil {
				t.Fatal("invalid signed result wire document was accepted")
			}
		})
	}
}

func TestWireDecodeDoesNotImplySignatureVerification(t *testing.T) {
	fixture := newObserverTaskFixture(t, "network-observer")
	unsigned := fixture.f.r
	unsigned.Signature = bytes.Repeat([]byte{0}, ed25519.SignatureSize)
	raw, err := EncodeSignedRequest(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSignedRequest(raw)
	if err != nil || !reflect.DeepEqual(decoded, unsigned) {
		t.Fatalf("wire codec unexpectedly performed authorization: %v", err)
	}
	if _, err := fixture.f.a.Verify(decoded, fixture.f.inputs, fixture.f.now); err == nil {
		t.Fatal("invalid request signature passed the authoritative verifier")
	}
}

func TestSignedRequestEncoderRejectsMalformedEnvelope(t *testing.T) {
	fixture := newObserverTaskFixture(t, "network-observer")
	invalid := fixture.f.r
	invalid.Signature = nil
	if _, err := EncodeSignedRequest(invalid); err == nil {
		t.Fatal("request without signature bytes was encoded")
	}
	invalid = fixture.f.r
	invalid.OperationNonce = "not-a-nonce"
	if _, err := EncodeSignedRequest(invalid); err == nil {
		t.Fatal("malformed operation nonce was encoded")
	}
	invalid = fixture.f.r
	invalid.NotAfter = time.Time{}
	if _, err := EncodeSignedRequest(invalid); err == nil {
		t.Fatal("invalid request window was encoded")
	}
}
