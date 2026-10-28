package bootstrapauthority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

// These wire formats are transport envelopes only. Decoding does not establish
// caller identity, platform evidence, request authorization, single-use state,
// credential issuance, or runner success. Those checks remain on the trusted
// controller side and in Authority.Verify/ObserverTask.Run.
const (
	SignedRequestWireFormat       = "ok147-bootstrap-issuer-request/v1"
	SignedResultWireFormat        = "ok147-bootstrap-issuer-result/v1"
	MaximumSignedRequestWireBytes = 64 * 1024
	MaximumSignedResultWireBytes  = 128 * 1024
)

type signedRequestWire struct {
	Format               string               `json:"format"`
	Audience             string               `json:"audience"`
	KeyID                string               `json:"keyId"`
	StoreDomainDigest    string               `json:"storeDomainDigest"`
	Request              bootstrapRequestWire `json:"request"`
	OperationNonce       string               `json:"operationNonce"`
	PredecessorStage     int                  `json:"predecessorStage"`
	PredecessorReceipt   string               `json:"predecessorReceiptDigest"`
	NotBefore            string               `json:"notBefore"`
	NotAfter             string               `json:"notAfter"`
	PollTimeoutNanos     int64                `json:"pollTimeoutNanos"`
	WrapperOverheadNanos int64                `json:"wrapperOverheadNanos"`
	Signature            []byte               `json:"signature"`
}

type bootstrapRequestWire struct {
	Binding bootstrapBindingWire `json:"binding"`
	CSRDER  []byte               `json:"csrDer"`
}

type bootstrapBindingWire struct {
	PlanDigest            string `json:"planDigest"`
	Attempt               string `json:"attempt"`
	TargetUID             string `json:"targetUid"`
	Endpoint              string `json:"endpoint"`
	PolicyDigest          string `json:"policyDigest"`
	Stage4ReceiptDigest   string `json:"stage4ReceiptDigest"`
	Role                  string `json:"role"`
	SourceNamespace       string `json:"sourceNamespace"`
	SourceName            string `json:"sourceName"`
	SourceUID             string `json:"sourceUid"`
	SourceResourceVersion string `json:"sourceResourceVersion"`
	SourceOwnerUID        string `json:"sourceOwnerUid"`
	CADigest              string `json:"caDigest"`
}

type signedResultWire struct {
	Format              string `json:"format"`
	Audience            string `json:"audience"`
	KeyID               string `json:"keyId"`
	SlotDigest          string `json:"slotDigest"`
	ClaimDigest         string `json:"claimDigest"`
	AuthorizationDigest string `json:"authorizationDigest"`
	RequestDigest       string `json:"requestDigest"`
	CertificateDER      []byte `json:"certificateDer"`
	IssuedAt            string `json:"issuedAt"`
	Signature           []byte `json:"signature"`
}

// EncodeSignedRequest emits the sole canonical JSON representation of the
// versioned request envelope. It does not sign or authorize the request.
func EncodeSignedRequest(request SignedRequest) ([]byte, error) {
	if err := validateSignedRequestEnvelope(request); err != nil {
		return nil, err
	}
	wire := signedRequestToWire(request)
	return marshalBoundedCanonical(wire, MaximumSignedRequestWireBytes)
}

// DecodeSignedRequest rejects duplicate/unknown fields, noncanonical encodings,
// and oversized bodies. The caller must still independently authenticate and
// verify the request against trusted platform expectations.
func DecodeSignedRequest(raw []byte) (SignedRequest, error) {
	var wire signedRequestWire
	if err := decodeCanonicalBounded(raw, MaximumSignedRequestWireBytes, &wire); err != nil || wire.Format != SignedRequestWireFormat {
		return SignedRequest{}, errors.New("signed issuer request wire document rejected")
	}
	request, err := signedRequestFromWire(wire)
	if err != nil || validateSignedRequestEnvelope(request) != nil {
		return SignedRequest{}, errors.New("signed issuer request wire document rejected")
	}
	canonical, err := marshalBoundedCanonical(signedRequestToWire(request), MaximumSignedRequestWireBytes)
	if err != nil || !bytes.Equal(raw, canonical) {
		return SignedRequest{}, errors.New("signed issuer request is not canonical")
	}
	return request, nil
}

// EncodeSignedResult emits a bounded public result envelope. The result may
// contain a public leaf certificate, never a private key. It is not evidence of
// stage completion or cluster convergence.
func EncodeSignedResult(result SignedResult) ([]byte, error) {
	if err := validateSignedResultEnvelope(result); err != nil {
		return nil, err
	}
	return marshalBoundedCanonical(signedResultToWire(result), MaximumSignedResultWireBytes)
}

// DecodeSignedResult rejects duplicate/unknown fields and noncanonical or
// oversized bodies. The caller must verify the result signature and all
// operation bindings before using the certificate.
func DecodeSignedResult(raw []byte) (SignedResult, error) {
	var wire signedResultWire
	if err := decodeCanonicalBounded(raw, MaximumSignedResultWireBytes, &wire); err != nil || wire.Format != SignedResultWireFormat {
		return SignedResult{}, errors.New("signed issuer result wire document rejected")
	}
	issuedAt, err := parseCanonicalWireTime(wire.IssuedAt)
	if err != nil {
		return SignedResult{}, errors.New("signed issuer result wire document rejected")
	}
	result := SignedResult{
		Audience: wire.Audience, KeyID: wire.KeyID, SlotDigest: wire.SlotDigest,
		ClaimDigest: wire.ClaimDigest, AuthorizationDigest: wire.AuthorizationDigest,
		Result:   bootstrapcheck.Result{RequestDigest: wire.RequestDigest, CertificateDER: append([]byte(nil), wire.CertificateDER...)},
		IssuedAt: issuedAt, Signature: append([]byte(nil), wire.Signature...),
	}
	if validateSignedResultEnvelope(result) != nil {
		return SignedResult{}, errors.New("signed issuer result wire document rejected")
	}
	canonical, err := marshalBoundedCanonical(signedResultToWire(result), MaximumSignedResultWireBytes)
	if err != nil || !bytes.Equal(raw, canonical) {
		return SignedResult{}, errors.New("signed issuer result is not canonical")
	}
	return result, nil
}

func marshalBoundedCanonical(value any, limit int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("issuer wire document exceeds its size limit")
	}
	return raw, nil
}

func decodeCanonicalBounded(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit || jsonstrict.Decode(raw, target) != nil {
		return errors.New("issuer wire document rejected")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return errors.New("issuer wire document is not canonical")
	}
	return nil
}

func parseCanonicalWireTime(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	parsed = parsed.UTC()
	if parsed.Format(time.RFC3339Nano) != raw {
		return time.Time{}, errors.New("issuer timestamp is not canonical UTC")
	}
	return parsed, nil
}

func validateSignedRequestEnvelope(request SignedRequest) error {
	if request.Audience != RequestAudience || !validDigest(request.KeyID) || !validDigest(request.StoreDomainDigest) ||
		!validDigest(request.PredecessorReceiptDigest) || request.PredecessorStage < 1 ||
		request.NotBefore.IsZero() || !request.NotAfter.After(request.NotBefore) || request.PollTimeout <= 0 || request.WrapperOverhead <= 0 ||
		len(request.Signature) != ed25519.SignatureSize {
		return errors.New("signed issuer request envelope is invalid")
	}
	if len(request.OperationNonce) != 32 || request.OperationNonce != string(bytes.ToLower([]byte(request.OperationNonce))) {
		return errors.New("signed issuer request envelope is invalid")
	}
	if nonce, err := hex.DecodeString(request.OperationNonce); err != nil || len(nonce) != 16 {
		return errors.New("signed issuer request envelope is invalid")
	}
	if _, err := RequestSigningBytes(request); err != nil {
		return errors.New("signed issuer request envelope is invalid")
	}
	if bootstrapcheck.ValidateObserverPollingBudget(request.PollTimeout, request.WrapperOverhead) != nil {
		return errors.New("signed issuer request envelope is invalid")
	}
	return nil
}

func validateSignedResultEnvelope(result SignedResult) error {
	if result.Audience != ResultAudience || !validDigest(result.KeyID) || !validDigest(result.SlotDigest) ||
		!validDigest(result.ClaimDigest) || !validDigest(result.AuthorizationDigest) || !validDigest(result.Result.RequestDigest) ||
		len(result.Result.CertificateDER) == 0 || len(result.Result.CertificateDER) > 65536 || result.IssuedAt.IsZero() ||
		len(result.Signature) != ed25519.SignatureSize {
		return errors.New("signed issuer result envelope is invalid")
	}
	if _, err := ResultSigningBytes(result); err != nil {
		return errors.New("signed issuer result envelope is invalid")
	}
	return nil
}

func signedRequestToWire(request SignedRequest) signedRequestWire {
	binding := request.Request.Binding
	return signedRequestWire{
		Format: SignedRequestWireFormat, Audience: request.Audience, KeyID: request.KeyID, StoreDomainDigest: request.StoreDomainDigest,
		Request: bootstrapRequestWire{Binding: bootstrapBindingWire{
			PlanDigest: binding.PlanDigest, Attempt: binding.Attempt, TargetUID: binding.TargetUID, Endpoint: binding.Endpoint,
			PolicyDigest: binding.PolicyDigest, Stage4ReceiptDigest: binding.Stage4ReceiptDigest, Role: binding.Role,
			SourceNamespace: binding.SourceNamespace, SourceName: binding.SourceName, SourceUID: binding.SourceUID,
			SourceResourceVersion: binding.SourceResourceVersion, SourceOwnerUID: binding.SourceOwnerUID, CADigest: binding.CADigest,
		}, CSRDER: append([]byte(nil), request.Request.CSRDER...)},
		OperationNonce: request.OperationNonce, PredecessorStage: request.PredecessorStage,
		PredecessorReceipt: request.PredecessorReceiptDigest, NotBefore: request.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter: request.NotAfter.UTC().Format(time.RFC3339Nano), PollTimeoutNanos: int64(request.PollTimeout),
		WrapperOverheadNanos: int64(request.WrapperOverhead), Signature: append([]byte(nil), request.Signature...),
	}
}

func signedRequestFromWire(wire signedRequestWire) (SignedRequest, error) {
	before, err := parseCanonicalWireTime(wire.NotBefore)
	if err != nil {
		return SignedRequest{}, err
	}
	after, err := parseCanonicalWireTime(wire.NotAfter)
	if err != nil {
		return SignedRequest{}, err
	}
	b := wire.Request.Binding
	return SignedRequest{
		Audience: wire.Audience, KeyID: wire.KeyID, StoreDomainDigest: wire.StoreDomainDigest,
		Request: bootstrapcheck.Request{Binding: bootstrapcheck.Binding{
			PlanDigest: b.PlanDigest, Attempt: b.Attempt, TargetUID: b.TargetUID, Endpoint: b.Endpoint,
			PolicyDigest: b.PolicyDigest, Stage4ReceiptDigest: b.Stage4ReceiptDigest, Role: b.Role,
			SourceNamespace: b.SourceNamespace, SourceName: b.SourceName, SourceUID: b.SourceUID,
			SourceResourceVersion: b.SourceResourceVersion, SourceOwnerUID: b.SourceOwnerUID, CADigest: b.CADigest,
		}, CSRDER: append([]byte(nil), wire.Request.CSRDER...)},
		OperationNonce: wire.OperationNonce, PredecessorStage: wire.PredecessorStage,
		PredecessorReceiptDigest: wire.PredecessorReceipt, NotBefore: before, NotAfter: after,
		PollTimeout: time.Duration(wire.PollTimeoutNanos), WrapperOverhead: time.Duration(wire.WrapperOverheadNanos),
		Signature: append([]byte(nil), wire.Signature...),
	}, nil
}

func signedResultToWire(result SignedResult) signedResultWire {
	return signedResultWire{
		Format: SignedResultWireFormat, Audience: result.Audience, KeyID: result.KeyID, SlotDigest: result.SlotDigest,
		ClaimDigest: result.ClaimDigest, AuthorizationDigest: result.AuthorizationDigest,
		RequestDigest: result.Result.RequestDigest, CertificateDER: append([]byte(nil), result.Result.CertificateDER...),
		IssuedAt: result.IssuedAt.UTC().Format(time.RFC3339Nano), Signature: append([]byte(nil), result.Signature...),
	}
}
