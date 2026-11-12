package desiredauthority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ErrAuthorizationUnverifiable includes all cryptographic, scope and
// freshness failures. No caller may treat this as permission to retry a CAS.
var ErrAuthorizationUnverifiable = errors.New("desired-state authority: signed authorization unverifiable")

const authorizationStatementVersion = "openkubes-authority-authorization/v1"
const maxAuthorizationTTL = 5 * time.Minute

// AuthorizationStatement is an externally approved, typed request proposal.
// Its exact canonical JSON is signed; it MUST NOT be constructed from an
// agent's claimed authorization without independent Policy verification.
type AuthorizationStatement struct {
	Version string
	DomainDigest string
	Audience string
	KeyID string
	Nonce string
	IssuedAt int64
	ExpiresAt int64
	Transition Transition
}

// SignedAuthorization is an untrusted wire value until VerifyAuthorization
// succeeds. Signature is ed25519 detached over CanonicalAuthorization bytes.
type SignedAuthorization struct {
	Statement AuthorizationStatement
	Signature []byte
}

// AuthorizationTrust must come from independently provisioned, pinned Policy
// configuration, never from the signed statement or Kubernetes ConfigMap.
type AuthorizationTrust struct {
	DomainDigest string
	Audience string
	KeyID string
	PublicKey ed25519.PublicKey
}

// CanonicalAuthorization binds every Transition field, including execution
// binding P and the declared authorization digest. Encoder order is fixed by
// struct member declaration. No maps or floating point fields are used.
func CanonicalAuthorization(a AuthorizationStatement) ([]byte,error) {
	if a.Version!=authorizationStatementVersion || !digestPattern.MatchString(a.DomainDigest) ||
		a.Audience=="" || a.KeyID=="" || a.Nonce=="" ||
		len(a.Audience)>128 || len(a.KeyID)>128 || len(a.Nonce)>128 ||
		a.Transition.Validate()!=nil || a.Transition.Operation!="CreateCluster" ||
		a.IssuedAt<=0 || a.ExpiresAt<=a.IssuedAt ||
		a.ExpiresAt-a.IssuedAt>int64(maxAuthorizationTTL.Seconds()) {
		return nil,ErrAuthorizationUnverifiable
	}
	// A fixed type removes ambiguity between similarly named JSON fields.
	return json.Marshal(struct {
		Version string
		DomainDigest string
		Audience string
		KeyID string
		Nonce string
		IssuedAt int64
		ExpiresAt int64
		Transition Transition
	}{
		Version:a.Version,DomainDigest:a.DomainDigest,Audience:a.Audience,
		KeyID:a.KeyID,Nonce:a.Nonce,IssuedAt:a.IssuedAt,ExpiresAt:a.ExpiresAt,
		Transition:a.Transition,
	})
}

// VerifyAuthorization is a read-only cryptographic preflight. It does not
// reserve or consume nonce, inspect real cluster inventory, verify history,
// grant an executor credential or call Store.CompareAndSwap.
func VerifyAuthorization(a SignedAuthorization,t Transition,domainDigest string,trust AuthorizationTrust,now time.Time) error {
	if t.Validate()!=nil || t.Operation!="CreateCluster" ||
		len(trust.PublicKey)!=ed25519.PublicKeySize ||
		!digestPattern.MatchString(domainDigest) ||
		trust.DomainDigest!=domainDigest || !digestPattern.MatchString(trust.DomainDigest) ||
		trust.Audience=="" || trust.KeyID=="" || now.IsZero() {
		return ErrAuthorizationUnverifiable
	}
	s:=a.Statement
	if s.Transition!=t || s.DomainDigest!=domainDigest ||
		s.Audience!=trust.Audience || s.KeyID!=trust.KeyID ||
		now.Unix()<s.IssuedAt || now.Unix()>=s.ExpiresAt {
		return ErrAuthorizationUnverifiable
	}
	payload,err:=CanonicalAuthorization(s)
	if err!=nil || len(a.Signature)!=ed25519.SignatureSize ||
		!ed25519.Verify(trust.PublicKey,payload,a.Signature) {
		return ErrAuthorizationUnverifiable
	}
	return nil
}

// AuthorizationStatementDigest supplies the signed statement identity for
// evidence correlation; unlike authorization itself a digest grants no rights.
func AuthorizationStatementDigest(s AuthorizationStatement)(string,error){
	raw,err:=CanonicalAuthorization(s)
	if err!=nil{return "",err}
	sum:=sha256.Sum256(raw)
	return "sha256:"+hex.EncodeToString(sum[:]),nil
}

// EqualAuthorizationDigest is a safe exact comparison for evidence checking.
// Even a matching digest does not authorize a write.
func EqualAuthorizationDigest(expected,actual string)bool {
	if !digestPattern.MatchString(expected)||!digestPattern.MatchString(actual){return false}
	return subtle.ConstantTimeCompare([]byte(expected),[]byte(actual))==1
}
