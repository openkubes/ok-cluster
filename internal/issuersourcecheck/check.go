// Package issuersourcecheck is an experimental offline helper for the future
// privileged platform task. It is not linked into CLI/runner/bootstrapauthority.
// It loads no files or Secrets, signs nothing, returns no key or capability and
// cannot authorize issuance. Real CA keys must remain inside the privileged task.
package issuersourcecheck

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

var errInvalidSource = errors.New("issuer source identity or key correspondence rejected")

// Validate checks caller-supplied metadata-only bytes and CA/key bytes against
// independent expected inputs. Matching bytes do not authenticate their source
// or prove current API state, source/key read atomicity, delegation, a durable
// issuance claim, CA validity at signing time, or an approved algorithm/profile.
// The caller must establish those boundaries separately inside the platform task.
// Keys are accepted only as one unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC PEM
// block. Supported decoding is NOT approval of any algorithm, strength or issuer.
// No input, path, parser diagnostic or key material is included in errors.
func Validate(metadata, certificateDER, privateKeyPEM []byte, expected bootstrapcheck.Binding, owner bootstrapcheck.SourceOwner) error {
	if bootstrapcheck.ValidateSourceMetadata(metadata, expected, owner) != nil ||
		len(certificateDER) == 0 || len(certificateDER) > 65536 ||
		len(privateKeyPEM) == 0 || len(privateKeyPEM) > 16384 {
		return errInvalidSource
	}
	hash := sha256.Sum256(certificateDER)
	if "sha256:"+hex.EncodeToString(hash[:]) != expected.CADigest {
		return errInvalidSource
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || len(certificate.UnhandledCriticalExtensions) != 0 {
		return errInvalidSource
	}
	raw := bytes.TrimSpace(privateKeyPEM)
	block, rest := pem.Decode(raw)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		!bytes.HasPrefix(raw, []byte("-----BEGIN "+block.Type+"-----")) ||
		bytes.Count(raw, []byte("-----BEGIN ")) != 1 {
		return errInvalidSource
	}
	// Some x509 key parsers accept trailing DER. Require one complete outer
	// sequence rather than silently ignoring bytes inside an otherwise valid PEM.
	var sequence asn1.RawValue
	remainder, err := asn1.Unmarshal(block.Bytes, &sequence)
	if err != nil || len(remainder) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return errInvalidSource
	}
	var parsed any
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return errInvalidSource
	}
	if err != nil {
		return errInvalidSource
	}
	var public crypto.PublicKey
	// Use the public key obtained from the standard-library parser. This is
	// correspondence checking, not validation of optional embedded public-key
	// fields or canonicalization of every inner ASN.1 element.
	switch key := parsed.(type) {
	case *rsa.PrivateKey:
		public = &key.PublicKey
	case *ecdsa.PrivateKey:
		public = &key.PublicKey
	case ed25519.PrivateKey:
		public = key.Public()
	default:
		return errInvalidSource
	}
	actual, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return errInvalidSource
	}
	want, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil || !bytes.Equal(actual, want) {
		return errInvalidSource
	}
	return nil
}
