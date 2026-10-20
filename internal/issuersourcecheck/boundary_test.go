package issuersourcecheck

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
)

func TestPEMSizeBoundaryWithOtherwiseValidKey(t *testing.T) {
	der, key, expected := fixture(t, edKey(t), nil)
	for _, size := range []int{16383, 16384, 16385} {
		value := append(bytes.Clone(key), bytes.Repeat([]byte("\n"), size-len(key))...)
		err := Validate([]byte(metadataFixture), der, value, expected, ownerFixture)
		if (err == nil) != (size <= 16384) {
			t.Fatalf("valid padded PEM size %d: %v", size, err)
		}
	}
}

func certificateAtSize(t *testing.T, size int) ([]byte, []byte, bootstrapcheck.Binding) {
	t.Helper()
	key := edKey(t) // fixed-size Ed25519 signature makes length deterministic
	padding := size - 512
	for i := 0; i < 8; i++ {
		der, encoded, expected := fixture(t, key, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, padding)}}
		})
		if len(der) == size {
			return der, encoded, expected
		}
		padding += size - len(der)
	}
	t.Fatalf("could not construct certificate of exact size %d", size)
	return nil, nil, bootstrapcheck.Binding{}
}

func TestCertificateSizeBoundaryWithOtherwiseValidCA(t *testing.T) {
	for _, size := range []int{65535, 65536, 65537} {
		der, key, expected := certificateAtSize(t, size)
		if _, err := x509.ParseCertificate(der); err != nil {
			t.Fatal(err)
		}
		err := Validate([]byte(metadataFixture), der, key, expected, ownerFixture)
		if (err == nil) != (size <= 65536) {
			t.Fatalf("valid bound CA DER size %d: %v", size, err)
		}
	}
}

func TestValidKeyWithPEMHeaderOrUnsupportedLabelIsRejected(t *testing.T) {
	der, key, expected := fixture(t, edKey(t), nil)
	block, _ := pem.Decode(key)
	for name, value := range map[string][]byte{
		"valid plaintext with Comment header": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Comment": "x"}, Bytes: block.Bytes}),
		// A valid plaintext payload with an encrypted label isolates the label
		// guard; unlike malformed ciphertext it would parse if that label were
		// incorrectly routed to the plain PKCS#8 decoder.
		"plaintext mislabeled encrypted":   pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: block.Bytes}),
		"plaintext mislabeled certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
	} {
		t.Run(name, func(t *testing.T) {
			if Validate([]byte(metadataFixture), der, value, expected, ownerFixture) == nil {
				t.Fatal("accepted forbidden PEM envelope")
			}
		})
	}
}

func marshalFixture(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestStructuredEncryptedPrivateKeyInfoIsRejected(t *testing.T) {
	der, key, expected := fixture(t, edKey(t), nil)
	// Well-formed PKCS#8 EncryptedPrivateKeyInfo / PBES2 envelope with opaque
	// synthetic ciphertext. No decryption/password correctness is claimed or
	// needed: encrypted-key input is unsupported and must fail closed.
	kdf := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}, Parameters: asn1.RawValue{FullBytes: marshalFixture(t, struct {
		Salt       []byte
		Iterations int
	}{[]byte("salt1234"), 2048})}}
	cipher := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, Parameters: asn1.RawValue{FullBytes: marshalFixture(t, make([]byte, 16))}}
	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}, Parameters: asn1.RawValue{FullBytes: marshalFixture(t, struct {
		KDF, Cipher pkix.AlgorithmIdentifier
	}{kdf, cipher})}}
	encrypted := marshalFixture(t, struct {
		Algorithm     pkix.AlgorithmIdentifier
		EncryptedData []byte
	}{algorithm, bytes.Repeat([]byte{0x42}, 32)})
	value := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encrypted})
	if Validate([]byte(metadataFixture), der, value, expected, ownerFixture) == nil {
		t.Fatal("accepted encrypted PKCS#8 envelope")
	}
	// Positive control: the underlying synthetic source/key pair is valid.
	if err := Validate([]byte(metadataFixture), der, key, expected, ownerFixture); err != nil {
		t.Fatal(err)
	}
}

func TestUnhandledCriticalCAExtensionRejected(t *testing.T) {
	for _, critical := range []bool{false, true} {
		der, key, expected := fixture(t, edKey(t), func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 2}, Critical: critical, Value: []byte{5, 0}}}
		})
		err := Validate([]byte(metadataFixture), der, key, expected, ownerFixture)
		if (err == nil) == critical {
			t.Fatalf("critical=%t: %v", critical, err)
		}
	}
}
