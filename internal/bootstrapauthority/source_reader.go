package bootstrapauthority

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/openkubes/ok-cluster/internal/bootstrapcheck"
	"github.com/openkubes/ok-cluster/internal/issuersourcecheck"
	"github.com/openkubes/ok-cluster/internal/jsonstrict"
)

const maximumSourceSecretBytes = 1024 * 1024

// SourceMetadataGetter and SourceSecretGetter are trusted, fixed platform
// adapters. The first must issue a PartialObjectMetadata-only GET with no full
// Secret fallback; the second must issue one exact Secret GET. Neither adapter
// may add application-level retries, log response bodies, follow redirects, or
// discover credentials. HTTP stacks may transparently retry idempotent GETs.
type SourceMetadataGetter func(context.Context, string, string) ([]byte, error)
type SourceSecretGetter func(context.Context, string, string) ([]byte, error)

// KubernetesSourceReaderConfig is platform-owner configuration, never a caller
// wire type. All identity, data-key, type, format and API adapters are explicit.
type KubernetesSourceReaderConfig struct {
	Expected            bootstrapcheck.Binding
	Owner               bootstrapcheck.SourceOwner
	SecretType          string
	CertificateDataKey  string
	PrivateKeyDataKey   string
	CertificateEncoding string // exactly "DER" or "PEM"
	ReadMetadata        SourceMetadataGetter
	ReadSecret          SourceSecretGetter
}

// KubernetesSourceReader performs two fixed GET reads and requires them to
// identify the same exact source UID/resourceVersion. It returns source bytes
// only to the trusted in-process issuer task; errors never contain API details.
type KubernetesSourceReader struct {
	config KubernetesSourceReaderConfig
}

func NewKubernetesSourceReader(config KubernetesSourceReaderConfig) (*KubernetesSourceReader, error) {
	if _, err := bootstrapcheck.SlotDigest(config.Expected); err != nil || config.Owner.Name == "" || len(config.Owner.Name) > 253 ||
		config.Owner.Name != strings.TrimSpace(config.Owner.Name) ||
		(config.Owner.APIVersion != "cluster.x-k8s.io/v1beta1" && config.Owner.APIVersion != "cluster.x-k8s.io/v1beta2") ||
		!safeDataKey(config.CertificateDataKey) || !safeDataKey(config.PrivateKeyDataKey) || config.CertificateDataKey == config.PrivateKeyDataKey ||
		(config.CertificateEncoding != "DER" && config.CertificateEncoding != "PEM") || config.SecretType == "" || len(config.SecretType) > 128 ||
		config.ReadMetadata == nil || config.ReadSecret == nil {
		return nil, errors.New("explicit issuer source-reader configuration required")
	}
	return &KubernetesSourceReader{config: config}, nil
}

// ReadSource matches ObserverTaskConfig.ReadSource. The requested binding is
// compared to trusted configuration before either adapter is called.
func (reader *KubernetesSourceReader) ReadSource(ctx context.Context, requested bootstrapcheck.Binding) (ObserverTaskSource, error) {
	if reader == nil || ctx == nil || ctx.Err() != nil || requested != reader.config.Expected {
		return ObserverTaskSource{}, ErrStop
	}
	c := reader.config
	metadata, err := c.ReadMetadata(ctx, c.Expected.SourceNamespace, c.Expected.SourceName)
	if err != nil || len(metadata) == 0 || len(metadata) > 256*1024 || bootstrapcheck.ValidateSourceMetadata(metadata, c.Expected, c.Owner) != nil {
		return ObserverTaskSource{}, ErrStop
	}
	if ctx.Err() != nil {
		return ObserverTaskSource{}, ErrStop
	}
	secretRaw, err := c.ReadSecret(ctx, c.Expected.SourceNamespace, c.Expected.SourceName)
	defer clear(secretRaw)
	if err != nil || len(secretRaw) == 0 || len(secretRaw) > maximumSourceSecretBytes {
		return ObserverTaskSource{}, ErrStop
	}
	secret, err := decodeSourceSecret(secretRaw)
	if err != nil || secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Type != c.SecretType || secret.Data == nil || secret.Immutable != nil && !*secret.Immutable {
		return ObserverTaskSource{}, ErrStop
	}
	secretMetadata, err := metadataOnlyEnvelope(secret.Metadata)
	if err != nil || bootstrapcheck.ValidateSourceMetadata(secretMetadata, c.Expected, c.Owner) != nil || !sameSourceObjectMetadata(metadata, secretMetadata) {
		return ObserverTaskSource{}, ErrStop
	}
	if len(secret.Data) != 2 {
		return ObserverTaskSource{}, ErrStop
	}
	certificateRaw, okCert := secret.Data[c.CertificateDataKey]
	privateKeyRaw, okKey := secret.Data[c.PrivateKeyDataKey]
	if !okCert || !okKey {
		return ObserverTaskSource{}, ErrStop
	}
	certificateBytes, certErr := decodeSecretBytes(certificateRaw, 65536)
	privateKeyBytes, keyErr := decodeSecretBytes(privateKeyRaw, 16384)
	defer clear(certificateBytes)
	defer clear(privateKeyBytes)
	certificateDER, err := decodeSourceCertificate(certificateBytes, c.CertificateEncoding)
	defer clear(certificateDER)
	if certErr != nil || keyErr != nil || err != nil || len(privateKeyBytes) == 0 || issuersourcecheck.Validate(metadata, certificateDER, privateKeyBytes, c.Expected, c.Owner) != nil {
		return ObserverTaskSource{}, ErrStop
	}
	return ObserverTaskSource{
		Metadata: append([]byte(nil), metadata...), CertificateDER: append([]byte(nil), certificateDER...),
		PrivateKeyPEM: append([]byte(nil), privateKeyBytes...),
	}, nil
}

type sourceSecretWire struct {
	APIVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   json.RawMessage            `json:"metadata"`
	Type       string                     `json:"type"`
	Immutable  *bool                      `json:"immutable"`
	Data       map[string]json.RawMessage `json:"data"`
	StringData json.RawMessage            `json:"stringData,omitempty"`
}

func decodeSourceSecret(raw []byte) (sourceSecretWire, error) {
	var secret sourceSecretWire
	if len(raw) == 0 || len(raw) > maximumSourceSecretBytes || jsonstrict.Decode(raw, &secret) != nil || len(secret.Metadata) == 0 || len(secret.StringData) != 0 {
		return sourceSecretWire{}, ErrStop
	}
	return secret, nil
}

func metadataOnlyEnvelope(metadata json.RawMessage) ([]byte, error) {
	if len(metadata) == 0 || len(metadata) > 256*1024 {
		return nil, ErrStop
	}
	value := struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Metadata   json.RawMessage `json:"metadata"`
	}{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata", Metadata: append([]byte(nil), metadata...)}
	return json.Marshal(value)
}

func sameSourceObjectMetadata(left, right []byte) bool {
	identity := func(raw []byte) (string, string, string, string, bool) {
		var envelope map[string]json.RawMessage
		if json.Unmarshal(raw, &envelope) != nil || len(envelope["metadata"]) == 0 {
			return "", "", "", "", false
		}
		var values struct {
			Name            string `json:"name"`
			Namespace       string `json:"namespace"`
			UID             string `json:"uid"`
			ResourceVersion string `json:"resourceVersion"`
		}
		if json.Unmarshal(envelope["metadata"], &values) != nil {
			return "", "", "", "", false
		}
		return values.Name, values.Namespace, values.UID, values.ResourceVersion, true
	}
	ln, lns, lu, lr, lok := identity(left)
	rn, rns, ru, rr, rok := identity(right)
	return lok && rok && ln == rn && lns == rns && lu == ru && lr == rr
}

func decodeSourceCertificate(raw []byte, encoding string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrStop
	}
	switch encoding {
	case "DER":
		if _, err := x509.ParseCertificate(raw); err != nil {
			return nil, ErrStop
		}
		return append([]byte(nil), raw...), nil
	case "PEM":
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
			bytes.Count(raw, []byte("-----BEGIN CERTIFICATE-----")) != 1 {
			return nil, ErrStop
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, ErrStop
		}
		return append([]byte(nil), block.Bytes...), nil
	default:
		return nil, ErrStop
	}
}

func decodeSecretBytes(encoded json.RawMessage, maximum int) ([]byte, error) {
	// Kubernetes Secret.data values are JSON strings containing canonical
	// standard base64. Reject JSON escapes so there is only one byte form and no
	// additional immutable string copy of the sensitive private-key value.
	if len(encoded) < 3 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' || len(encoded)-2 > base64.StdEncoding.EncodedLen(maximum) {
		return nil, ErrStop
	}
	encoded = encoded[1 : len(encoded)-1]
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(decoded, encoded)
	if err != nil || n == 0 || n > maximum {
		clear(decoded)
		return nil, ErrStop
	}
	decoded = decoded[:n]
	canonical := make([]byte, base64.StdEncoding.EncodedLen(n))
	base64.StdEncoding.Encode(canonical, decoded)
	if !bytes.Equal(canonical, encoded) {
		clear(decoded)
		clear(canonical)
		return nil, ErrStop
	}
	clear(canonical)
	return decoded, nil
}

func safeDataKey(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func encodeSecretData(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
