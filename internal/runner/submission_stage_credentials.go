package runner

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/digest"
)

const (
	SubmissionStageCredentialPackageFormat = "ok147-submission-stage-credential-package/v1"
	minimumStageCredentialRemaining        = 15 * time.Minute
	maximumStageCredentialLifetime         = time.Hour
	maximumStageCredentialObjectBytes      = 128 * 1024
)

// SubmissionStageCredentialSource binds one externally obtained TokenRequest
// result without embedding any credential in a caller-visible receipt.
type SubmissionStageCredentialSource struct {
	AuthorityIdentity          string
	TokenFile                  string
	TokenDigest                string
	CAFile                     string
	CABundleDigest             string
	TokenRequestEvidenceDigest string
	ExpectedIssuer             string
	ExpectedSubject            string
	ExpectedAudiences          []string
	IssuedAt                   time.Time
	ExpiresAt                  time.Time
}

type SubmissionStageCredentialPackageConfig struct {
	Package             VerifiedSubmissionStagePackage
	MaterializationTime time.Time
	Ledger              SubmissionStageCredentialSource
	SelectedAuthority   SubmissionStageCredentialSource
}

type SubmissionStageCredentialObjectReceipt struct {
	Role                       string   `json:"role"`
	Authority                  string   `json:"authority"`
	Namespace                  string   `json:"namespace"`
	Name                       string   `json:"name"`
	ExpiresAt                  string   `json:"expiresAt"`
	Audiences                  []string `json:"audiences"`
	CABundleDigest             string   `json:"caBundleDigest"`
	TokenRequestEvidenceDigest string   `json:"tokenRequestEvidenceDigest"`
	ObjectDigest               string   `json:"objectDigest"`
}

// SubmissionStageCredentialPackageReceipt contains no token, CA, subject or
// source path. ObjectDigest binds the private exact Secret object.
type SubmissionStageCredentialPackageReceipt struct {
	Format                string                                   `json:"format"`
	State                 string                                   `json:"state"`
	StageID               string                                   `json:"stageId"`
	StagePackageDigest    string                                   `json:"stagePackageDigest"`
	InstallationAuthority string                                   `json:"installationAuthority"`
	MaterializedAt        string                                   `json:"materializedAt"`
	PackageDigest         string                                   `json:"packageDigest"`
	Credentials           []SubmissionStageCredentialObjectReceipt `json:"credentials"`
	MutationAllowed       bool                                     `json:"mutationAllowed"`
}

type submissionStageCredentialObject struct {
	role      string
	authority string
	name      string
	raw       []byte
}

type submissionStageCredentialPackageIdentity struct {
	StagePackageDigest    string                                   `json:"stagePackageDigest"`
	InstallationAuthority string                                   `json:"installationAuthority"`
	MaterializedAt        string                                   `json:"materializedAt"`
	Credentials           []SubmissionStageCredentialObjectReceipt `json:"credentials"`
}

// VerifiedSubmissionStageCredentialPackage deliberately exposes only its
// redaction-safe receipt. Secret bytes stay in-package for the later exact
// installer boundary.
type VerifiedSubmissionStageCredentialPackage struct {
	objects               []submissionStageCredentialObject
	receipt               SubmissionStageCredentialPackageReceipt
	installationAuthority string
	verified              bool
}

type submissionStageTokenClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt json.Number     `json:"exp"`
	IssuedAt  json.Number     `json:"iat"`
	NotBefore json.Number     `json:"nbf"`
}

// BuildSubmissionStageCredentialPackage reads two bounded TokenRequest/CA
// sources and creates two private immutable Secret objects. It performs no
// Kubernetes request and has no method that exposes the Secret bytes.
func BuildSubmissionStageCredentialPackage(config SubmissionStageCredentialPackageConfig) (VerifiedSubmissionStageCredentialPackage, error) {
	stagePlan, err := PlanSubmissionStageInstallation(config.Package)
	if err != nil {
		return VerifiedSubmissionStageCredentialPackage{}, err
	}
	if config.MaterializationTime.IsZero() || !config.MaterializationTime.Equal(config.MaterializationTime.Truncate(time.Second)) {
		return VerifiedSubmissionStageCredentialPackage{}, errors.New("stage credential materialization time is required")
	}
	materializedAt := config.MaterializationTime.UTC().Format(time.RFC3339)
	bindings := []struct {
		role      string
		name      string
		authority string
		source    SubmissionStageCredentialSource
	}{
		{role: "ledger", name: config.Package.ledgerCredential, authority: config.Package.ledgerAuthority, source: config.Ledger},
		{role: "authority", name: config.Package.selectedCredential, authority: config.Package.selectedAuthority, source: config.SelectedAuthority},
	}
	objects := make([]submissionStageCredentialObject, 0, len(bindings))
	receipts := make([]SubmissionStageCredentialObjectReceipt, 0, len(bindings))
	tokens := make([][]byte, 0, len(bindings))
	for _, binding := range bindings {
		object, objectReceipt, token, err := buildSubmissionStageCredentialObject(stagePlan.StageID, config.MaterializationTime.UTC(), binding.role, binding.name, binding.authority, binding.source)
		if err != nil {
			return VerifiedSubmissionStageCredentialPackage{}, err
		}
		objects = append(objects, object)
		receipts = append(receipts, objectReceipt)
		tokens = append(tokens, token)
	}
	if len(tokens[0]) == len(tokens[1]) && subtle.ConstantTimeCompare(tokens[0], tokens[1]) == 1 {
		return VerifiedSubmissionStageCredentialPackage{}, errors.New("stage ledger and authority credentials must be distinct")
	}
	packageIdentity, err := json.Marshal(submissionStageCredentialPackageIdentity{
		StagePackageDigest: stagePlan.PackageDigest, InstallationAuthority: config.Package.installationAuthority,
		MaterializedAt: materializedAt, Credentials: receipts,
	})
	if err != nil {
		return VerifiedSubmissionStageCredentialPackage{}, errors.New("encode stage credential package identity")
	}
	receipt := SubmissionStageCredentialPackageReceipt{
		Format: SubmissionStageCredentialPackageFormat, State: "VERIFIED", StageID: stagePlan.StageID,
		StagePackageDigest: stagePlan.PackageDigest, InstallationAuthority: config.Package.installationAuthority,
		MaterializedAt: materializedAt, PackageDigest: digest.SHA256(packageIdentity),
		Credentials: receipts, MutationAllowed: false,
	}
	return VerifiedSubmissionStageCredentialPackage{
		objects: cloneStageCredentialObjects(objects), receipt: receipt,
		installationAuthority: config.Package.installationAuthority, verified: true,
	}, nil
}

func (packaged VerifiedSubmissionStageCredentialPackage) Receipt() (SubmissionStageCredentialPackageReceipt, error) {
	if !packaged.verified || packaged.receipt.State != "VERIFIED" || len(packaged.objects) != 2 {
		return SubmissionStageCredentialPackageReceipt{}, errors.New("stage credential package was not produced by verification")
	}
	receipt := packaged.receipt
	receipt.Credentials = append([]SubmissionStageCredentialObjectReceipt(nil), packaged.receipt.Credentials...)
	for index := range receipt.Credentials {
		receipt.Credentials[index].Audiences = append([]string(nil), packaged.receipt.Credentials[index].Audiences...)
	}
	return receipt, nil
}

func buildSubmissionStageCredentialObject(stageID string, now time.Time, role, name, authority string, source SubmissionStageCredentialSource) (submissionStageCredentialObject, SubmissionStageCredentialObjectReceipt, []byte, error) {
	if source.AuthorityIdentity != authority || authority == "" {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, errors.New("stage credential authority differs from verified package")
	}
	if !submissionStageInputNamePattern.MatchString(name) || len(name) > 63 || source.TokenFile == "" || source.CAFile == "" {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, errors.New("stage credential object or source identity is invalid")
	}
	if !stageReceiptPrefixDigestPattern.MatchString(source.TokenDigest) || !stageReceiptPrefixDigestPattern.MatchString(source.CABundleDigest) || !stageReceiptPrefixDigestPattern.MatchString(source.TokenRequestEvidenceDigest) {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, errors.New("stage credential source digest is invalid")
	}
	token, err := readBoundedRegular(source.TokenFile, maximumTokenBytes)
	if err != nil || digest.SHA256(token) != source.TokenDigest {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, errors.New("stage credential token differs from bound source")
	}
	ca, err := readBoundedRegular(source.CAFile, maximumCABytes)
	if err != nil || digest.SHA256(ca) != source.CABundleDigest || !validStageCredentialCA(ca, now) {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, errors.New("stage credential CA differs from bound source")
	}
	claims, err := verifyStageCredentialJWT(token, source, now)
	if err != nil {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, err
	}
	audiences, err := tokenAudiences(claims.Audience)
	if err != nil {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, err
	}
	secret := map[string]any{
		"apiVersion": "v1", "kind": "Secret", "immutable": true, "type": "Opaque",
		"metadata": map[string]any{
			"name": name, "namespace": submissionStageInputNamespace,
			"labels": map[string]any{
				"app.kubernetes.io/name": "ok-cluster-contract-executor",
				"openkubes.io/stage-id":  stageID, "openkubes.io/credential-role": role,
			},
			"annotations": map[string]any{
				"openkubes.io/authority-identity": authority,
				"openkubes.io/expires-at":         source.ExpiresAt.UTC().Format(time.RFC3339),
			},
		},
		"data": map[string]any{
			"token":  base64.StdEncoding.EncodeToString(token),
			"ca.crt": base64.StdEncoding.EncodeToString(ca),
		},
	}
	raw, err := json.Marshal(secret)
	if err != nil || len(raw) > maximumStageCredentialObjectBytes {
		return submissionStageCredentialObject{}, SubmissionStageCredentialObjectReceipt{}, nil, errors.New("stage credential Secret exceeds accepted size")
	}
	object := submissionStageCredentialObject{role: role, authority: authority, name: name, raw: raw}
	receipt := SubmissionStageCredentialObjectReceipt{
		Role: role, Authority: authority, Namespace: submissionStageInputNamespace, Name: name,
		ExpiresAt: source.ExpiresAt.UTC().Format(time.RFC3339), Audiences: audiences,
		CABundleDigest: source.CABundleDigest, TokenRequestEvidenceDigest: source.TokenRequestEvidenceDigest,
		ObjectDigest: digest.SHA256(raw),
	}
	return object, receipt, append([]byte(nil), token...), nil
}

func verifyStageCredentialJWT(token []byte, source SubmissionStageCredentialSource, now time.Time) (submissionStageTokenClaims, error) {
	return verifyStageCredentialJWTWithSubject(token, source, now, validStageCredentialSubject)
}

func verifyStageCredentialJWTWithSubject(token []byte, source SubmissionStageCredentialSource, now time.Time, subjectAllowed func(string) bool) (submissionStageTokenClaims, error) {
	if subjectAllowed == nil {
		return submissionStageTokenClaims{}, errors.New("stage credential subject policy is missing")
	}
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return submissionStageTokenClaims{}, errors.New("stage credential token is not a signed JWT")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT header is invalid")
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil || header.Algorithm != "RS256" && header.Algorithm != "ES256" {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT algorithm is not accepted")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) < 32 {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT signature encoding is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT payload is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims submissionStageTokenClaims
	if err := decoder.Decode(&claims); err != nil {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT claims are invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT claims contain trailing data")
	}
	issuedAt, err := exactJWTUnix(claims.IssuedAt)
	if err != nil {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT issued-at claim is invalid")
	}
	expiresAt, err := exactJWTUnix(claims.ExpiresAt)
	if err != nil {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT expiration claim is invalid")
	}
	notBefore, err := exactJWTUnix(claims.NotBefore)
	if err != nil {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT not-before claim is invalid")
	}
	if source.ExpectedIssuer == "" || claims.Issuer != source.ExpectedIssuer || source.ExpectedSubject == "" || claims.Subject != source.ExpectedSubject || !subjectAllowed(claims.Subject) {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT issuer or subject differs from bound source")
	}
	audiences, err := tokenAudiences(claims.Audience)
	if err != nil || !equalAudienceSet(audiences, source.ExpectedAudiences) {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT audiences differ from bound source")
	}
	issued := time.Unix(issuedAt, 0).UTC()
	expires := time.Unix(expiresAt, 0).UTC()
	if source.IssuedAt.IsZero() || source.ExpiresAt.IsZero() || !source.IssuedAt.Equal(source.IssuedAt.Truncate(time.Second)) || !source.ExpiresAt.Equal(source.ExpiresAt.Truncate(time.Second)) || !issued.Equal(source.IssuedAt) || !expires.Equal(source.ExpiresAt) || notBefore != issuedAt {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT time claims differ from bound source")
	}
	if now.Before(issued) || expires.Sub(now) < minimumStageCredentialRemaining || expires.Sub(issued) > maximumStageCredentialLifetime || !expires.After(issued) {
		return submissionStageTokenClaims{}, errors.New("stage credential JWT is outside the accepted short-lived window")
	}
	return claims, nil
}

func exactJWTUnix(value json.Number) (int64, error) {
	if value == "" || strings.ContainsAny(string(value), ".eE") {
		return 0, errors.New("JWT time is not an integer")
	}
	return strconv.ParseInt(string(value), 10, 64)
}

func tokenAudiences(raw json.RawMessage) ([]string, error) {
	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err != nil {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil || single == "" {
			return nil, errors.New("stage credential JWT audience claim is invalid")
		}
		multiple = []string{single}
	}
	if len(multiple) == 0 {
		return nil, errors.New("stage credential JWT audience claim is empty")
	}
	result := append([]string(nil), multiple...)
	sort.Strings(result)
	for index, audience := range result {
		if audience == "" || strings.TrimSpace(audience) != audience || index > 0 && audience == result[index-1] {
			return nil, errors.New("stage credential JWT audience claim is invalid")
		}
	}
	return result, nil
}

func equalAudienceSet(actual, expected []string) bool {
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if len(actual) != len(want) || len(want) == 0 {
		return false
	}
	for index := range actual {
		if want[index] == "" || strings.TrimSpace(want[index]) != want[index] || index > 0 && want[index] == want[index-1] || actual[index] != want[index] {
			return false
		}
	}
	return true
}

func validStageCredentialSubject(subject string) bool {
	const prefix = "system:serviceaccount:" + submissionStageInputNamespace + ":"
	name := strings.TrimPrefix(subject, prefix)
	return name != subject && submissionStageInputNamePattern.MatchString(name) && len(name) <= 63
}

func validStageCredentialCA(raw []byte, now time.Time) bool {
	found := false
	remaining := bytes.TrimSpace(raw)
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return false
		}
		remaining = bytes.TrimSpace(rest)
		if block.Type != "CERTIFICATE" {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return false
		}
		found = true
	}
	return found
}

func cloneStageCredentialObjects(objects []submissionStageCredentialObject) []submissionStageCredentialObject {
	result := append([]submissionStageCredentialObject(nil), objects...)
	for index := range result {
		result[index].raw = append([]byte(nil), objects[index].raw...)
	}
	return result
}
