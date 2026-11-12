package desiredauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var ErrDomainUnverifiable = errors.New("desired-state authority domain: identity unavailable or changed")
var domainDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var domainNamePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

// DomainBinding values must be pinned by a separately trusted platform.
type DomainBinding struct {
	Endpoint string
	TrustDigest string
	ClusterUID string
	AuthorityNamespace string
	NamespaceUID string
	FenceName string
	FenceUID string
	FenceResourceVersion string
	ExpectedDomainDigest string
}

// A metadata-only RV change cannot establish a new authority incarnation.
func (b DomainBinding) DomainIdentity() (string, error) {
	u, err := url.Parse(b.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" ||
		u.ForceQuery || u.RawPath != "" {
		return "", ErrDomainUnverifiable
	}
	if !domainDigestPattern.MatchString(b.TrustDigest) ||
		!domainNamePattern.MatchString(b.AuthorityNamespace) ||
		!domainNamePattern.MatchString(b.FenceName) ||
		b.AuthorityNamespace == "default" || strings.HasPrefix(b.AuthorityNamespace, "kube-") ||
		!safeDomainID(b.ClusterUID) || !safeDomainID(b.NamespaceUID) ||
		!safeDomainID(b.FenceUID) || !safeDomainID(b.FenceResourceVersion) {
		return "", ErrDomainUnverifiable
	}
	raw, err := json.Marshal(struct {
		Version, Endpoint, TrustDigest, ClusterUID, Namespace, NamespaceUID, FenceName, FenceUID string
	}{
		Version:"openkubes-desired-authority-domain/v1",Endpoint:b.Endpoint,
		TrustDigest:b.TrustDigest,ClusterUID:b.ClusterUID,
		Namespace:b.AuthorityNamespace,NamespaceUID:b.NamespaceUID,
		FenceName:b.FenceName,FenceUID:b.FenceUID,
	})
	if err != nil { return "", ErrDomainUnverifiable }
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func safeDomainID(s string) bool {
	if len(s)==0 || len(s)>256 || strings.TrimSpace(s)!=s {return false}
	for _, r := range s { if r<33 || r==127 {return false} }
	return true
}

type DomainObject struct {
	Name string
	Namespace string
	UID string
	ResourceVersion string
	Deleting bool
	OwnerReferences bool
}
type FenceObject struct {
	DomainObject
	Immutable bool
	Format string
	State string
	NamespaceUID string
	DomainDigest string
}

// The future API adapter is responsible for strict parsing, pinned HTTPS trust
// and scoped credentials. A caller-supplied observation is NOT a policy grant.
type DomainReader interface {
	ReadNamespace(context.Context,string)(DomainObject,error)
	ReadFence(context.Context,string,string)(FenceObject,error)
}

// VerifyDomain is a point-in-time read-only verification, not an anti-delete
// guarantee or authorization to create an absent desired-state record.
func VerifyDomain(ctx context.Context,b DomainBinding,reader DomainReader) error {
	if reader==nil {return ErrDomainUnverifiable}
	derived,err:=b.DomainIdentity()
	if err!=nil || derived!=b.ExpectedDomainDigest {return ErrDomainUnverifiable}
	cluster,err:=reader.ReadNamespace(ctx,"kube-system")
	if err!=nil || cluster.Name!="kube-system" || cluster.Namespace!="" ||
		cluster.UID!=b.ClusterUID || cluster.Deleting || cluster.OwnerReferences ||
		!safeDomainID(cluster.ResourceVersion) {return ErrDomainUnverifiable}
	ns,err:=reader.ReadNamespace(ctx,b.AuthorityNamespace)
	if err!=nil || ns.Name!=b.AuthorityNamespace || ns.Namespace!="" ||
		ns.UID!=b.NamespaceUID || ns.Deleting || ns.OwnerReferences ||
		!safeDomainID(ns.ResourceVersion) {return ErrDomainUnverifiable}
	fence,err:=reader.ReadFence(ctx,b.AuthorityNamespace,b.FenceName)
	if err!=nil || fence.Name!=b.FenceName || fence.Namespace!=b.AuthorityNamespace ||
		fence.UID!=b.FenceUID || fence.ResourceVersion!=b.FenceResourceVersion ||
		fence.Deleting || fence.OwnerReferences || !fence.Immutable ||
		fence.Format!="openkubes-desired-authority-fence/v1" || fence.State!="ACTIVE" ||
		fence.NamespaceUID!=b.NamespaceUID || fence.DomainDigest!=derived {
		return ErrDomainUnverifiable
	}
	return nil
}

// Read-only bracketing is NOT a transactional write fence; ABA and deletion
// between checks require server-side admission plus protected history.
func VerifyStableRead(ctx context.Context,b DomainBinding,reader DomainReader,read func(context.Context)error)error{
	if read==nil || VerifyDomain(ctx,b,reader)!=nil {return ErrDomainUnverifiable}
	readErr:=read(ctx)
	if VerifyDomain(ctx,b,reader)!=nil || readErr!=nil {return ErrDomainUnverifiable}
	return nil
}
