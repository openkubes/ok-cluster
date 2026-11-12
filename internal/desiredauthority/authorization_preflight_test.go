package desiredauthority

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func signedAuthorizationFixture(t *testing.T)(SignedAuthorization, Transition, AuthorizationTrust,time.Time){
	t.Helper()
	seed:=sha256.Sum256([]byte("openkubes-authority-authorization-test-seed/v1"))
	private:=ed25519.NewKeyFromSeed(seed[:])
	domain:="sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	trust:=AuthorizationTrust{DomainDigest:domain,Audience:"ok226-authority-cas-v1",KeyID:"policy-signer-1",PublicKey:private.Public().(ed25519.PublicKey)}
	transition:=request()
	now:=time.Unix(1_800_000_000,0)
	statement:=AuthorizationStatement{Version:authorizationStatementVersion,DomainDigest:domain,Audience:trust.Audience,KeyID:trust.KeyID,Nonce:"nonce-unique-1",IssuedAt:now.Unix()-10,ExpiresAt:now.Unix()+120,Transition:transition}
	payload,err:=CanonicalAuthorization(statement)
	if err!=nil{t.Fatal(err)}
	return SignedAuthorization{Statement:statement,Signature:ed25519.Sign(private,payload)},transition,trust,now
}

func TestSignedAuthorizationValidOfflinePreflight(t *testing.T){
	a,tr,trust,now:=signedAuthorizationFixture(t)
	if err:=VerifyAuthorization(a,tr,trust.DomainDigest,trust,now);err!=nil{t.Fatal(err)}
	digest,err:=AuthorizationStatementDigest(a.Statement)
	if err!=nil||!EqualAuthorizationDigest(digest,digest){t.Fatal("bad correlation digest",err)}
}

func TestSignedAuthorizationRejectsTampering(t *testing.T){
	cases:=[]struct{name string;mutate func(*SignedAuthorization,*Transition,*AuthorizationTrust,*time.Time)}{
		{"changed tenant",func(_ *SignedAuthorization,tr *Transition,_ *AuthorizationTrust,_ *time.Time){tr.Tenant="team-b"}},
		{"changed request",func(_ *SignedAuthorization,tr *Transition,_ *AuthorizationTrust,_ *time.Time){tr.RequestDigest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}},
		{"changed execution binding",func(_ *SignedAuthorization,tr *Transition,_ *AuthorizationTrust,_ *time.Time){tr.ExecutionBindingDigest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}},
		{"changed authorization digest",func(_ *SignedAuthorization,tr *Transition,_ *AuthorizationTrust,_ *time.Time){tr.AuthorizationDigest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}},
		{"changed transition id",func(_ *SignedAuthorization,tr *Transition,_ *AuthorizationTrust,_ *time.Time){tr.TransitionID="other"}},
		{"changed key id",func(a *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,_ *time.Time){a.Statement.KeyID="different"}},
		{"changed domain",func(a *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,_ *time.Time){a.Statement.DomainDigest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}},
		{"changed audience",func(a *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,_ *time.Time){a.Statement.Audience="another-executor"}},
		{"changed nonce",func(a *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,_ *time.Time){a.Statement.Nonce="other"}},
		{"altered signature",func(a *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,_ *time.Time){a.Signature[0]^=1}},
		{"expired",func(_ *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,now *time.Time){*now=now.Add(5*time.Minute)}},
		{"future issue",func(_ *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,now *time.Time){*now=now.Add(-time.Minute)}},
		{"wrong pinned key",func(_ *SignedAuthorization,_ *Transition,trust *AuthorizationTrust,_ *time.Time){trust.PublicKey=make([]byte,ed25519.PublicKeySize)}},
		{"wrong trusted audience",func(_ *SignedAuthorization,_ *Transition,trust *AuthorizationTrust,_ *time.Time){trust.Audience="other"}},
		{"missing signature",func(a *SignedAuthorization,_ *Transition,_ *AuthorizationTrust,_ *time.Time){a.Signature=nil}},
	}
	for _,tc:=range cases{
		t.Run(tc.name,func(t *testing.T){
			a,tr,trust,now:=signedAuthorizationFixture(t)
			tc.mutate(&a,&tr,&trust,&now)
			if err:=VerifyAuthorization(a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrAuthorizationUnverifiable){t.Fatalf("unexpected pass: %v",err)}
		})
	}
}

func TestSignedAuthorizationRejectsUnsupportedAndOverlong(t *testing.T){
	a,tr,trust,now:=signedAuthorizationFixture(t)
	tr.Operation="DeleteCluster"
	if err:=VerifyAuthorization(a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrAuthorizationUnverifiable){t.Fatal(err)}
	a,tr,trust,now=signedAuthorizationFixture(t)
	a.Statement.ExpiresAt=a.Statement.IssuedAt+3600
	if err:=VerifyAuthorization(a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrAuthorizationUnverifiable){t.Fatal(err)}
}

func TestSignatureDoesNotConsumeOrReserveNonce(t *testing.T){
	a,tr,trust,now:=signedAuthorizationFixture(t)
	for i:=0;i<2;i++ {
		if err:=VerifyAuthorization(a,tr,trust.DomainDigest,trust,now);err!=nil{t.Fatal(err)}
	}
	// This confirms an intentionally read-only preflight; replay prevention
	// MUST be independently enforced by a server-side single-use claim.
}
