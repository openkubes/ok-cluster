package desiredauthority

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "time"
)

// Single-use claims are distinct from both OK-147 bootstrap issuer claims and
// desired-state CAS acceptance. This contract has NO Kubernetes or executor wiring.
var ErrClaimUnverifiable = errors.New("desired-state authority: single-use claim unverifiable")
var ErrClaimConsumed = errors.New("desired-state authority: authorization claim slot consumed")

const claimRecordVersion = "openkubes-authority-single-use-claim/v1"

type ClaimRecord struct {
 Version string
 SlotDigest string
 StatementDigest string
 SignatureDigest string
 DomainDigest string
 Audience string
 KeyID string
 Nonce string
 Transition Transition
 ClaimedAt int64
}

type ClaimWriteOutcome string
const (
 ClaimCreated ClaimWriteOutcome = "CREATED"
 ClaimConflict ClaimWriteOutcome = "CONFLICT"
 ClaimIndeterminate ClaimWriteOutcome = "INDETERMINATE"
)

// ClaimStore MUST enforce permanent no-reuse of a domain-scoped slot via
// atomic, linearizable create-if-absent. Missing records are NOT proof of
// trustworthy history; deployment anti-delete, fencing and restore rules
// remain separate mandatory activation gates.
type ClaimStore interface {
 CreateIfAbsent(context.Context,string,ClaimRecord)(ClaimWriteOutcome,error)
 InspectClaim(context.Context,string)(ClaimRecord,bool,error)
}

// ClaimSlotDigest binds a nonce to its domain, intended audience and key ID.
// A different signed statement with the same nonce MUST collide at one slot.
func ClaimSlotDigest(s AuthorizationStatement)(string,error){
 if _,err:=CanonicalAuthorization(s);err!=nil{return "",ErrClaimUnverifiable}
 raw,err:=json.Marshal(struct{Version,Domain,Audience,KeyID,Nonce string}{
  claimRecordVersion,s.DomainDigest,s.Audience,s.KeyID,s.Nonce,
 })
 if err!=nil{return "",ErrClaimUnverifiable}
 sum:=sha256.Sum256(raw)
 return "sha256:"+hex.EncodeToString(sum[:]),nil
}

func ProposedClaim(a SignedAuthorization, t Transition, domain string, trust AuthorizationTrust, now time.Time)(ClaimRecord,error){
 if VerifyAuthorization(a,t,domain,trust,now)!=nil{return ClaimRecord{},ErrClaimUnverifiable}
 slot,err:=ClaimSlotDigest(a.Statement)
 if err!=nil{return ClaimRecord{},ErrClaimUnverifiable}
 statement,err:=AuthorizationStatementDigest(a.Statement)
 if err!=nil{return ClaimRecord{},ErrClaimUnverifiable}
 signature:=sha256.Sum256(a.Signature)
 return ClaimRecord{
  Version:claimRecordVersion,SlotDigest:slot,StatementDigest:statement,
  SignatureDigest:"sha256:"+hex.EncodeToString(signature[:]),
  DomainDigest:domain,Audience:a.Statement.Audience,KeyID:a.Statement.KeyID,
  Nonce:a.Statement.Nonce,Transition:t,ClaimedAt:now.Unix(),
 },nil
}

func validateClaimRecord(c ClaimRecord)bool{
 if c.Version!=claimRecordVersion||!digestPattern.MatchString(c.SlotDigest)||
 !digestPattern.MatchString(c.StatementDigest)||!digestPattern.MatchString(c.SignatureDigest)||
 !digestPattern.MatchString(c.DomainDigest)||c.Audience==""||c.KeyID==""||
 c.Nonce==""||c.ClaimedAt<=0||c.Transition.Validate()!=nil||c.Transition.Operation!="CreateCluster" {return false}
 s:=AuthorizationStatement{Version:authorizationStatementVersion,DomainDigest:c.DomainDigest,
  Audience:c.Audience,KeyID:c.KeyID,Nonce:c.Nonce,IssuedAt:1,ExpiresAt:2,Transition:c.Transition}
 // Slot validation requires only immutable identity fields, not signed times.
 slot,err:=ClaimSlotDigest(s)
 return err==nil&&slot==c.SlotDigest
}

// ClaimOnce always rejects an already occupied slot, including an IDENTICAL
// replay. A failed or ambiguous create NEVER grants a usable claim.
// An authoritative protected Store is mandatory; only fake stores are supplied.
func ClaimOnce(ctx context.Context,store ClaimStore,a SignedAuthorization,t Transition,
 domain string,trust AuthorizationTrust,now time.Time)(ClaimRecord,error){
 if store==nil{return ClaimRecord{},ErrClaimUnverifiable}
 proposed,err:=ProposedClaim(a,t,domain,trust,now)
 if err!=nil{return ClaimRecord{},err}
 outcome,err:=store.CreateIfAbsent(ctx,proposed.SlotDigest,proposed)
 if err!=nil{return ClaimRecord{},ErrClaimUnverifiable}
 switch outcome{
 case ClaimCreated: return proposed,nil
 case ClaimConflict: return ClaimRecord{},ErrClaimConsumed
 default: return ClaimRecord{},ErrClaimUnverifiable
 }
}

// InspectClaimAttempt provides read-only evidence after ambiguous creation.
// Exact record correlation indicates slot consumption, NEVER a new execution
// entitlement; callers MUST NOT call ClaimOnce again after uncertainty.
func InspectClaimAttempt(ctx context.Context,store ClaimStore,attempt ClaimRecord)(ClaimRecord,error){
 if store==nil||!validateClaimRecord(attempt){return ClaimRecord{},ErrClaimUnverifiable}
 stored,exists,err:=store.InspectClaim(ctx,attempt.SlotDigest)
 if err!=nil||!exists||!validateClaimRecord(stored)||stored!=attempt{
  return ClaimRecord{},ErrClaimUnverifiable
 }
 return stored,nil
}
