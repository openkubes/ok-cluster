package desiredauthority

import (
 "context"
 "errors"
 "fmt"
 "sync"
 "testing"
)

type claimMemoryStore struct {
 mu sync.Mutex
 records map[string]ClaimRecord
 loseResponse bool
 unknown bool
 unreadable bool
 writes int
}
func(s *claimMemoryStore)CreateIfAbsent(_ context.Context,slot string,c ClaimRecord)(ClaimWriteOutcome,error){
 s.mu.Lock();defer s.mu.Unlock()
 if s.unknown{return ClaimIndeterminate,errors.New("write result unknown")}
 if _,exists:=s.records[slot];exists{return ClaimConflict,nil}
 s.records[slot]=c;s.writes++
 if s.loseResponse{return ClaimIndeterminate,errors.New("response lost")}
 return ClaimCreated,nil
}
func(s *claimMemoryStore)InspectClaim(_ context.Context,slot string)(ClaimRecord,bool,error){
 s.mu.Lock();defer s.mu.Unlock()
 if s.unreadable{return ClaimRecord{},false,errors.New("read unavailable")}
 c,ok:=s.records[slot];return c,ok,nil
}

func TestClaimOnceSingleWinnerAmongConcurrentAgents(t *testing.T){
 a,tr,trust,now:=signedAuthorizationFixture(t)
 store:=&claimMemoryStore{records:map[string]ClaimRecord{}}
 const agents=40
 var wg sync.WaitGroup
 outcomes:=make(chan error,agents)
 for i:=0;i<agents;i++{wg.Add(1);go func(){
  defer wg.Done()
  _,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now)
  outcomes<-err
 }()}
 wg.Wait();close(outcomes)
 wins,consumed:=0,0
 for err:=range outcomes{switch{
 case err==nil:wins++
 case errors.Is(err,ErrClaimConsumed):consumed++
 default:t.Fatalf("unexpected outcome: %v",err)
 }}
 if wins!=1||consumed!=agents-1||store.writes!=1{t.Fatalf("wins=%d consumed=%d writes=%d",wins,consumed,store.writes)}
}
func TestExactReplayIsConsumedNotAuthorized(t *testing.T){
 a,tr,trust,now:=signedAuthorizationFixture(t)
 store:=&claimMemoryStore{records:map[string]ClaimRecord{}}
 first,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now)
 if err!=nil{t.Fatal(err)}
 if _,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrClaimConsumed){t.Fatal(err)}
 record,err:=InspectClaimAttempt(context.Background(),store,first)
 if err!=nil||record!=first||store.writes!=1{t.Fatal("readback mismatch",err)}
}
func TestUnknownWriteAndReadbackDoNotAuthorize(t *testing.T){
 a,tr,trust,now:=signedAuthorizationFixture(t)
 store:=&claimMemoryStore{records:map[string]ClaimRecord{},loseResponse:true}
 attempt,err:=ProposedClaim(a,tr,trust.DomainDigest,trust,now)
 if err!=nil{t.Fatal(err)}
 if _,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrClaimUnverifiable){t.Fatal(err)}
 if _,err:=InspectClaimAttempt(context.Background(),store,attempt);err!=nil{t.Fatal(err)}
 if _,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrClaimConsumed){t.Fatal(err)}
 if store.writes!=1{t.Fatalf("unexpected writes=%d",store.writes)}
 store.unreadable=true
 if _,err:=InspectClaimAttempt(context.Background(),store,attempt);!errors.Is(err,ErrClaimUnverifiable){t.Fatal(err)}
}
func TestUnknownNotCommittedNeverInferredAbsent(t *testing.T){
 a,tr,trust,now:=signedAuthorizationFixture(t)
 store:=&claimMemoryStore{records:map[string]ClaimRecord{},unknown:true}
 attempt,err:=ProposedClaim(a,tr,trust.DomainDigest,trust,now);if err!=nil{t.Fatal(err)}
 if _,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrClaimUnverifiable){t.Fatal(err)}
 if _,err:=InspectClaimAttempt(context.Background(),store,attempt);!errors.Is(err,ErrClaimUnverifiable){t.Fatal(err)}
 if store.writes!=0{t.Fatalf("unexpected writes=%d",store.writes)}
}
func TestClaimSlotCollisionsAndScopeIsolation(t *testing.T){
 a,tr,trust,now:=signedAuthorizationFixture(t)
 store:=&claimMemoryStore{records:map[string]ClaimRecord{}}
 if _,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now);err!=nil{t.Fatal(err)}
 other:=a.Statement
 other.Transition.TransitionID="different"
 slot1,err:=ClaimSlotDigest(a.Statement);if err!=nil{t.Fatal(err)}
 slot2,err:=ClaimSlotDigest(other);if err!=nil{t.Fatal(err)}
 if slot1!=slot2{t.Fatal("changed transition bypassed nonce slot")}
 other.Nonce="different-nonce"
 slot3,err:=ClaimSlotDigest(other);if err!=nil{t.Fatal(err)}
 if slot3==slot1{t.Fatal("different nonce collided")}
 for _,change:=range []func(*AuthorizationStatement){
  func(s *AuthorizationStatement){s.DomainDigest="sha256:"+fmt.Sprintf("%064x",12)},
  func(s *AuthorizationStatement){s.Audience="other-audience"},
  func(s *AuthorizationStatement){s.KeyID="other-key"},
 }{
  next:=a.Statement;change(&next)
  slot,err:=ClaimSlotDigest(next)
  if err!=nil||slot==slot1{t.Fatalf("slot not separated: %s %v",slot,err)}
 }
}
func TestClaimBadSignatureCannotConsumeSlot(t *testing.T){
 a,tr,trust,now:=signedAuthorizationFixture(t)
 store:=&claimMemoryStore{records:map[string]ClaimRecord{}}
 a.Signature[0]^=1
 if _,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now);!errors.Is(err,ErrClaimUnverifiable){t.Fatal(err)}
 if store.writes!=0{t.Fatal("invalid signature wrote claim")}
}
func TestClaimTamperedInspectionFailsClosed(t *testing.T){
 a,tr,trust,now:=signedAuthorizationFixture(t)
 store:=&claimMemoryStore{records:map[string]ClaimRecord{}}
 claim,err:=ClaimOnce(context.Background(),store,a,tr,trust.DomainDigest,trust,now);if err!=nil{t.Fatal(err)}
 store.records[claim.SlotDigest]=func()ClaimRecord{c:=claim;c.SignatureDigest="sha256:"+fmt.Sprintf("%064x",1);return c}()
 if _,err:=InspectClaimAttempt(context.Background(),store,claim);!errors.Is(err,ErrClaimUnverifiable){t.Fatal(err)}
}
