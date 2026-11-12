package desiredauthority

import (
 "context"
 "errors"
 "fmt"
 "sync"
 "testing"
)
// A test-only linearizable store, NOT Kubernetes persistence.
type memoryStore struct {
 mu sync.Mutex
 state map[string]Snapshot
 unavailable bool
}
func (s *memoryStore) key(tenant,cluster,profile string)string{return tenant+"/"+cluster+"/"+profile}
func (s *memoryStore) Inspect(_ context.Context,tenant,cluster,profile string)(Snapshot,error){
 s.mu.Lock();defer s.mu.Unlock()
 if s.unavailable{return Snapshot{},errors.New("read unavailable")}
 state,ok:=s.state[s.key(tenant,cluster,profile)]
 if !ok{return Snapshot{Revision:Absent},nil}
 return state,nil
}
func (s *memoryStore) CompareAndSwap(_ context.Context,t Transition)(Result,error){
 if err:=t.Validate();err!=nil{return Result{},err}
 s.mu.Lock();defer s.mu.Unlock()
 key:=s.key(t.Tenant,t.Cluster,t.AuthorityProfile)
 old,ok:=s.state[key];if !ok{old=Snapshot{Revision:Absent}}
 if old.Last!=nil && *old.Last==t && old.Revision==t.To{return Result{Outcome:AlreadyAccepted,State:old},nil}
 if old.Revision!=t.From{return Result{Outcome:PreconditionFailed,State:old},nil}
 next:=t;now:=Snapshot{Revision:t.To,Last:&next};s.state[key]=now
 return Result{Outcome:Accepted,State:now},nil
}
func request()Transition{
 dg:=func(ch string)string{b:="";for i:=0;i<64;i++{b+=ch};return "sha256:"+b}
 return Transition{Tenant:"team-a",Cluster:"alpha",AuthorityProfile:"same-plane-v1",TransitionID:"nonce-1",From:Absent,To:Revision(dg("a")),Operation:"CreateCluster",RequestDigest:dg("b"),ExecutionBindingDigest:dg("c"),AuthorizationDigest:dg("d")}
}
func TestConcurrentAcceptanceHasOneWinner(t *testing.T){
 s:=&memoryStore{state:map[string]Snapshot{}};base:=request();const n=32
 results:=make(chan string,n);var wg sync.WaitGroup
 for i:=0;i<n;i++{wg.Add(1);go func(i int){
  defer wg.Done();q:=base;q.TransitionID=fmt.Sprintf("nonce-%d",i)
  q.To=Revision(fmt.Sprintf("sha256:%064x",i+1))
  r,e:=s.CompareAndSwap(context.Background(),q);if e!=nil{results<-"ERROR";return};results<-r.Outcome
 }(i)}
 wg.Wait();close(results);winners,conflicts:=0,0
 for status:=range results{switch status{case Accepted:winners++;case PreconditionFailed:conflicts++;default:t.Fatalf("unexpected %s",status)}}
 if winners!=1||conflicts!=n-1{t.Fatalf("winners=%d conflicts=%d",winners,conflicts)}
}
func TestReplayAndConflictingTuple(t *testing.T){
 s:=&memoryStore{state:map[string]Snapshot{}};a:=request()
 if r,_:=s.CompareAndSwap(context.Background(),a);r.Outcome!=Accepted{t.Fatal(r)}
 if r,_:=s.CompareAndSwap(context.Background(),a);r.Outcome!=AlreadyAccepted{t.Fatal(r)}
 sameTarget:=a;sameTarget.TransitionID="different"
 if r,_:=s.CompareAndSwap(context.Background(),sameTarget);r.Outcome!=PreconditionFailed{t.Fatal(r)}
 res,err:=ReconcileIndeterminate(context.Background(),s,a)
 if err!=nil||res.Outcome!=AlreadyAccepted{t.Fatal(res,err)}
 res,err=ReconcileIndeterminate(context.Background(),s,sameTarget)
 if !errors.Is(err,ErrUnverifiable)||res.Outcome!=Indeterminate{t.Fatal(res,err)}
}
func TestMissingResponseAndUnknownStoreFailClosed(t *testing.T){
 s:=&memoryStore{state:map[string]Snapshot{}};a:=request()
 res,err:=ReconcileIndeterminate(context.Background(),s,a)
 if !errors.Is(err,ErrUnverifiable)||res.Outcome!=Indeterminate{t.Fatal(res,err)}
 s.unavailable=true
 res,err=ReconcileIndeterminate(context.Background(),s,a)
 if !errors.Is(err,ErrUnverifiable)||res.Outcome!=Indeterminate{t.Fatal(res,err)}
}
func TestUnsupportedAndInvalidTransitions(t *testing.T){
 s:=&memoryStore{state:map[string]Snapshot{}}
 invalid:=[]Transition{request(),request(),request(),request(),request(),request()}
 invalid[0].Operation="AdoptCluster"
 invalid[1].AuthorizationDigest=""
 invalid[2].To=DesiredAbsent
 invalid[3].From=invalid[3].To
 invalid[4].Tenant=""
 invalid[5].Tenant="team/other"
 for i,q:=range invalid{
  if _,err:=s.CompareAndSwap(context.Background(),q);!errors.Is(err,ErrInvalid){t.Fatalf("case %d err %v",i,err)}
 }
}
