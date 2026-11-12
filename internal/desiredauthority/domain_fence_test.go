package desiredauthority

import (
 "context"
 "errors"
 "testing"
)

type fenceFake struct {
 system DomainObject
 ns DomainObject
 fence FenceObject
 errorOn string
 calls int
}
func(f *fenceFake) ReadNamespace(_ context.Context,name string)(DomainObject,error){
 f.calls++
 if f.errorOn==name{return DomainObject{},errors.New("API unavailable")}
 if name=="kube-system"{return f.system,nil}
 return f.ns,nil
}
func(f *fenceFake) ReadFence(_ context.Context,_,_ string)(FenceObject,error){
 f.calls++
 if f.errorOn=="fence"{return FenceObject{},errors.New("no fence")}
 return f.fence,nil
}
func domainFixture(t *testing.T)(DomainBinding,*fenceFake){
 t.Helper()
 b:=DomainBinding{Endpoint:"https://api.example.test:6443",TrustDigest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",ClusterUID:"cluster-uid-1",AuthorityNamespace:"openkubes-authority",NamespaceUID:"namespace-uid-1",FenceName:"authority-domain-fence",FenceUID:"fence-uid-1",FenceResourceVersion:"17"}
 d,e:=b.DomainIdentity();if e!=nil{t.Fatal(e)};b.ExpectedDomainDigest=d
 f:=&fenceFake{system:DomainObject{Name:"kube-system",UID:b.ClusterUID,ResourceVersion:"12"},ns:DomainObject{Name:b.AuthorityNamespace,UID:b.NamespaceUID,ResourceVersion:"20"},fence:FenceObject{DomainObject:DomainObject{Name:b.FenceName,Namespace:b.AuthorityNamespace,UID:b.FenceUID,ResourceVersion:b.FenceResourceVersion},Immutable:true,Format:"openkubes-desired-authority-fence/v1",State:"ACTIVE",NamespaceUID:b.NamespaceUID,DomainDigest:d}}
 return b,f
}
func TestDomainVerifiedReadOnly(t *testing.T){b,f:=domainFixture(t);if e:=VerifyDomain(context.Background(),b,f);e!=nil{t.Fatal(e)}}
func TestDomainNegativeIdentityAndDeletion(t *testing.T){
 cases:=[]struct{name string;mutate func(*DomainBinding,*fenceFake)}{
 {"different cluster UID",func(_ *DomainBinding,f *fenceFake){f.system.UID="replacement"}},
 {"different namespace UID",func(_ *DomainBinding,f *fenceFake){f.ns.UID="replacement"}},
 {"different fence UID",func(_ *DomainBinding,f *fenceFake){f.fence.UID="replacement"}},
 {"different fence RV",func(_ *DomainBinding,f *fenceFake){f.fence.ResourceVersion="18"}},
 {"fence not immutable",func(_ *DomainBinding,f *fenceFake){f.fence.Immutable=false}},
 {"fence disabled",func(_ *DomainBinding,f *fenceFake){f.fence.State="DISABLED"}},
 {"fence domain mismatch",func(_ *DomainBinding,f *fenceFake){f.fence.DomainDigest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
 {"fence namespace mismatch",func(_ *DomainBinding,f *fenceFake){f.fence.NamespaceUID="replacement"}},
 {"namespace deleting",func(_ *DomainBinding,f *fenceFake){f.ns.Deleting=true}},
 {"fence deleting",func(_ *DomainBinding,f *fenceFake){f.fence.Deleting=true}},
 {"fence owned",func(_ *DomainBinding,f *fenceFake){f.fence.OwnerReferences=true}},
 {"wrong endpoint",func(b *DomainBinding,_ *fenceFake){b.Endpoint="https://other.example.test:6443"}},
 {"wrong trust",func(b *DomainBinding,_ *fenceFake){b.TrustDigest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
 {"fence unavailable",func(_ *DomainBinding,f *fenceFake){f.errorOn="fence"}},
 {"namespace 404",func(_ *DomainBinding,f *fenceFake){f.errorOn="openkubes-authority"}},
 {"cluster unavailable",func(_ *DomainBinding,f *fenceFake){f.errorOn="kube-system"}},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){b,f:=domainFixture(t);tc.mutate(&b,f);if e:=VerifyDomain(context.Background(),b,f);!errors.Is(e,ErrDomainUnverifiable){t.Fatalf("unexpected %v",e)}})}
}
func TestDomainDigestExcludesFenceRVButPinsAtUse(t *testing.T){b,f:=domainFixture(t);b.FenceResourceVersion="18";d,e:=b.DomainIdentity();if e!=nil||d!=b.ExpectedDomainDigest{t.Fatalf("digest changed %v",e)};if e:=VerifyDomain(context.Background(),b,f);!errors.Is(e,ErrDomainUnverifiable){t.Fatalf("unexpected %v",e)}}
func TestStableReadDetectsDrift(t *testing.T){b,f:=domainFixture(t);count:=0;e:=VerifyStableRead(context.Background(),b,f,func(context.Context)error{count++;f.fence.UID="replacement";return nil});if !errors.Is(e,ErrDomainUnverifiable)||count!=1{t.Fatalf("got %v count %d",e,count)}}
func TestStableReadSkipsBadDomain(t *testing.T){b,f:=domainFixture(t);f.ns.UID="replacement";count:=0;e:=VerifyStableRead(context.Background(),b,f,func(context.Context)error{count++;return nil});if !errors.Is(e,ErrDomainUnverifiable)||count!=0{t.Fatalf("got %v count %d",e,count)}}
func TestUntrustedBindingRejected(t *testing.T){b,f:=domainFixture(t);for _,endpoint:=range []string{"http://api.example.test:6443","https://user@api.example.test:6443","https://api.example.test:6443/path"}{broken:=b;broken.Endpoint=endpoint;if e:=VerifyDomain(context.Background(),broken,f);!errors.Is(e,ErrDomainUnverifiable){t.Fatalf("%s: %v",endpoint,e)}}}
