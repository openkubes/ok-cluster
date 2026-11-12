package desiredauthority

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openkubes/ok-cluster/internal/jsonstrict"
	"github.com/openkubes/ok-cluster/internal/kubeconfigtarget"
)

const domainMetadataAccept = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"

// PinnedDomainReader performs only three exact-name Kubernetes GETs.
// It neither discovers credentials nor issues a grant or mutation.
type PinnedDomainReader struct {
	endpoint string
	token string
	client *http.Client
}

type PinnedDomainReaderConfig struct {
	Binding DomainBinding
	CABundle []byte
	BearerToken string
}

// NewPinnedDomainReader validates *externally pinned* trust. A matching
// observation is not evidence that the remote system is anti-deletion fenced.
func NewPinnedDomainReader(c PinnedDomainReaderConfig) (*PinnedDomainReader,error) {
	b:=c.Binding
	d,err:=b.DomainIdentity()
	if err!=nil || d!=b.ExpectedDomainDigest || len(c.CABundle)==0 || len(c.CABundle)>256*1024 ||
		len(c.BearerToken)==0 || len(c.BearerToken)>65536 {return nil,ErrDomainUnverifiable}
	trust,err:=kubeconfigtarget.TrustDigest(c.CABundle)
	if err!=nil || trust!=b.TrustDigest {return nil,ErrDomainUnverifiable}
	for _,ch:=range c.BearerToken {
		if ch<0x21 || ch>0x7e {return nil,ErrDomainUnverifiable}
	}
	u,err:=url.Parse(b.Endpoint)
	if err!=nil || u.Hostname()=="" || u.Port()=="" {return nil,ErrDomainUnverifiable}
	roots:=x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CABundle) {return nil,ErrDomainUnverifiable}
	tr:=&http.Transport{
		Proxy:nil,
		DialContext:(&net.Dialer{Timeout:5*time.Second,KeepAlive:-1}).DialContext,
		TLSClientConfig:&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS12},
		TLSHandshakeTimeout:5*time.Second,
		ResponseHeaderTimeout:10*time.Second,
		MaxResponseHeaderBytes:32*1024,
		DisableKeepAlives:true,
		TLSNextProto:map[string]func(string,*tls.Conn)http.RoundTripper{},
	}
	client:=&http.Client{Transport:tr,Timeout:15*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
	return &PinnedDomainReader{endpoint:b.Endpoint,token:c.BearerToken,client:client},nil
}

func (r *PinnedDomainReader) get(ctx context.Context,path,accept string) ([]byte,error) {
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,r.endpoint+path,nil)
	if err!=nil{return nil,ErrDomainUnverifiable}
	req.Header.Set("Accept",accept)
	req.Header.Set("Authorization","Bearer "+r.token)
	req.Header.Set("Cache-Control","no-cache")
	resp,err:=r.client.Do(req)
	if err!=nil{return nil,ErrDomainUnverifiable}
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK{return nil,ErrDomainUnverifiable}
	ct,_,err:=mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err!=nil || ct!="application/json" {return nil,ErrDomainUnverifiable}
	raw,err:=io.ReadAll(io.LimitReader(resp.Body,131073))
	if err!=nil || len(raw)>131072 {return nil,ErrDomainUnverifiable}
	return raw,nil
}

type domainMetadata struct {
	Name string `json:"name"`
	Namespace string `json:"namespace"`
	UID string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
	DeletionTimestamp json.RawMessage `json:"deletionTimestamp"`
	OwnerReferences []json.RawMessage `json:"ownerReferences"`
}
func domainExactFieldKeys(raw []byte,canonical []string,ignoreOthers bool)(map[string]json.RawMessage,error) {
	var fields map[string]json.RawMessage
	if jsonstrict.Decode(raw,&fields)!=nil || fields==nil{return nil,ErrDomainUnverifiable}
	for key:=range fields {
		matched:=false
		for _,known:=range canonical {
			if strings.EqualFold(key,known) {
				if key!=known{return nil,ErrDomainUnverifiable}
				matched=true
				break
			}
		}
		if !matched&&!ignoreOthers{return nil,ErrDomainUnverifiable}
	}
	return fields,nil
}
func domainDecodeMetadata(raw []byte)(domainMetadata,error){
	fields,err:=domainExactFieldKeys(raw,[]string{"name","namespace","uid","resourceVersion","deletionTimestamp","ownerReferences"},true)
	if err!=nil{return domainMetadata{},ErrDomainUnverifiable}
	var m domainMetadata
	if json.Unmarshal(raw,&m)!=nil || !safeDomainID(m.Name) || !safeDomainID(m.UID) ||
		!safeDomainID(m.ResourceVersion) || len(m.OwnerReferences)!=0 {return domainMetadata{},ErrDomainUnverifiable}
	if v,ok:=fields["deletionTimestamp"];ok && !bytes.Equal(bytes.TrimSpace(v),[]byte("null")){return domainMetadata{},ErrDomainUnverifiable}
	return m,nil
}

func(r *PinnedDomainReader) ReadNamespace(ctx context.Context,name string)(DomainObject,error){
	if !domainNamePattern.MatchString(name){return DomainObject{},ErrDomainUnverifiable}
	raw,err:=r.get(ctx,"/api/v1/namespaces/"+name,domainMetadataAccept)
	if err!=nil{return DomainObject{},err}
	doc,err:=domainExactFieldKeys(raw,[]string{"apiVersion","kind","metadata"},false)
	if err!=nil || string(doc["apiVersion"])!=`"meta.k8s.io/v1"` || string(doc["kind"])!=`"PartialObjectMetadata"`{return DomainObject{},ErrDomainUnverifiable}
	m,err:=domainDecodeMetadata(doc["metadata"])
	if err!=nil || m.Name!=name || m.Namespace!="" {return DomainObject{},ErrDomainUnverifiable}
	return DomainObject{Name:m.Name,UID:m.UID,ResourceVersion:m.ResourceVersion},nil
}

func(r *PinnedDomainReader) ReadFence(ctx context.Context,namespace,name string)(FenceObject,error){
	if !domainNamePattern.MatchString(name)||!domainNamePattern.MatchString(namespace){return FenceObject{},ErrDomainUnverifiable}
	raw,err:=r.get(ctx,"/api/v1/namespaces/"+namespace+"/configmaps/"+name,"application/json")
	if err!=nil{return FenceObject{},err}
	doc,err:=domainExactFieldKeys(raw,[]string{"apiVersion","kind","metadata","immutable","data","binaryData"},false)
	if err!=nil || string(doc["apiVersion"])!=`"v1"` || string(doc["kind"])!=`"ConfigMap"` || string(doc["immutable"])!="true" {return FenceObject{},ErrDomainUnverifiable}
	if v,ok:=doc["binaryData"];ok && !bytes.Equal(bytes.TrimSpace(v),[]byte("null")) && !bytes.Equal(bytes.TrimSpace(v),[]byte("{}")){return FenceObject{},ErrDomainUnverifiable}
	m,err:=domainDecodeMetadata(doc["metadata"])
	if err!=nil || m.Name!=name || m.Namespace!=namespace {return FenceObject{},ErrDomainUnverifiable}
	fields,err:=domainExactFieldKeys(doc["data"],[]string{"format","state","namespaceUID","domainDigest"},false)
	if err!=nil||len(fields)!=4{return FenceObject{},ErrDomainUnverifiable}
	var values map[string]string
	if json.Unmarshal(doc["data"],&values)!=nil || len(values)!=4{return FenceObject{},ErrDomainUnverifiable}
	return FenceObject{
		DomainObject:DomainObject{Name:m.Name,Namespace:m.Namespace,UID:m.UID,ResourceVersion:m.ResourceVersion},
		Immutable:true,Format:values["format"],State:values["state"],NamespaceUID:values["namespaceUID"],DomainDigest:values["domainDigest"],
	},nil
}

var _ DomainReader=(*PinnedDomainReader)(nil)
