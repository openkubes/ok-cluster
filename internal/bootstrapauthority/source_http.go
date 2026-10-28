package bootstrapauthority

import (
	"context"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const partialMetadataAccept = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
const maximumSourceReadDuration = 15 * time.Second

// NewKubernetesSourceHTTPGetters builds the only API reads needed by the
// candidate source reader. The caller supplies an already configured,
// platform-owned HTTP client; this function does not load kubeconfigs, discover
// credentials, or establish authority. The API server and object identity are
// fixed at construction so callback arguments cannot select another object.
// The HTTP client is copied and redirects are disabled.
func NewKubernetesSourceHTTPGetters(apiServer, namespace, name string, client *http.Client) (SourceMetadataGetter, SourceSecretGetter, error) {
	base, err := url.Parse(apiServer)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.Path != "" || base.RawPath != "" ||
		!validNamespace(namespace) || !validSecretName(name) || client == nil {
		return nil, nil, ErrStop
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	baseURL := strings.TrimSuffix(base.String(), "/")
	objectURL := baseURL + "/api/v1/namespaces/" + namespace + "/secrets/" + name
	metadata := func(ctx context.Context, requestedNamespace, requestedName string) ([]byte, error) {
		if requestedNamespace != namespace || requestedName != name {
			return nil, ErrStop
		}
		return sourceHTTPGet(ctx, &copyClient, objectURL, partialMetadataAccept, 256*1024)
	}
	secret := func(ctx context.Context, requestedNamespace, requestedName string) ([]byte, error) {
		if requestedNamespace != namespace || requestedName != name {
			return nil, ErrStop
		}
		return sourceHTTPGet(ctx, &copyClient, objectURL, "application/json", maximumSourceSecretBytes)
	}
	return metadata, secret, nil
}

func sourceHTTPGet(ctx context.Context, client *http.Client, endpoint, accept string, maximum int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrStop
	}
	boundedContext, cancel := context.WithTimeout(ctx, maximumSourceReadDuration)
	defer cancel()
	req, err := http.NewRequestWithContext(boundedContext, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, ErrStop
	}
	req.Header.Set("Accept", accept)
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrStop
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrStop
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, ErrStop
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maximum+1))
	if err != nil || len(body) == 0 || int64(len(body)) > maximum {
		return nil, ErrStop
	}
	return body, nil
}

func validNamespace(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] < 'a' || value[len(value)-1] > 'z' && (value[len(value)-1] < '0' || value[len(value)-1] > '9') {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

func validSecretName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] < 'a' || label[0] > 'z' && (label[0] < '0' || label[0] > '9') || label[len(label)-1] < 'a' || label[len(label)-1] > 'z' && (label[len(label)-1] < '0' || label[len(label)-1] > '9') {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}
