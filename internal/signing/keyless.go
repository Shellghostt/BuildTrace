package signing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	openapi "github.com/go-openapi/runtime"
	openapiclient "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	rekorutil "github.com/sigstore/rekor/pkg/util"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/shellghostt/buildtrace/internal/attestation"
)

const FulcioURL = "https://fulcio.sigstore.dev"
const RekorURL = "https://rekor.sigstore.dev"
const MaxNetworkBytes = 1 << 20

type KeylessOptions struct {
	TrustedRoot TrustedRoot
	LookupEnv   func(string) (string, bool)
}

// SignKeyless contacts only the explicit GitHub OIDC/public-good services.
// Service/library errors are intentionally replaced by fixed diagnostics.
func SignKeyless(parent context.Context, payload []byte, options KeylessOptions) ([]byte, error) {
	if options.TrustedRoot.Material == nil {
		return nil, invalid("keyless signing requires a provisioned trusted-root file")
	}
	if len(payload) == 0 || len(payload) > attestation.MaxInputBytes {
		return nil, invalid("payload exceeds the statement bound")
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	if options.LookupEnv == nil {
		options.LookupEnv = os.LookupEnv
	}
	token, err := oidcToken(ctx, options.LookupEnv)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure("signing_failed", 3, "keyless signing was cancelled")
	}
	key, err := sign.NewEphemeralKeypair(&sign.EphemeralKeypairOptions{Algorithm: common.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256})
	if err != nil {
		return nil, failure("signing_failed", 3, "ephemeral signing key could not be created")
	}
	fulcioTransport := boundedTransport(ctx, "fulcio.sigstore.dev")
	rekorTransport := boundedTransport(ctx, "rekor.sigstore.dev")
	defer fulcioTransport.inner.CloseIdleConnections()
	defer rekorTransport.inner.CloseIdleConnections()
	rekorHTTP := &http.Client{Transport: rekorTransport, Timeout: 30 * time.Second, CheckRedirect: noRedirect}
	api := openapiclient.NewWithClient("rekor.sigstore.dev", rekorclient.DefaultBasePath, []string{"https"}, rekorHTTP)
	api.Consumers["application/json"] = openapi.JSONConsumer()
	api.Producers["application/json"] = openapi.JSONProducer()
	registry := strfmt.NewFormats()
	registry.Add("signedCheckpoint", &rekorutil.SignedNote{}, rekorutil.SignedCheckpointValidator)
	rekor := rekorclient.New(api, registry)
	b, err := sign.Bundle(&sign.DSSEData{Data: payload, PayloadType: PayloadType}, key, sign.BundleOptions{
		Context: ctx, TrustedRoot: options.TrustedRoot.Material,
		CertificateProvider:        sign.NewFulcio(&sign.FulcioOptions{BaseURL: FulcioURL, Timeout: 30 * time.Second, Retries: 1, Transport: fulcioTransport}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: token},
		TransparencyLogs: []sign.Transparency{sign.NewRekor(&sign.RekorOptions{BaseURL: RekorURL, Version: 1,
			Timeout: 30 * time.Second, Retries: 0, Client: rekor.Entries})},
	})
	if err != nil {
		return nil, failure("signing_failed", 3, "keyless certificate/signing/transparency service failed; no output was published")
	}
	encoded, err := protojson.Marshal(b)
	if err != nil {
		return nil, failure("signing_failed", 3, "standard keyless bundle could not be encoded")
	}
	decoded, err := DecodeKeylessBundle(encoded)
	if err != nil || !bytes.Equal(decoded.Decoded.Payload, payload) {
		return nil, failure("signing_failed", 3, "keyless bundle lacks valid complete offline material")
	}
	summary, err := fulciocert.SummarizeCertificate(decoded.Leaf)
	if err != nil {
		return nil, failure("signing_failed", 3, "keyless certificate identity is invalid")
	}
	// The signing operation already owns this payload/key. Validate its returned
	// certificate/log material; consumer verification still supplies its own policy.
	if _, err := VerifyKeyless(decoded, options.TrustedRoot, summary.SubjectAlternativeName, summary.Issuer); err != nil {
		return nil, failure("signing_failed", 3, "keyless bundle failed pinned-root offline validation")
	}
	if ctx.Err() != nil {
		return nil, failure("signing_failed", 3, "keyless signing was cancelled before publication")
	}
	return append(encoded, '\n'), nil
}

func oidcToken(ctx context.Context, lookup func(string) (string, bool)) (string, error) {
	if path, supplied := lookup("BUILDTRACE_OIDC_TOKEN_FILE"); supplied {
		data, err := ReadSecurityFile(path, MaxKeyBytes, true, "key_unreadable")
		if err != nil {
			return "", err
		}
		token := string(bytes.TrimSpace(data))
		clear(data)
		if !jwtToken(token) {
			return "", invalid("OIDC token file must contain one bounded JWT")
		}
		return token, nil
	}
	actions, _ := lookup("GITHUB_ACTIONS")
	requestURL, _ := lookup("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken, _ := lookup("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	u, err := url.Parse(requestURL)
	if err != nil || actions != "true" || u.Scheme != "https" || u.User != nil || u.Fragment != "" ||
		(u.Port() != "" && u.Port() != "443") || !strings.HasSuffix(u.Hostname(), ".actions.githubusercontent.com") ||
		!public(requestToken, MaxKeyBytes) || len(requestURL) > 4096 {
		return "", invalid("keyless signing requires an OIDC token file or valid GitHub Actions OIDC configuration")
	}
	query := u.Query()
	query.Set("audience", "sigstore")
	u.RawQuery = query.Encode()
	transport := boundedTransport(ctx, u.Hostname())
	defer transport.inner.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: noRedirect}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", invalid("invalid GitHub OIDC request configuration")
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	response, err := client.Do(req)
	if err != nil {
		return "", failure("signing_failed", 3, "GitHub OIDC token request failed")
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if err != nil || response.StatusCode != http.StatusOK || len(data) > 64<<10 || checkJSON(data, 64<<10) != nil {
		return "", failure("signing_failed", 3, "GitHub OIDC returned invalid or unavailable token material")
	}
	var result struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(data, &result) != nil || !jwtToken(result.Value) {
		return "", failure("signing_failed", 3, "GitHub OIDC token material is invalid")
	}
	return result.Value, nil
}

func jwtToken(value string) bool {
	if !public(value, MaxKeyBytes) || strings.TrimSpace(value) != value {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			valid := c == '-' || c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !valid {
				return false
			}
		}
	}
	return true
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

type serviceTransport struct {
	ctx   context.Context
	host  string
	inner *http.Transport
}

func boundedTransport(ctx context.Context, host string) *serviceTransport {
	return &serviceTransport{ctx: ctx, host: host, inner: &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 20 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 20 * time.Second,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4,
	}}
}

func (t *serviceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.ctx.Err() != nil {
		return nil, errors.New("signing service request was cancelled")
	}
	if req.URL.Scheme != "https" || req.URL.Hostname() != t.host || req.URL.User != nil || req.Response != nil ||
		(req.URL.Port() != "" && req.URL.Port() != "443") {
		return nil, errors.New("signing service request or redirect is not allowed")
	}
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	request := req.Clone(ctx)
	request.Header.Set("User-Agent", "BuildTrace-M4/1")
	response, err := t.inner.RoundTrip(request)
	if err != nil {
		stop()
		cancel()
		return nil, errors.New("signing service transport failed")
	}
	if response.ContentLength > MaxNetworkBytes {
		_ = response.Body.Close()
		stop()
		cancel()
		return nil, errors.New("signing service response exceeded its bound")
	}
	response.Body = &boundedResponseBody{inner: response.Body, remaining: MaxNetworkBytes, cancel: cancel, stop: stop}
	return response, nil
}

type boundedResponseBody struct {
	inner     io.ReadCloser
	remaining int
	cancel    context.CancelFunc
	stop      func() bool
}

func (b *boundedResponseBody) Read(p []byte) (int, error) {
	if len(p) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.inner.Read(p)
	if n > b.remaining {
		return n, errors.New("signing service response exceeded its bound")
	}
	b.remaining -= n
	return n, err
}

func (b *boundedResponseBody) Close() error {
	b.stop()
	b.cancel()
	return b.inner.Close()
}
