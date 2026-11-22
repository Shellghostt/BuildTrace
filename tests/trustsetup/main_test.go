package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type responseTransport struct {
	status int
	body   string
	calls  int
}

func (r *responseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body)), Header: make(http.Header)}, nil
}

func TestTUFRootRotation404RetainsTypedHTTPFailure(t *testing.T) {
	transport := &responseTransport{status: 404, body: "not found"}
	fetcher := &boundedFetcher{ctx: t.Context(), client: &http.Client{Transport: transport}}
	_, err := fetcher.DownloadFile("https://tuf-repo-cdn.sigstore.dev/9999.root.json", 1024, time.Second)
	var status *metadata.ErrDownloadHTTP
	if !errors.As(err, &status) || status.StatusCode != 404 || transport.calls != 1 {
		t.Fatal("TUF cannot terminate root rotation on its expected 404", err)
	}
}

func TestTUFEndpointAndDownloadBounds(t *testing.T) {
	transport := &responseTransport{status: 200, body: strings.Repeat("x", 33)}
	fetcher := &boundedFetcher{ctx: t.Context(), client: &http.Client{Transport: transport}}
	if _, err := fetcher.DownloadFile("https://attacker.invalid/root.json", 32, time.Second); err == nil || transport.calls != 0 {
		t.Fatal("unconfigured endpoint was contacted")
	}
	_, err := fetcher.DownloadFile("https://tuf-repo-cdn.sigstore.dev/root.json", 32, time.Second)
	var size *metadata.ErrDownloadLengthMismatch
	if !errors.As(err, &size) {
		t.Fatal("download was not bounded", err)
	}
}
