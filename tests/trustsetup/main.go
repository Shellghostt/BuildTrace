// Command trustsetup provisions an authenticated public-good root snapshot.
// It is a separate opt-in setup tool; verification never calls it or TUF.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/shellghostt/buildtrace/internal/signing"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func main() {
	out := flag.String("out", ".tmp/trusted-root.json", "authenticated root snapshot output")
	flag.Parse()
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	err := setup(ctx, *out)
	cancel()
	stop()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setup(ctx context.Context, out string) error {
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 10 * time.Second, MaxIdleConns: 2}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	options := tuf.DefaultOptions()
	options.DisableLocalCache = true
	options.Context = ctx
	options.Fetcher = &boundedFetcher{ctx: ctx, client: client}
	provider, err := tuf.New(options)
	if err != nil {
		return fmt.Errorf("authenticated Sigstore TUF setup failed: %w", err)
	}
	data, err := provider.GetTarget("trusted_root.json")
	if err != nil {
		return fmt.Errorf("authenticated trusted-root target could not be retrieved: %w", err)
	}
	if _, err := signing.ParseTrustedRoot(data); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(out), ".buildtrace-trust-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(name) }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(name, out); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	return json.NewEncoder(os.Stdout).Encode(struct {
		Path      string    `json:"trustRootFile"`
		SHA256    string    `json:"sha256"`
		Source    string    `json:"source"`
		Bootstrap string    `json:"bootstrap"`
		Retrieved time.Time `json:"retrievedAt"`
	}{out, hex.EncodeToString(sum[:]), tuf.DefaultMirror, "sigstore-go v1.3.0 embedded TUF root", time.Now().UTC()})
}

type boundedFetcher struct {
	ctx    context.Context
	client *http.Client
}

func (f *boundedFetcher) DownloadFile(address string, maximum int64, _ time.Duration) ([]byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Host != "tuf-repo-cdn.sigstore.dev" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("unconfigured TUF download endpoint")
	}
	if maximum <= 0 || maximum > 4<<20 {
		maximum = 4 << 20
	}
	req, err := http.NewRequestWithContext(f.ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	response, err := f.client.Do(req)
	if err != nil {
		return nil, errors.New("TUF download failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: response.StatusCode, URL: address}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, errors.New("TUF response could not be read")
	}
	if int64(len(data)) > maximum {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: "TUF response exceeded its configured bound"}
	}
	return data, nil
}
