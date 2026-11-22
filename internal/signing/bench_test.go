package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

func benchFixture(b *testing.B, name string) []byte {
	b.Helper()
	data, err := os.ReadFile("../../tests/fixtures/m4/" + name)
	if err != nil {
		b.Fatal(err)
	}
	return data
}

func BenchmarkM4EnvelopeParse(b *testing.B) {
	data := benchFixture(b, "local-ed25519.dsse.json")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeEnvelope(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkM4LocalSigning(b *testing.B) {
	data := benchFixture(b, "statement.intoto.jsonl")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := SignLocal(data, key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkM4HistoricalOfflineKeyless(b *testing.B) {
	data := benchFixture(b, "historical.sigstore.json")
	root, err := ParseTrustedRoot(benchFixture(b, "trusted-root.json"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		input, err := DecodeKeylessBundle(data)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := VerifyKeyless(input, root, "https://fixture.invalid/owner/repository/.github/workflows/m4.yml@refs/heads/m4", "https://issuer.fixture.invalid"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRepeatedSigningParsingAndCancellationReleaseHeapAndGoroutines(t *testing.T) {
	data, err := os.ReadFile("../../tests/fixtures/m4/historical.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	rootData, err := os.ReadFile("../../tests/fixtures/m4/trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	root, err := ParseTrustedRoot(rootData)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile("../../tests/fixtures/m4/statement.intoto.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("e30.e30.Zg"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	options := KeylessOptions{TrustedRoot: root, LookupEnv: func(name string) (string, bool) {
		if name == "BUILDTRACE_OIDC_TOKEN_FILE" {
			return tokenPath, true
		}
		return "", false
	}}
	debug.FreeOSMemory()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	goroutines := runtime.NumGoroutine()
	const iterations = 300
	for range iterations {
		encoded, err := SignLocal(payload, key)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := DecodeEnvelope(encoded)
		if err != nil || VerifyPAE(envelope, key.Public()) != nil {
			t.Fatal("local lifecycle failed", err)
		}
		input, err := DecodeKeylessBundle(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyKeyless(input, root, "https://fixture.invalid/owner/repository/.github/workflows/m4.yml@refs/heads/m4", "https://issuer.fixture.invalid"); err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEnvelope([]byte(`{"duplicate":1,"duplicate":2}`)); err == nil {
			t.Fatal("failed parse unexpectedly succeeded")
		}
		if _, err := SignKeyless(ctx, payload, options); err == nil {
			t.Fatal("cancelled signing unexpectedly succeeded")
		} else {
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != 3 {
				t.Fatal(err)
			}
		}
	}
	debug.FreeOSMemory()
	runtime.ReadMemStats(&after)
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	goroutineDelta := runtime.NumGoroutine() - goroutines
	if delta > 8<<20 || goroutineDelta > 2 {
		t.Fatalf("retained lifecycle resources grew: heap=%d goroutines=%d", delta, goroutineDelta)
	}
	runtime.KeepAlive(root)
	runtime.KeepAlive(key)
	runtime.KeepAlive(data)
	runtime.KeepAlive(payload)
	receipt, _ := json.Marshal(struct {
		Iterations     int    `json:"iterations"`
		HeapBefore     uint64 `json:"heapBefore"`
		HeapAfter      uint64 `json:"heapAfter"`
		HeapDelta      int64  `json:"heapDelta"`
		GoroutineDelta int    `json:"goroutineDelta"`
	}{iterations, before.HeapAlloc, after.HeapAlloc, delta, goroutineDelta})
	t.Log(string(receipt))
}
