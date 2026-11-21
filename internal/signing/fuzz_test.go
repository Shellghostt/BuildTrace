package signing

import (
	"os"
	"testing"
)

func FuzzDecodeEnvelope(f *testing.F) {
	data, err := os.ReadFile("../../tests/fixtures/m4/local-ed25519.dsse.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30K","signatures":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = DecodeEnvelope(data)
	})
}

func FuzzDecodeKeylessBundle(f *testing.F) {
	data, err := os.ReadFile("../../tests/fixtures/m4/historical.sigstore.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = DecodeKeylessBundle(data)
	})
}
