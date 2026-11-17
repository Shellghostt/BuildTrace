package attestation

import (
	"bytes"
	"testing"
)

// BenchmarkRecordInspect profiles one complete synthetic recording/inspection
// lifecycle. Artifact hashing has its separate real 1 GiB memory gate.
func BenchmarkRecordInspect(b *testing.B) {
	options := fixtureOptions(true)
	b.ReportAllocs()
	for b.Loop() {
		line, err := Build(options)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Read(bytes.NewReader(line)); err != nil {
			b.Fatal(err)
		}
	}
}
