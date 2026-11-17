package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shellghostt/buildtrace/pkg/intoto"
)

const helloSHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
const directorySHA256 = "af7be037cf7f2ef0beef5b69314747e532b6ce13738578a8f8f362c105f98727"

func fixtureOptions(claims bool) Options {
	options := Options{
		Artifacts: []Observation{{Name: "dist/app", Kind: "file", Size: 5, SHA256: helloSHA256}},
		Checkout: Checkout{URI: "https://user:fixture-secret@source.invalid/acme/project.git?token=fixture-secret#fixture-secret",
			Commit: strings.Repeat("a", 40), Dirty: true},
		Recorder: Recorder{Version: "0.1.0-fixture", GoVersion: "1.26.11", GitVersion: "2.53.0", OS: "linux", Arch: "amd64"},
	}
	if claims {
		options.Artifacts = append(options.Artifacts, Observation{Name: "bundle", Kind: "directory", Size: 16, SHA256: directorySHA256})
		options.BuilderID = "https://user:fixture-secret@builder.invalid/recorder?token=fixture-secret#fixture-secret"
		options.InvocationID = "fixture-2"
		options.SourceURI = "git@source.invalid:acme/asserted.git"
		options.SourceCommit = strings.Repeat("b", 40)
		options.StartedOn = "2026-11-14T05:30:00.125+05:30"
		options.FinishedOn = "2026-11-14T00:01:00.5Z"
	}
	return options
}

func TestRecordGoldenFixtures(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		claims bool
	}{{"observed.intoto.jsonl", false}, {"claimed.intoto.jsonl", true}} {
		t.Run(fixture.name, func(t *testing.T) {
			got, err := Build(fixtureOptions(fixture.claims))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("..", "..", "tests", "fixtures", "m3", fixture.name)
			// Regeneration is deliberate; ordinary tests never rewrite a golden.
			if os.Getenv("BUILDTRACE_WRITE_M3_GOLDEN") == "1" {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("record differs from committed golden:\n%s\nwant:\n%s", got, want)
			}
			if bytes.Count(got, []byte{'\n'}) != 1 || got[len(got)-1] != '\n' {
				t.Fatal("not exactly one terminated compact record")
			}
		})
	}
}

func TestDefaultRecordingIDIsCanonicalAndExplicitIDPreservesBytes(t *testing.T) {
	options := fixtureOptions(false)
	encoded, err := Build(options)
	if err != nil {
		t.Fatal(err)
	}
	var statement intoto.Statement
	var predicate intoto.Provenance
	if err := json.Unmarshal(encoded, &statement); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(statement.Predicate, &predicate); err != nil {
		t.Fatal(err)
	}
	id := predicate.RunDetails.Metadata.InvocationID
	predicate.RunDetails.Metadata.InvocationID = ""
	statement.Predicate, _ = intoto.MarshalLine(predicate)
	withoutID, _ := intoto.MarshalLine(statement)
	digest := sha256.Sum256(withoutID)
	if id != fmt.Sprintf("sha256:%x", digest) {
		t.Fatal("ID does not match documented canonical recording hash")
	}
	options.InvocationID = id
	again, err := Build(options)
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatalf("explicit derived ID changed the record: %v", err)
	}
}

func TestRecordDoesNotInventOriginalBuildHistory(t *testing.T) {
	for _, claims := range []bool{false, true} {
		encoded, err := Build(fixtureOptions(claims))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("fixture-secret")) || bytes.Contains(encoded, []byte("byproducts")) || bytes.Contains(encoded, []byte("builderDependencies")) {
			t.Fatal("credentials or uncaptured data appeared")
		}
		var statement intoto.Statement
		var predicate intoto.Provenance
		_ = json.Unmarshal(encoded, &statement)
		_ = json.Unmarshal(statement.Predicate, &predicate)
		if !claims {
			if predicate.RunDetails.Metadata.StartedOn != nil || predicate.RunDetails.Metadata.FinishedOn != nil || len(predicate.BuildDefinition.ResolvedDependencies) != 0 || bytes.Contains(encoded, []byte("assertedSource")) {
				t.Fatal("checkout observation invented source/dependency/time claims")
			}
		} else {
			if len(predicate.BuildDefinition.ResolvedDependencies) != 1 || !bytes.Contains(encoded, []byte(`"evidence":"caller_assertion"`)) ||
				string(predicate.BuildDefinition.ResolvedDependencies[0].Annotations["buildtrace.evidence"]) != `"caller_assertion"` {
				t.Fatal("explicit source assertion lost its label")
			}
			if predicate.RunDetails.Metadata.StartedOn.Format("2006-01-02T15:04:05.999999999Z07:00") != "2026-11-14T00:00:00.125Z" {
				t.Fatal("claimed time was not normalized with precision intact")
			}
		}
	}
}

func TestRecordingOrderingAndAllInputsAffectDeterminism(t *testing.T) {
	options := fixtureOptions(true)
	first, err := Build(options)
	if err != nil {
		t.Fatal(err)
	}
	options.Artifacts[0], options.Artifacts[1] = options.Artifacts[1], options.Artifacts[0]
	again, err := Build(options)
	if err != nil || !bytes.Equal(first, again) {
		t.Fatal("selection order changed canonical bytes")
	}
	for _, change := range []func(*Options){
		func(o *Options) { o.Recorder.Version = "different-recorder" },
		func(o *Options) { o.Checkout.Dirty = false },
		func(o *Options) { o.InvocationID = "different-id" },
		func(o *Options) { o.FinishedOn = "2026-11-14T00:02:00Z" },
		func(o *Options) { o.Artifacts[0].SHA256 = strings.Repeat("c", 64) },
	} {
		changed := fixtureOptions(true)
		change(&changed)
		got, err := Build(changed)
		if err != nil || bytes.Equal(first, got) {
			t.Fatalf("changed input did not change the record: %v", err)
		}
	}
}

func TestRecordRejectsInvalidInputsWithoutEchoingThem(t *testing.T) {
	for name, change := range map[string]func(*Options){
		"no artifacts":          func(o *Options) { o.Artifacts = nil },
		"too many":              func(o *Options) { o.Artifacts = make([]Observation, MaxArtifacts+1) },
		"duplicate":             func(o *Options) { o.Artifacts = append(o.Artifacts, o.Artifacts[0]) },
		"host path":             func(o *Options) { o.Artifacts[0].Name = "/private/fixture-secret/app" },
		"noncanonical":          func(o *Options) { o.Artifacts[0].Name = "a/../app" },
		"missing digest":        func(o *Options) { o.Artifacts[0].SHA256 = "" },
		"negative size":         func(o *Options) { o.Artifacts[0].Size = -1 },
		"unsupported kind":      func(o *Options) { o.Artifacts[0].Kind = "socket" },
		"short checkout":        func(o *Options) { o.Checkout.Commit = "abc123" },
		"source pair":           func(o *Options) { o.SourceURI = "https://source.invalid/project" },
		"short asserted commit": func(o *Options) { o.SourceURI = "https://source.invalid/project"; o.SourceCommit = "abc123" },
		"local asserted source": func(o *Options) {
			o.SourceURI = "/private/fixture-secret/repo"
			o.SourceCommit = strings.Repeat("b", 40)
		},
		"time pair":         func(o *Options) { o.StartedOn = "2026-11-14T00:00:00Z" },
		"time order":        func(o *Options) { o.StartedOn = "2026-11-14T01:00:00Z"; o.FinishedOn = "2026-11-14T00:00:00Z" },
		"bad time":          func(o *Options) { o.StartedOn = "fixture-secret"; o.FinishedOn = "2026-11-14T00:00:00Z" },
		"bad builder":       func(o *Options) { o.BuilderID = "fixture-secret" },
		"bad invocation":    func(o *Options) { o.InvocationID = "/private/fixture-secret/id" },
		"control character": func(o *Options) { o.InvocationID = "fixture-secret\n" },
	} {
		t.Run(name, func(t *testing.T) {
			options := fixtureOptions(false)
			change(&options)
			encoded, err := Build(options)
			if !IsInputError(err) || encoded != nil {
				t.Fatalf("invalid input was accepted: %v", err)
			}
			if strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("raw private input leaked through the error")
			}
		})
	}
}

func TestURIInputsRemoveCredentialQueryAndFragment(t *testing.T) {
	for _, source := range []string{"https://user:fixture-secret@source.invalid/project.git?secret=fixture-secret#fixture-secret", "git+https://user:fixture-secret@source.invalid/project.git?secret=fixture-secret#fixture-secret", "git@source.invalid:project.git"} {
		got := SanitizeObservedRemote(source)
		if got == "" || strings.Contains(got, "fixture-secret") || strings.ContainsAny(got, "?@#") {
			t.Fatal(got)
		}
	}
	for _, local := range []string{"/private/fixture-secret/repo", `C:\private\fixture-secret\repo`, "../local", ""} {
		if SanitizeObservedRemote(local) != "" {
			t.Fatal("local remote was published")
		}
	}
	for _, label := range []string{"https://user:fixture-secret@builder.invalid/run?secret=fixture-secret#fixture-secret", "urn:public:run?secret=fixture-secret#fixture-secret"} {
		clean, err := sanitizeLabel(label, false)
		if err != nil || strings.Contains(clean, "fixture-secret") {
			t.Fatalf("identifier leaked query/fragment: %s %v", clean, err)
		}
	}
}

func TestRecordAcceptsFullSHA256GitCommitAsAnExplicitClaim(t *testing.T) {
	options := fixtureOptions(true)
	options.SourceCommit = strings.Repeat("b", 64)
	encoded, err := Build(options)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(bytes.NewReader(encoded))
	if err != nil || got.Dependencies[0].Digest["gitCommit"] != options.SourceCommit {
		t.Fatal("full SHA-256 Git commit was not retained", err)
	}
}
