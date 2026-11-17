package attestation

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validLine(t *testing.T) []byte {
	t.Helper()
	line, err := Build(fixtureOptions(false))
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestInspectAcceptsGoldensAndCRLFWithUnsignedScope(t *testing.T) {
	for _, claims := range []bool{false, true} {
		line, err := Build(fixtureOptions(claims))
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range [][]byte{line, append(append([]byte(nil), line[:len(line)-1]...), '\r', '\n')} {
			got, err := Read(bytes.NewReader(candidate))
			if err != nil || got.Scope != "unsigned_statement" || got.Status != "inspected" || !got.RecorderContract || len(got.Subjects) == 0 {
				t.Fatal(got, err)
			}
		}
	}
}

func TestInspectRejectsMalformedFramingVersionsAndTypes(t *testing.T) {
	valid := string(validLine(t))
	for name, input := range map[string]string{
		"empty": "", "blank": "\n", "unterminated": strings.TrimSuffix(valid, "\n"),
		"truncated": valid[:len(valid)/2] + "\n", "multiple": valid + valid,
		"extra blank": valid + "\n", "pretty printed": "{\n\"_type\":\"x\"}\n",
		"oversized":               strings.Repeat(" ", MaxInputBytes+1) + "\n",
		"duplicate":               strings.Replace(valid, `"_type":`, `"_type":"duplicate","_type":`, 1),
		"escaped duplicate":       strings.Replace(valid, `"_type":`, `"\u005ftype":"duplicate","_type":`, 1),
		"nested duplicate":        strings.Replace(valid, `"buildType":`, `"buildType":"duplicate","buildType":`, 1),
		"statement v2":            strings.Replace(valid, "Statement/v1", "Statement/v2", 1),
		"wrong predicate version": strings.Replace(valid, "provenance/v1", "provenance/v1.2", 1),
		"unknown predicate":       strings.Replace(valid, "provenance/v1", "other/v1", 1),
		"dsse":                    "{\"payloadType\":\"application/vnd.in-toto+json\",\"payload\":\"e30=\",\"signatures\":[]}\n",
		"bad digest":              strings.Replace(valid, helloSHA256, "abc123", 1),
		"null builder":            strings.Replace(valid, `"builder":{"id":"`+DefaultBuilderID+`"}`, `"builder":null`, 1),
		"wrong external type":     strings.Replace(valid, `"externalParameters":{"artifacts":[{"name":"dist/app","path":"dist/app"}]}`, `"externalParameters":[]`, 1),
		"invalid utf8":            "{\"invalid\":\"\xff\"}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(input)); !IsInputError(err) {
				t.Fatalf("invalid input accepted: %v", err)
			}
		})
	}
}

func TestInspectPreservesCompatibleFieldsAndMatchesKeysExactly(t *testing.T) {
	valid := string(validLine(t))
	valid = strings.Replace(valid, `"_type":`, `"_TYPE":"future-unknown","future":9007199254740993,"_type":`, 1)
	valid = strings.Replace(valid, `"digest":{"sha256":`, `"Digest":false,"digest":{"sha256":`, 1)
	valid = strings.Replace(valid, `"buildType":`, `"BuildType":42,"buildType":`, 1)
	got, err := Read(strings.NewReader(valid))
	if err != nil || got.BuildType != BuildType || got.Subjects[0].Digest["sha256"] != helloSHA256 {
		t.Fatal(got, err)
	}
	if !bytes.Contains(got.Raw, []byte("9007199254740993")) || !bytes.Contains(got.Raw, []byte(`"Digest":false`)) {
		t.Fatal("compatible fields or exact numbers were lost")
	}
	valid = strings.Replace(valid, BuildType, "https://other.invalid/build/v1", 1)
	got, err = Read(strings.NewReader(valid))
	if err != nil || got.RecorderContract || got.Status != "inspected" {
		t.Fatal("unknown build type was interpreted or verified", err)
	}
}

func TestInspectAcceptsUpstreamBase64FormsWithoutCheckingContentDigest(t *testing.T) {
	for _, content := range []string{"//8=", "//8", "__8=", "__8"} {
		var record map[string]any
		if err := json.Unmarshal(validLine(t), &record); err != nil {
			t.Fatal(err)
		}
		// Inline bytes deliberately differ from the declared subject digest:
		// this is format inspection, never artifact/digest verification.
		record["subject"].([]any)[0].(map[string]any)["content"] = content
		encoded, _ := json.Marshal(record)
		got, err := Read(bytes.NewReader(append(encoded, '\n')))
		if err != nil || got.Status != "inspected" || got.Subjects[0].Content != content {
			t.Fatalf("upstream-compatible content %q was rejected: %v", content, err)
		}
	}
}

func TestInspectBoundsDepthTokenWorkAndResourceArrays(t *testing.T) {
	base := strings.TrimSuffix(string(validLine(t)), "\n")
	deep := `"future":` + strings.Repeat("[", MaxNestingDepth+1) + "0" + strings.Repeat("]", MaxNestingDepth+1) + ","
	manyTokens := `"future":[` + strings.Repeat("0,", MaxJSONTokens) + "0],"
	for _, extension := range []string{deep, manyTokens} {
		input := "{" + extension + base[1:] + "\n"
		if _, err := Read(strings.NewReader(input)); !IsInputError(err) {
			t.Fatal("unbounded extension was accepted", err)
		}
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal([]byte(base), &fields)
	fields["subject"] = json.RawMessage("[" + strings.Repeat(`{"digest":{"sha256":"`+helloSHA256+`"}},`, MaxArtifacts) + `{"digest":{"sha256":"` + helloSHA256 + `"}}]`)
	tooMany, _ := json.Marshal(fields)
	if _, err := Read(bytes.NewReader(append(tooMany, '\n'))); !IsInputError(err) {
		t.Fatal("oversized subjects were accepted", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("synthetic I/O failure") }

func TestInspectPreservesIOFailuresAsToolErrors(t *testing.T) {
	if _, err := Read(failingReader{}); err == nil || IsInputError(err) {
		t.Fatal("I/O failure was misclassified", err)
	}
}

func FuzzRead(f *testing.F) {
	line, _ := Build(fixtureOptions(false))
	f.Add(line)
	f.Add([]byte("{}\n"))
	f.Add([]byte("[\n"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Read(bytes.NewReader(input))
	})
}
