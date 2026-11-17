// These tests use pinned upstream generated Protobuf types and validators.
// They establish format compatibility, not a SLSA level or an honest build.
package schemas

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	provenance "github.com/in-toto/attestation/go/predicates/provenance/v1"
	statement "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func validate(data []byte) error {
	var record statement.Statement
	decoder := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := decoder.Unmarshal(data, &record); err != nil {
		return err
	}
	if record.GetType() != statement.StatementTypeUri || record.GetPredicateType() != "https://slsa.dev/provenance/v1" {
		return fmt.Errorf("unsupported statement/predicate URI")
	}
	if err := record.Validate(); err != nil {
		return err
	}
	predicate, err := protojson.Marshal(record.GetPredicate())
	if err != nil {
		return err
	}
	var slsa provenance.Provenance
	if err := decoder.Unmarshal(predicate, &slsa); err != nil {
		return err
	}
	return slsa.Validate()
}

func TestFixturesValidateWithPinnedUpstreamTypes(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join("..", "fixtures", "m3", "*.intoto.jsonl"))
	if err != nil || len(fixtures) != 2 {
		t.Fatal("expected two distinct committed fixtures", err)
	}
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			data, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			if err := validate(data); err != nil {
				t.Fatalf("upstream schema/required-field validation failed: %v", err)
			}
		})
	}
}

func TestUpstreamValidationRejectsMalformedRequiredFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "m3", "observed.intoto.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"wrong statement": func(r map[string]any) { r["_type"] = "https://in-toto.io/Statement/v2" },
		"wrong predicate": func(r map[string]any) { r["predicateType"] = "https://slsa.dev/provenance/v1.2" },
		"no subject":      func(r map[string]any) { r["subject"] = []any{} },
		"no digest":       func(r map[string]any) { r["subject"].([]any)[0].(map[string]any)["digest"] = map[string]any{} },
		"no build type": func(r map[string]any) {
			delete(r["predicate"].(map[string]any)["buildDefinition"].(map[string]any), "buildType")
		},
		"wrong external type": func(r map[string]any) {
			r["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"] = []any{}
		},
		"no builder": func(r map[string]any) {
			delete(r["predicate"].(map[string]any)["runDetails"].(map[string]any), "builder")
		},
		"no builder ID": func(r map[string]any) {
			delete(r["predicate"].(map[string]any)["runDetails"].(map[string]any)["builder"].(map[string]any), "id")
		},
	} {
		t.Run(name, func(t *testing.T) {
			var record map[string]any
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			change(record)
			invalid, _ := json.Marshal(record)
			if err := validate(invalid); err == nil {
				t.Fatal("malformed required field passed upstream validation")
			}
		})
	}
}

func TestUpstreamCompatibleBase64FormsAndFullGitCommit(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "m3", "claimed.intoto.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"//8=", "//8", "__8=", "__8"} {
		var record map[string]any
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		record["subject"].([]any)[0].(map[string]any)["content"] = content
		dependency := record["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["resolvedDependencies"].([]any)[0].(map[string]any)
		dependency["digest"].(map[string]any)["gitCommit"] = strings.Repeat("b", 64)
		encoded, _ := json.Marshal(record)
		if err := validate(encoded); err != nil {
			t.Fatalf("compatible upstream representation %q failed: %v", content, err)
		}
	}
}

func TestPinnedSchemaSourcesAndLicensesMatchChecksums(t *testing.T) {
	data, err := os.ReadFile("UPSTREAM.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		File       string `json:"file"`
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		SHA256     string `json:"sha256"`
	}
	if err := json.Unmarshal(data, &entries); err != nil || len(entries) != 6 {
		t.Fatal("invalid source pin manifest", err)
	}
	for _, entry := range entries {
		wantCommit := "50bf01716982189898823e90586075f37cd9bb7d"
		if entry.Repository == "slsa-framework/slsa" {
			wantCommit = "19e4e2f005f871270c4f555fc47afecfb37f3efe"
		}
		if entry.Commit != wantCommit || !strings.HasPrefix(entry.File, "upstream/") || strings.Contains(entry.File, "..") {
			t.Fatal("unexpected schema source pin", entry)
		}
		contents, err := os.ReadFile(filepath.FromSlash(entry.File))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		if hex.EncodeToString(digest[:]) != entry.SHA256 {
			t.Fatal("archived schema/license checksum changed", entry.File)
		}
	}
}
