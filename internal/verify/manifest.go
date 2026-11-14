// Package verify recomputes artifacts against unsigned manifests in M2.
package verify

import (
	"fmt"
	"path/filepath"

	"github.com/shellghostt/buildtrace/internal/hashing"
	"github.com/shellghostt/buildtrace/internal/manifest"
)

type Report struct {
	Scope    string `json:"scope"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Artifact string `json:"artifact,omitempty"`
	Path     string `json:"path,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Verified int    `json:"verified"`
}

func Check(m manifest.Manifest, root string) (Report, error) {
	report := Report{Scope: "unsigned_manifest", Status: "failed"}
	for _, a := range m.Artifacts {
		report.Artifact = a.Name
		report.Path = a.Path
		path := filepath.FromSlash(a.Path)
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		actual, err := hashing.Hash(path)
		if err != nil {
			report.Reason = "artifact_unreadable"
			return report, fmt.Errorf("artifact %q (%s): %w", a.Name, a.Path, err)
		}
		if a.Kind != actual.Kind {
			report.Reason = "kind_mismatch"
			report.Expected = a.Kind
			report.Actual = actual.Kind
			return report, nil
		}
		if a.Digest.SHA256 != actual.SHA256 {
			report.Reason = "digest_mismatch"
			report.Expected = a.Digest.SHA256
			report.Actual = actual.SHA256
			return report, nil
		}
		if a.Size != actual.Size {
			report.Reason = "size_mismatch"
			report.Expected = fmt.Sprint(a.Size)
			report.Actual = fmt.Sprint(actual.Size)
			return report, nil
		}
		report.Verified++
	}
	report.Status = "matched"
	report.Artifact = ""
	report.Path = ""
	return report, nil
}
