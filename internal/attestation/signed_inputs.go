package attestation

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shellghostt/buildtrace/internal/hashing"
)

// CollectSigned uses the M3 selection/name contract and M2 canonical hashes,
// anchored to the checkout root for the duration of signed capture. The M3
// default collector remains unchanged.
func CollectSigned(rootPath string, selections []string) ([]Observation, error) {
	if len(selections) == 0 || len(selections) > MaxArtifacts {
		return nil, invalid("select between 1 and 1000 artifacts")
	}
	rootPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	seen := map[string]bool{}
	observations := make([]Observation, 0, len(selections))
	for _, selection := range selections {
		if !publicString(selection) || strings.TrimSpace(selection) == "" {
			return nil, invalid("artifact path must be a bounded public path")
		}
		absolute := selection
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(rootPath, absolute)
		}
		absolute = filepath.Clean(absolute)
		parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			return nil, err
		}
		relative, err := filepath.Rel(rootPath, filepath.Join(parent, filepath.Base(absolute)))
		name := filepath.ToSlash(relative)
		if err != nil || !artifactName(name) {
			return nil, invalid("artifact must be inside the repository root")
		}
		key := name
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seen[key] {
			return nil, invalid("duplicate or colliding artifact name")
		}
		seen[key] = true
		result, err := hashing.HashRoot(root, relative)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, invalid("artifact does not exist")
			}
			if errors.Is(err, hashing.ErrChanged) {
				return nil, invalid("artifact changed while hashing; stop writers and retry")
			}
			return nil, err
		}
		observations = append(observations, Observation{Name: name, Kind: result.Kind, Size: result.Size, SHA256: result.SHA256})
	}
	return observations, nil
}
