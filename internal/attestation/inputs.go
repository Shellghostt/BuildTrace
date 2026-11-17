package attestation

import (
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shellghostt/buildtrace/internal/hashing"
	"github.com/shellghostt/buildtrace/internal/metadata"
)

// Collect hashes selected paths using the unchanged M2 canonical byte policy.
// Unlike M2 manifests, M3 subjects never expose an absolute host path.
func Collect(root string, selections []string) ([]Observation, error) {
	if len(selections) == 0 || len(selections) > MaxArtifacts {
		return nil, invalid("select between 1 and 1000 artifacts")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(selections))
	observations := make([]Observation, 0, len(selections))
	for _, selection := range selections {
		if !publicString(selection) || strings.TrimSpace(selection) == "" {
			return nil, invalid("artifact path must be a bounded public path")
		}
		absolute := selection
		if !filepath.IsAbs(absolute) {
			absolute = filepath.Join(root, absolute)
		}
		absolute = filepath.Clean(absolute)
		// Resolve parents, but never the terminal artifact symlink.
		parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, invalid("artifact does not exist")
			}
			return nil, err
		}
		resolved := filepath.Join(parent, filepath.Base(absolute))
		relative, err := filepath.Rel(root, resolved)
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
		result, err := hashing.Hash(resolved)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, invalid("artifact does not exist")
			}
			var pathError *fs.PathError
			if errors.As(err, &pathError) {
				return nil, err
			}
			return nil, invalid(err.Error())
		}
		observations = append(observations, Observation{Name: name, Kind: result.Kind, Size: result.Size, SHA256: result.SHA256})
	}
	return observations, nil
}

func artifactName(value string) bool {
	return publicString(value) && value != "." && value != ".." && !strings.HasPrefix(value, "../") &&
		!strings.Contains(value, "\\") && !strings.Contains(value, ":") && !path.IsAbs(value) && path.Clean(value) == value
}

// SanitizeObservedRemote omits local/unsupported remotes and removes URI
// userinfo, query and fragment. A checkout observation is never a source assertion.
func SanitizeObservedRemote(value string) string {
	uri, err := sanitizeSource(value)
	if err != nil {
		return ""
	}
	return uri
}

func sanitizeSource(value string) (string, error) {
	if !publicString(value) {
		return "", invalid("invalid source URI")
	}
	normalized := metadata.NormalizeGitURI(value)
	normalized = strings.TrimPrefix(normalized, "git+")
	u, err := url.Parse(normalized)
	if err != nil || u.Hostname() == "" || u.Opaque != "" {
		return "", invalid("source must be a network URI")
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "http", "ssh", "git":
	default:
		return "", invalid("unsupported source URI scheme")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
	u.Path = strings.TrimSuffix(u.Path, ".git")
	u.RawPath = ""
	return "git+" + u.String(), nil
}

func sanitizeLabel(value string, requireURI bool) (string, error) {
	if !publicString(value) || strings.TrimSpace(value) != value {
		return "", invalid("invalid public identifier")
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", invalid("invalid public identifier")
	}
	if u.IsAbs() {
		switch strings.ToLower(u.Scheme) {
		case "https", "http":
			if u.Hostname() == "" || u.Opaque != "" {
				return "", invalid("invalid public URI")
			}
			u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
			return u.String(), nil
		case "urn":
			if u.Opaque == "" || strings.ContainsAny(u.Opaque, "@?#") {
				return "", invalid("invalid public URN")
			}
			u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = "", "", "", false
			return u.String(), nil
		case "sha256":
			if !requireURI && sha256Hex(u.Opaque) {
				return value, nil
			}
		}
		return "", invalid("unsupported public identifier scheme")
	}
	if requireURI || strings.ContainsAny(value, "/\\@?#:") {
		return "", invalid("public identifier must not be a host path or credential")
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return "", invalid("invalid public identifier")
		}
	}
	return value, nil
}

// IsInputError lets the CLI distinguish invalid observations from I/O failures.
func IsInputError(err error) bool {
	var input *InputError
	return errors.As(err, &input) || errors.Is(err, os.ErrNotExist)
}
