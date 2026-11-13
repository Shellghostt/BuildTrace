// Package metadata collects the facts about a build that belong in a
// manifest.
//
// The rule that shapes this package: an allowlist. The collector reads
// exactly the fields it names and nothing else. It never dumps the
// environment, never reads a credential file, and never runs a shell. A
// secret can only reach the manifest if the user puts it in an explicit
// input, and the one place where that could happen by accident, the git
// remote URL, is redacted.
package metadata

import (
	"strings"
)

// Source describes the repository the build came from.
type Source struct {
	// URI is the canonical remote of the repository, in git+ URI form:
	// "git+https://github.com/shellghostt/eventrelay". It is empty when the
	// repository has no remote.
	URI string `json:"uri"`
	// Commit is the full 40-character commit SHA of HEAD.
	Commit string `json:"commit"`
	// Dirty is true when the working tree has changes that are not
	// committed, including untracked files.
	Dirty bool `json:"dirty"`
}

// Builder describes who ran the build.
type Builder struct {
	// ID identifies the builder. It is an explicit input, not a guess.
	ID string `json:"id"`
	// Host is the machine name.
	Host string `json:"host"`
	// OS and Arch are the operating system and architecture the binary runs
	// on.
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// Toolchain describes the tools that took part in the build.
type Toolchain struct {
	// Go is the Go version the build ran under, without the "go" prefix.
	Go string `json:"go"`
	// Git is the version of the git binary, without the "git version "
	// prefix. It is empty when git is not installed.
	Git string `json:"git,omitempty"`
}

// NormalizeGitURI turns a git remote into the git+ URI form and removes any
// credentials that may be embedded in it.
//
// A remote like "https://user:token@example.com/repo.git" must never reach a
// manifest: manifests get uploaded, committed and attached to releases.
//
// The forms handled here are the ones git itself produces:
//
//	https://github.com/owner/repo.git   -> git+https://github.com/owner/repo
//	git@github.com:owner/repo.git       -> git+ssh://github.com/owner/repo
//	ssh://git@github.com/owner/repo.git -> git+ssh://github.com/owner/repo
//	https://token@github.com/owner/repo -> git+https://github.com/owner/repo
func NormalizeGitURI(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}

	switch {
	case strings.HasPrefix(remote, "git+"):
		// Already a git+ URI. Strip the credentials anyway.
		return "git+" + stripCredentials(strings.TrimPrefix(remote, "git+"))
	case strings.HasPrefix(remote, "http://"), strings.HasPrefix(remote, "https://"):
		return "git+" + stripCredentials(remote)
	case strings.HasPrefix(remote, "ssh://"):
		return "git+" + stripCredentials(remote)
	case strings.HasPrefix(remote, "git://"):
		return "git+" + stripCredentials(remote)
	case isWindowsPath(remote):
		// A local path such as C:\repos\eventrelay. The colon is a drive
		// letter, not a scp-like separator.
		return remote
	case strings.Contains(remote, ":") && !strings.Contains(remote, "://"):
		// The scp-like form: git@github.com:owner/repo.git
		host, path, found := strings.Cut(remote, ":")
		if !found {
			return remote
		}
		if _, hostOnly, hasUser := strings.Cut(host, "@"); hasUser {
			host = hostOnly
		}
		return "git+ssh://" + host + "/" + strings.TrimSuffix(strings.TrimPrefix(path, "/"), ".git")
	default:
		// A local path. It is recorded as-is: it contains no secret, and
		// pretending to know more about it would be a guess.
		return remote
	}
}

// isWindowsPath reports whether the value starts with a drive letter.
func isWindowsPath(value string) bool {
	if len(value) < 2 || value[1] != ':' {
		return false
	}
	letter := value[0]
	return ('a' <= letter && letter <= 'z') || ('A' <= letter && letter <= 'Z')
}

// stripCredentials removes the userinfo part of a URL.
func stripCredentials(rawURL string) string {
	scheme, rest, found := strings.Cut(rawURL, "://")
	if !found {
		return strings.TrimSuffix(rawURL, ".git")
	}

	authority, path, hasPath := strings.Cut(rest, "/")
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}

	if !hasPath {
		return scheme + "://" + authority
	}
	return scheme + "://" + authority + "/" + strings.TrimSuffix(path, ".git")
}
