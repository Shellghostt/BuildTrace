package metadata

import (
	"strings"
	"testing"
)

func TestNormalizeGitURIConvertsTheFormsGitProduces(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{
			name:   "https remote",
			remote: "https://github.com/shellghostt/eventrelay.git",
			want:   "git+https://github.com/shellghostt/eventrelay",
		},
		{
			name:   "https remote without the git suffix",
			remote: "https://github.com/shellghostt/eventrelay",
			want:   "git+https://github.com/shellghostt/eventrelay",
		},
		{
			name:   "http remote",
			remote: "http://example.com/owner/repo.git",
			want:   "git+http://example.com/owner/repo",
		},
		{
			name:   "scp-like ssh remote",
			remote: "git@github.com:shellghostt/eventrelay.git",
			want:   "git+ssh://github.com/shellghostt/eventrelay",
		},
		{
			name:   "scp-like ssh remote without a user",
			remote: "github.com:shellghostt/eventrelay.git",
			want:   "git+ssh://github.com/shellghostt/eventrelay",
		},
		{
			name:   "ssh url remote",
			remote: "ssh://git@github.com/shellghostt/eventrelay.git",
			want:   "git+ssh://github.com/shellghostt/eventrelay",
		},
		{
			name:   "git protocol remote",
			remote: "git://github.com/shellghostt/eventrelay.git",
			want:   "git+git://github.com/shellghostt/eventrelay",
		},
		{
			name:   "already a git+ uri",
			remote: "git+https://github.com/shellghostt/eventrelay",
			want:   "git+https://github.com/shellghostt/eventrelay",
		},
		{
			name:   "surrounding whitespace is ignored",
			remote: "  https://github.com/shellghostt/eventrelay.git\n",
			want:   "git+https://github.com/shellghostt/eventrelay",
		},
		{
			name:   "a local path is left alone",
			remote: "C:\\repos\\eventrelay",
			want:   "C:\\repos\\eventrelay",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NormalizeGitURI(test.remote); got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}

func TestNormalizeGitURIRemovesCredentials(t *testing.T) {
	// The secret is the thing that matters: a manifest gets uploaded,
	// committed and attached to releases, so a token in a remote URL would
	// leak to everyone who can read the repository.
	secret := "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{
			name:   "a token in a https url",
			remote: "https://" + secret + "@github.com/shellghostt/eventrelay.git",
			want:   "git+https://github.com/shellghostt/eventrelay",
		},
		{
			name:   "a user and a password in a https url",
			remote: "https://user:" + secret + "@github.com/shellghostt/eventrelay.git",
			want:   "git+https://github.com/shellghostt/eventrelay",
		},
		{
			name:   "a token in an ssh url",
			remote: "ssh://git:" + secret + "@github.com/shellghostt/eventrelay.git",
			want:   "git+ssh://github.com/shellghostt/eventrelay",
		},
		{
			name:   "a token in an already normalised uri",
			remote: "git+https://" + secret + "@github.com/shellghostt/eventrelay",
			want:   "git+https://github.com/shellghostt/eventrelay",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NormalizeGitURI(test.remote)
			if strings.Contains(got, secret) {
				t.Fatalf("the secret survived in %q", got)
			}
			if got != test.want {
				t.Fatalf("expected %q, got %q", test.want, got)
			}
		})
	}
}

func TestNormalizeGitURIOnAnEmptyRemote(t *testing.T) {
	if got := NormalizeGitURI("   "); got != "" {
		t.Fatalf("expected an empty string, got %q", got)
	}
}
