package metadata

import (
	"strings"
	"testing"
)

func TestSigningKeysAndOIDCTokensNeverEnterGitEnvironment(t *testing.T) {
	const secret = "m4-disposable-private-material"
	for _, name := range []string{"BUILDTRACE_SIGNING_KEY", "BUILDTRACE_OIDC_TOKEN_FILE", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "GITHUB_TOKEN"} {
		t.Setenv(name, secret)
	}
	for _, value := range gitEnvironment() {
		if strings.Contains(value, secret) || strings.HasPrefix(value, "BUILDTRACE_") || strings.HasPrefix(value, "ACTIONS_ID_TOKEN_") {
			t.Fatal("signing configuration entered the git subprocess environment")
		}
	}
}
