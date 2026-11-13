// Command buildtrace records how an artifact was built and verifies one.
//
// The commands are:
//
//	buildtrace manifest --artifact dist/app --out buildtrace.json
//	buildtrace version
//
// `record`, `verify` and `inspect` arrive with the later milestones. The
// tool says so rather than pretending they exist.
//
// See docs/PLAN.md for the specification this implements.
package main

import (
	"os"

	"github.com/shellghostt/buildtrace/internal/cli"
)

// version is overridden at build time with:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

func main() {
	app := &cli.App{
		Version: version,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}
	os.Exit(app.Run(os.Args[1:]))
}
