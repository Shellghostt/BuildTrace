// Command buildtrace records artifact observations and verifies selected bytes
// under explicit unsigned-manifest or external signer policy.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/shellghostt/buildtrace/internal/cli"
)

// version is overridden at build time with:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	app := &cli.App{
		Version: version,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Context: ctx,
	}
	code := app.Run(os.Args[1:])
	stop()
	os.Exit(code)
}
