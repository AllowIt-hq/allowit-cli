// Command allowit sends actions through an AllowIt policy.
package main

import (
	"os"

	"github.com/ackrate/allowit-cli/internal/cli"
)

func main() {
	os.Exit(cli.App{Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}.Run(os.Args[1:]))
}
