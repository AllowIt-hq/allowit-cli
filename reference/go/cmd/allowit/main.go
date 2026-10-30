// Command allowit sends actions through an Allowit policy.
package main

import (
	"os"

	"github.com/allowit-hq/allowit-cli/internal/cli"
)

func main() {
	os.Exit(cli.App{Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}.Run(os.Args[1:]))
}
