package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const policyUsage = `allowit policy runs the owner's policy lifecycle through the AllowIt SDK CLI.

The SDK CLI (Node 22) does the work: it generates the pinned Rust policy and its parameters,
signs with the owner's key, keeps its journal and talks to the network. This
command only checks the arguments and runs it. No ALLOWIT_TOKEN is needed.
The default network is Testnet. ALLOWIT_NETWORK=solana:devnet is explicit;
configure its RPC as well. The SDK refuses Mainnet. Generate never signs.
Execute uses only the executor key and ALLOWIT_OWNER public key; status has no signer.

Configuration (environment only):
  ALLOWIT_SDK_CLI  absolute path to the SDK's native/cli.mjs
                   (default: native-sdk/cli.mjs beside the allowit executable)
  ALLOWIT_NODE     Node 22 executable (default: node, found on PATH)

Commands:
  allowit policy generate PROMPT          generate a policy from one prompt;
                                          prints the generated Rust source
  allowit policy import EXECUTOR_JSON      import the browser policy bundle
  allowit policy deploy                   deploy the generated policy; prints
                                          the generated skill and the
                                          transaction's explorer link
  allowit policy fund AMOUNT              fund the policy; prints the
                                          transaction's explorer link
  allowit policy execute RECIPIENT AMOUNT pay AMOUNT to RECIPIENT, a Solana
                                          token account, under the policy
  allowit policy status                   show the deployed policy's state
  allowit policy revoke                   revoke the deployed policy
  allowit policy withdraw AMOUNT          withdraw unspent funds
  allowit policy tune VALUE               change the policy's tunable value

  Every command accepts --json: the SDK prints a machine-readable result on
  stdout instead. Progress and errors go to stderr.

Arguments:
  PROMPT is a single argument: quote it. AMOUNT is a positive decimal such as
  5 or 0.25; VALUE is a non-negative decimal. No sign, exponent or separator.
  The SDK checks precision and limits. Use -- before a PROMPT that begins
  with -.

Set ALLOWIT_REQUEST_ID to a fresh ID for each new intended operation. Keep
it unchanged for retries; exit 6 is an earlier receipt, not a new payment.

Exit status is the SDK CLI's own. allowit exits 2 for invalid arguments and 3
when the SDK CLI cannot be found or started, before anything runs.
`

// policyCommand is one lifecycle command and the positional arguments it takes.
type policyCommand struct {
	args  []string
	check func([]string) error
}

var policyCommands = map[string]policyCommand{
	"import":   {[]string{"EXECUTOR_JSON"}, nil},
	"generate": {[]string{"PROMPT"}, func(a []string) error { return checkPrompt(a[0]) }},
	"deploy":   {nil, nil},
	"fund":     {[]string{"AMOUNT"}, func(a []string) error { return checkDecimal("AMOUNT", a[0], true) }},
	"execute": {[]string{"RECIPIENT", "AMOUNT"}, func(a []string) error {
		if !solanaAddress(a[0]) {
			return usagef("RECIPIENT %q is not a Solana token account address", a[0])
		}
		return checkDecimal("AMOUNT", a[1], true)
	}},
	"status":   {nil, nil},
	"revoke":   {nil, nil},
	"withdraw": {[]string{"AMOUNT"}, func(a []string) error { return checkDecimal("AMOUNT", a[0], true) }},
	"tune":     {[]string{"VALUE"}, func(a []string) error { return checkDecimal("VALUE", a[0], false) }},
}

// Plain decimals only. The length cap keeps absurd input out of the SDK; the
// SDK decides the precision and range each command accepts.
var decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)

const maxDecimalLength = 40

func checkDecimal(name, v string, positive bool) error {
	kind := "a non-negative decimal"
	if positive {
		kind = "a positive decimal"
	}
	if len(v) > maxDecimalLength || !decimalPattern.MatchString(v) || positive && strings.Trim(v, "0.") == "" {
		return usagef("%s %q must be %s such as 5 or 0.25 (no sign, exponent or separator)", name, v, kind)
	}
	return nil
}

func checkPrompt(p string) error {
	if strings.TrimSpace(p) == "" {
		return usagef("PROMPT must not be empty")
	}
	return nil
}

// Command is one SDK CLI invocation. The program is run directly with these
// arguments, never through a shell.
type Command struct {
	Path   string
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// CommandRunner runs a command to completion and returns its exit status. An
// error means it could not be started or waited for.
type CommandRunner func(Command) (int, error)

// execRunner runs the command with the process's environment. While it runs,
// an interrupt from the terminal reaches the child through the process group,
// so allowit only waits; a termination request sent to allowit alone is
// passed on. Either way the child's exit status is the result.
func execRunner(c Command) (int, error) {
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-signals:
				if s != os.Interrupt {
					_ = cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return 0, err
	}
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return cmd.ProcessState.ExitCode(), nil
}

// sdkCLI finds the SDK CLI: ALLOWIT_SDK_CLI, else native-sdk/cli.mjs beside
// the allowit executable (symlinks resolved).
func (a App) sdkCLI() (string, error) {
	if p := a.Getenv("ALLOWIT_SDK_CLI"); p != "" {
		if !filepath.IsAbs(p) {
			return "", &configError{fmt.Errorf("ALLOWIT_SDK_CLI must be an absolute path to the SDK's cli.mjs, not %q", p)}
		}
		if !regularFile(p) {
			return "", &configError{fmt.Errorf("ALLOWIT_SDK_CLI %q is not a readable file", p)}
		}
		return p, nil
	}
	executable := a.Executable
	if executable == nil {
		executable = os.Executable
	}
	self, err := executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		return "", &configError{fmt.Errorf("cannot locate the allowit executable (%v); set ALLOWIT_SDK_CLI to the SDK's cli.mjs", err)}
	}
	p := filepath.Join(filepath.Dir(self), "native-sdk", "cli.mjs")
	if !regularFile(p) {
		return "", &configError{fmt.Errorf("the AllowIt SDK CLI is not installed at %s; set ALLOWIT_SDK_CLI to the absolute path of the SDK's native/cli.mjs", p)}
	}
	return p, nil
}

func regularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// parsePolicyArgs accepts --json anywhere before --, and positionals in order.
func parsePolicyArgs(args []string) (positional []string, asJSON, help bool, err error) {
	for i, arg := range args {
		switch {
		case arg == "--":
			return append(positional, args[i+1:]...), asJSON, help, nil
		case arg == "--json" || arg == "-json":
			asJSON = true
		case arg == "-h" || arg == "--help" || arg == "-help":
			help = true
		case strings.HasPrefix(arg, "-") && arg != "-":
			return nil, false, false, usagef("unknown flag %s (only --json is accepted; put -- before a PROMPT that begins with -)", arg)
		default:
			positional = append(positional, arg)
		}
	}
	return positional, asJSON, help, nil
}

// policy validates a lifecycle command and runs the SDK CLI as
// NODE CLI COMMAND [--json] [-- ARG...].
func (a App) policy(args []string, out, errOut printer) (int, error) {
	if len(args) == 0 {
		errOut.printf("%s", policyUsage)
		return exitUsage, nil
	}
	name := args[0]
	if name == "help" || name == "-h" || name == "--help" || name == "-help" {
		out.printf("%s", policyUsage)
		return exitOK, nil
	}
	cmd, ok := policyCommands[name]
	if !ok {
		return 0, usagef("unknown policy command %q (generate, import, deploy, fund, execute, status, revoke, withdraw, tune)", name)
	}
	synopsis := strings.Join(append(append([]string{"allowit policy", name}, cmd.args...), "[--json]"), " ")
	pos, asJSON, help, err := parsePolicyArgs(args[1:])
	if err != nil {
		return 0, err
	}
	if help {
		out.printf("usage: %s\n\n%s", synopsis, policyUsage)
		return exitOK, nil
	}
	if len(pos) != len(cmd.args) {
		hint := ""
		if name == "generate" && len(pos) > 1 {
			hint = " (quote the prompt so it is one argument)"
		}
		return 0, usagef("usage: %s%s", synopsis, hint)
	}
	for _, p := range pos {
		if strings.ContainsRune(p, 0) {
			return 0, usagef("arguments must not contain NUL characters")
		}
	}
	if cmd.check != nil {
		if err := cmd.check(pos); err != nil {
			return 0, err
		}
	}
	cli, err := a.sdkCLI()
	if err != nil {
		return 0, err
	}
	node := a.Getenv("ALLOWIT_NODE")
	if node == "" {
		node = "node"
	}
	argv := []string{cli, name}
	if asJSON {
		argv = append(argv, "--json")
	}
	if len(pos) > 0 {
		argv = append(append(argv, "--"), pos...)
	}
	run := a.Runner
	if run == nil {
		run = execRunner
	}
	code, err := run(Command{Path: node, Args: argv, Stdin: a.Stdin, Stdout: a.Stdout, Stderr: a.Stderr})
	if err != nil {
		return 0, &configError{fmt.Errorf("cannot run the AllowIt SDK CLI with %s (set ALLOWIT_NODE to a Node 22 executable): %v", node, err)}
	}
	if code != 0 {
		errOut.printf("allowit: policy %s: the SDK CLI exited with status %d\n", name, code)
	}
	return code, nil
}
