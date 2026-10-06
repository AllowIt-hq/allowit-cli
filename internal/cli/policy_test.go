package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A valid Solana address (the System Program) used as a token account.
const tokenAccount = "11111111111111111111111111111111"

type policyRun struct {
	code     int
	stdout   string
	stderr   string
	commands []Command
}

// runPolicy runs allowit with a recording runner; no subprocess is started.
func runPolicy(t *testing.T, env map[string]string, runner func(Command) (int, error), args ...string) policyRun {
	t.Helper()
	var out, errOut bytes.Buffer
	var r policyRun
	app := App{
		Getenv: func(k string) string { return env[k] },
		Stdin:  strings.NewReader("stdin"), Stdout: &out, Stderr: &errOut,
		Runner: func(c Command) (int, error) {
			r.commands = append(r.commands, c)
			if runner == nil {
				return 0, nil
			}
			return runner(c)
		},
		Executable: func() (string, error) { return "", errors.New("no executable in tests") },
	}
	r.code = app.Run(args)
	r.stdout, r.stderr = out.String(), errOut.String()
	return r
}

func sdkFile(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "cli.mjs")
	if err := os.WriteFile(p, []byte("// SDK CLI stub; never executed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sdkEnv(t *testing.T) (map[string]string, string) {
	cli := sdkFile(t, t.TempDir())
	return map[string]string{"ALLOWIT_SDK_CLI": cli}, cli
}

func TestPolicyDispatchArgv(t *testing.T) {
	env, cli := sdkEnv(t)
	prompt := `Pay at most 5 USDC a day; "quotes", $(rm -rf /) and ; stay literal`
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"generate", prompt}, []string{cli, "generate", "--", prompt}},
		{[]string{"generate", "--json", prompt}, []string{cli, "generate", "--json", "--", prompt}},
		{[]string{"generate", prompt, "--json"}, []string{cli, "generate", "--json", "--", prompt}},
		{[]string{"generate", "--", "-dash prompt"}, []string{cli, "generate", "--", "-dash prompt"}},
		{[]string{"generate", "--json", "--", "--json"}, []string{cli, "generate", "--json", "--", "--json"}},
		{[]string{"deploy"}, []string{cli, "deploy"}},
		{[]string{"deploy", "--json"}, []string{cli, "deploy", "--json"}},
		{[]string{"fund", "12.5"}, []string{cli, "fund", "--", "12.5"}},
		{[]string{"execute", tokenAccount, "0.000001"}, []string{cli, "execute", "--", tokenAccount, "0.000001"}},
		{[]string{"execute", "--json", tokenAccount, "3"}, []string{cli, "execute", "--json", "--", tokenAccount, "3"}},
		{[]string{"status", "-json"}, []string{cli, "status", "--json"}},
		{[]string{"revoke"}, []string{cli, "revoke"}},
		{[]string{"withdraw", "1"}, []string{cli, "withdraw", "--", "1"}},
		{[]string{"tune", "0"}, []string{cli, "tune", "--", "0"}},
		{[]string{"tune", "0.75", "--json"}, []string{cli, "tune", "--json", "--", "0.75"}},
	} {
		r := runPolicy(t, env, nil, append([]string{"policy"}, c.args...)...)
		if r.code != exitOK || len(r.commands) != 1 || r.stdout != "" || r.stderr != "" {
			t.Fatalf("%q: %+v", c.args, r)
		}
		got := r.commands[0]
		if got.Path != "node" || !reflect.DeepEqual(got.Args, c.want) {
			t.Fatalf("%q: ran %q %q, want node %q", c.args, got.Path, got.Args, c.want)
		}
	}
}

// The child gets the process's own streams, so the SDK's Rust source, skill
// and explorer links reach the user unaltered and it can prompt on stdin.
func TestPolicyInheritsStreams(t *testing.T) {
	env, _ := sdkEnv(t)
	r := runPolicy(t, env, func(c Command) (int, error) {
		in := new(bytes.Buffer)
		in.ReadFrom(c.Stdin)
		fmt.Fprintf(c.Stdout, "pub fn evaluate() {} // stdin=%s\n", in)
		fmt.Fprint(c.Stderr, "compiling\n")
		return 0, nil
	}, "policy", "generate", "limit")
	if r.code != exitOK || r.stdout != "pub fn evaluate() {} // stdin=stdin\n" || r.stderr != "compiling\n" {
		t.Fatalf("%+v", r)
	}
}

func TestPolicyExitStatusPropagates(t *testing.T) {
	env, _ := sdkEnv(t)
	for _, code := range []int{0, 1, 2, 3, 7, 42, 130, 255} {
		r := runPolicy(t, env, func(Command) (int, error) { return code, nil }, "policy", "fund", "1")
		if r.code != code {
			t.Fatalf("child exited %d, allowit exited %d", code, r.code)
		}
		reported := strings.Contains(r.stderr, fmt.Sprintf("allowit: policy fund: the SDK CLI exited with status %d\n", code))
		if reported != (code != 0) || r.stdout != "" {
			t.Fatalf("exit %d: %+v", code, r)
		}
	}
}

func TestPolicyStartFailureIsConfigError(t *testing.T) {
	env, _ := sdkEnv(t)
	env["ALLOWIT_NODE"] = "/opt/node22/bin/node"
	r := runPolicy(t, env, func(Command) (int, error) { return 0, errors.New("executable file not found") }, "policy", "status")
	if r.code != exitConfig || r.commands[0].Path != "/opt/node22/bin/node" || !strings.Contains(r.stderr, "cannot run the AllowIt SDK CLI with /opt/node22/bin/node") {
		t.Fatalf("%+v", r)
	}
}

// Invalid arguments are refused before anything runs.
func TestPolicyArgumentValidation(t *testing.T) {
	env, _ := sdkEnv(t)
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"generate"}, "usage: allowit policy generate PROMPT [--json]"},
		{[]string{"generate", "pay", "bob"}, "quote the prompt"},
		{[]string{"generate", "  "}, "PROMPT must not be empty"},
		{[]string{"generate", "a\x00b"}, "NUL"},
		{[]string{"generate", "-starts with dash"}, "unknown flag"},
		{[]string{"deploy", "extra"}, "usage: allowit policy deploy [--json]"},
		{[]string{"status", "x"}, "usage: allowit policy status [--json]"},
		{[]string{"revoke", "x"}, "usage: allowit policy revoke [--json]"},
		{[]string{"fund"}, "usage: allowit policy fund AMOUNT [--json]"},
		{[]string{"fund", "1", "2"}, "usage: allowit policy fund AMOUNT"},
		{[]string{"execute", tokenAccount}, "usage: allowit policy execute RECIPIENT AMOUNT [--json]"},
		{[]string{"execute", "not-an-account", "1"}, "is not a Solana token account address"},
		{[]string{"execute", tokenAccount, "0"}, "positive decimal"},
		{[]string{"withdraw"}, "usage: allowit policy withdraw AMOUNT"},
		{[]string{"tune"}, "usage: allowit policy tune VALUE"},
		{[]string{"tune", "-1"}, "unknown flag"},
		{[]string{"tune", "--", "-1"}, "non-negative decimal"},
		{[]string{"deploy", "--network", "mainnet"}, "unknown flag --network"},
		{[]string{"deploy", "--json=false"}, "unknown flag"},
		{[]string{"mint"}, `unknown policy command "mint"`},
	} {
		r := runPolicy(t, env, nil, append([]string{"policy"}, c.args...)...)
		if r.code != exitUsage || len(r.commands) != 0 || !strings.Contains(r.stderr, c.msg) {
			t.Fatalf("%q: %+v", c.args, r)
		}
	}
	for _, cmd := range []string{"fund", "withdraw", "tune"} {
		for _, v := range []string{"", "0", "0.0", "00", "01", "1.", ".5", "+1", "-1", "1e3", "1,000", "0x10", " 1", "NaN", strings.Repeat("9", 41)} {
			if cmd == "tune" && (v == "0" || v == "0.0") {
				continue
			}
			r := runPolicy(t, env, nil, "policy", cmd, "--", v)
			if r.code != exitUsage || len(r.commands) != 0 {
				t.Fatalf("%s %q accepted: %+v", cmd, v, r)
			}
		}
	}
	for _, v := range []string{"1", "0.25", "1000000", "0.000000001", "10.10"} {
		if r := runPolicy(t, env, nil, "policy", "withdraw", v); r.code != exitOK || len(r.commands) != 1 {
			t.Fatalf("withdraw %q refused: %+v", v, r)
		}
	}
}

func TestPolicyHelp(t *testing.T) {
	for _, args := range [][]string{{"policy", "help"}, {"policy", "--help"}, {"policy", "-h"}, {"policy", "deploy", "--help"}, {"policy", "execute", "-h"}} {
		r := runPolicy(t, map[string]string{}, nil, args...)
		if r.code != exitOK || len(r.commands) != 0 {
			t.Fatalf("%q: %+v", args, r)
		}
		for _, want := range []string{"prints the generated Rust source", "generated skill and the", "explorer link", "--json", "ALLOWIT_SDK_CLI", "ALLOWIT_NODE", "No ALLOWIT_TOKEN is needed", "Testnet", "Mainnet"} {
			if !strings.Contains(r.stdout, want) {
				t.Fatalf("%q: help lacks %q:\n%s", args, want, r.stdout)
			}
		}
	}
	if r := runPolicy(t, map[string]string{}, nil, "policy", "fund", "--help"); !strings.HasPrefix(r.stdout, "usage: allowit policy fund AMOUNT [--json]\n") {
		t.Fatal(r.stdout)
	}
	if r := runPolicy(t, map[string]string{}, nil, "policy"); r.code != exitUsage || !strings.Contains(r.stderr, "allowit policy generate PROMPT") || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	if r := runPolicy(t, map[string]string{}, nil, "help"); !strings.Contains(r.stdout, "allowit policy generate|deploy") {
		t.Fatal(r.stdout)
	}
}

func TestPolicySDKLocation(t *testing.T) {
	// The SDK shipped beside the executable, found through a symlink.
	install := t.TempDir()
	if err := os.Mkdir(filepath.Join(install, "native-sdk"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundled := sdkFile(t, filepath.Join(install, "native-sdk"))
	bin := filepath.Join(install, "allowit")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "allowit")
	if err := os.Symlink(bin, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	app := func(env map[string]string, exe string) (App, *[]Command, *bytes.Buffer) {
		var ran []Command
		errOut := new(bytes.Buffer)
		return App{
			Getenv: func(k string) string { return env[k] }, Stdout: new(bytes.Buffer), Stderr: errOut,
			Runner:     func(c Command) (int, error) { ran = append(ran, c); return 0, nil },
			Executable: func() (string, error) { return exe, nil },
		}, &ran, errOut
	}
	resolved, err := filepath.EvalSymlinks(bundled)
	if err != nil {
		t.Fatal(err)
	}
	a, ran, _ := app(map[string]string{}, link)
	if code := a.Run([]string{"policy", "deploy"}); code != exitOK || (*ran)[0].Args[0] != resolved {
		t.Fatalf("bundled SDK not used: %d %+v", code, *ran)
	}

	// ALLOWIT_SDK_CLI takes precedence over the bundled SDK.
	configured := sdkFile(t, t.TempDir())
	a, ran, _ = app(map[string]string{"ALLOWIT_SDK_CLI": configured}, link)
	if code := a.Run([]string{"policy", "deploy"}); code != exitOK || (*ran)[0].Args[0] != configured {
		t.Fatalf("ALLOWIT_SDK_CLI not used: %d %+v", code, *ran)
	}

	for _, c := range []struct {
		env map[string]string
		exe string
		msg string
	}{
		{map[string]string{"ALLOWIT_SDK_CLI": "native/cli.mjs"}, link, "must be an absolute path"},
		{map[string]string{"ALLOWIT_SDK_CLI": filepath.Join(install, "missing.mjs")}, link, "is not a readable file"},
		{map[string]string{"ALLOWIT_SDK_CLI": install}, link, "is not a readable file"},
		{map[string]string{}, filepath.Join(t.TempDir(), "allowit"), "set ALLOWIT_SDK_CLI"},
	} {
		if c.exe != link {
			os.WriteFile(c.exe, nil, 0o755)
		}
		a, ran, errOut := app(c.env, c.exe)
		if code := a.Run([]string{"policy", "status"}); code != exitConfig || len(*ran) != 0 || !strings.Contains(errOut.String(), c.msg) {
			t.Fatalf("%v: %d %q", c.env, code, errOut.String())
		}
	}
}

// Owner lifecycle commands need no harness token and never read one.
func TestPolicyNeedsNoHarnessToken(t *testing.T) {
	env, _ := sdkEnv(t)
	r := runPolicy(t, env, nil, "policy", "status")
	if r.code != exitOK || len(r.commands) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestVersion(t *testing.T) {
	if r := runPolicy(t, map[string]string{}, nil, "version"); r.stdout != "allowit 0.3.0-dev\n" {
		t.Fatal(r.stdout)
	}
}
