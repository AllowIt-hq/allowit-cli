package cli

import (
	"flag"
	"reflect"
	"testing"
)

// The real gateway generates URL-safe base64 IDs, which may start with '-'.
// Protect both identifier slots when a policy AND request ID begin with a dash.
func TestEndOfOptionsPreservesGatewayIDs(t *testing.T) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	got, err := parse(fs, []string{"--json", "--", "-policy0123456789", "-request0123456789"})
	if err != nil || !*asJSON || !reflect.DeepEqual(got, []string{"-policy0123456789", "-request0123456789"}) {
		t.Fatalf("gateway identifiers treated as flags: %q %v", got, err)
	}
}

func TestDoubleDashFlagValueDoesNotEndOptions(t *testing.T) {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	merchant := fs.String("merchant", "", "")
	asJSON := fs.Bool("json", false, "")
	got, err := parse(fs, []string{"--merchant", "--", "policy0123456789", "--json"})
	if err != nil || *merchant != "--" || !*asJSON || !reflect.DeepEqual(got, []string{"policy0123456789"}) {
		t.Fatalf("flag value changed argument parsing: %q %v", got, err)
	}
}

func TestGeneratedSkillFlagsAfterIdentifiers(t *testing.T) {
	for _, name := range []string{"show", "eval", "exec", "status"} {
		t.Run(name, func(t *testing.T) {
			fs := flag.NewFlagSet(name, flag.ContinueOnError)
			asJSON := fs.Bool("json", false, "")
			action := fs.String("action", "", "")
			want := []string{"-policy0123456789"}
			if name == "status" {
				want = append(want, "-request0123456789")
			}
			args := append([]string{"--"}, want...)
			args = append(args, "--json", "--action", "transfer")
			got, err := parse(fs, args)
			if err != nil || !*asJSON || *action != "transfer" || !reflect.DeepEqual(got, want) {
				t.Fatalf("generated skill: %q %v", got, err)
			}
		})
	}
}

func TestStatusRequiresBoundRequestID(t *testing.T) {
	for _, net := range []netKind{netUnknown, netLocal, netWallet} {
		r := map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment"}
		if err := checkStatus(r, "request-1234", net); err == nil {
			t.Fatal("unbound result was accepted")
		}
		r["requestId"] = "request-1234"
		if err := checkStatus(r, "request-1234", net); err != nil {
			t.Fatal(err)
		}
	}
}
