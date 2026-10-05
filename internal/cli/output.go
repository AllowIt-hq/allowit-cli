package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Exit codes. Scripts and agents branch on these; keep them stable.
const (
	exitOK             = 0
	exitUsage          = 2
	exitConfig         = 3
	exitRejected       = 4
	exitUncertain      = 5
	exitReplayed       = 6
	exitOwnerSignature = 10
	exitAwaitingInput  = 11
	exitPending        = 12
	exitDenied         = 20
)

type result struct {
	State string
	Exit  int
	Note  string
}

// classify maps a harness request result onto a CLI state. command is eval,
// exec or status. The server's kind ("judgment" or "transaction") decides what
// a ready request means; without it, status never reports ready as complete.
func classify(r map[string]any, command string) result {
	outcome, status, kind := str(r["outcome"]), str(r["status"]), str(r["kind"])
	if kind == "" && command == "eval" {
		kind = "judgment"
	} else if kind == "" && command == "exec" {
		kind = "transaction"
	}
	switch {
	case r["localRecorded"] == true || status == "recorded":
		return result{"recorded", exitOK, "Local dev: the action was recorded against the policy budget. No funds moved; a mock receipt is not proof of payment."}
	case r["executed"] == true || status == "settled":
		return result{"settled", exitOK, "The transfer is confirmed on chain."}
	case outcome == "awaiting_input":
		return result{"awaiting_input", exitAwaitingInput, "The owner must answer this question in AllowIt. Stop, report the prompt, then check again with `allowit status`."}
	case outcome == "pending":
		return result{"pending", exitPending, "The policy is still evaluating. Check again with `allowit status`."}
	case outcome != "pass":
		return result{"denied", exitDenied, "The policy did not permit this request."}
	case status == "submitted":
		return result{"owner_signature", exitOwnerSignature, "The owner's wallet transaction was submitted and is waiting for network confirmation. Nothing is confirmed yet."}
	case status == "ready" && kind == "judgment":
		return result{"passed", exitOK, "The policy permits this exact request. Nothing was spent or reserved."}
	case status == "ready" && kind == "transaction":
		return result{"owner_signature", exitOwnerSignature, "The policy passed. The owner must review and sign this transfer in AllowIt; nothing has been paid yet."}
	}
	return result{"ready", exitOwnerSignature, "The policy passed, but this request is not complete: nothing is confirmed as recorded or paid. Check again with `allowit status`."}
}

// knownStates lists the status each outcome may carry. Anything else is
// incomplete or contradictory and is reported as uncertain.
var knownStates = map[string]map[string]bool{
	"pass":           {"ready": true, "submitted": true, "recorded": true, "settled": true},
	"pending":        {"evaluating": true},
	"awaiting_input": {"awaiting_input": true},
	"fail":           {"denied": true},
}

// checkResult rejects a harness result the CLI cannot report with certainty:
// a missing or unknown outcome or status, mistyped fields, or fields that
// contradict each other, the command or the policy's network. Only a
// consistent result may be reported as passed, recorded, settled or denied.
// With netUnknown the network checks cannot run; see needsNetwork.
func checkResult(r map[string]any, command string, net netKind) error {
	if r == nil {
		return errors.New("AllowIt returned an empty result")
	}
	outcome, ok := r["outcome"].(string)
	if !ok {
		return errors.New("AllowIt returned a result without an outcome")
	}
	for _, k := range []string{"status", "kind", "requestId"} {
		if v := r[k]; v != nil {
			if _, ok := v.(string); !ok {
				return fmt.Errorf("AllowIt returned a result with an invalid %s", k)
			}
		}
	}
	for _, k := range []string{"executed", "localRecorded"} {
		if v := r[k]; v != nil {
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("AllowIt returned a result with an invalid %s", k)
			}
		}
	}
	status, kind := str(r["status"]), str(r["kind"])
	executed, recorded := r["executed"] == true, r["localRecorded"] == true
	states, ok := knownStates[outcome]
	switch {
	case !ok:
		return fmt.Errorf("AllowIt returned an unknown outcome %q", outcome)
	case !states[status]:
		return fmt.Errorf("AllowIt returned outcome %q with status %q", outcome, status)
	// executed and localRecorded must agree with the status, never override it.
	case executed != (status == "settled"):
		return fmt.Errorf("AllowIt returned status %q with executed %v", status, r["executed"])
	case recorded != (status == "recorded"):
		return fmt.Errorf("AllowIt returned status %q with localRecorded %v", status, r["localRecorded"])
	case net == netLocal && (status == "settled" || status == "submitted"):
		return errors.New("AllowIt reported an on-chain transaction for a Local dev policy")
	case net == netWallet && status == "recorded":
		return errors.New("AllowIt reported a mock recording for a wallet policy")
	case kind != "" && kind != "judgment" && kind != "transaction":
		return fmt.Errorf("AllowIt returned an unknown kind %q", kind)
	case command == "eval" && kind == "transaction", command == "exec" && kind == "judgment":
		return fmt.Errorf("AllowIt returned a %q result for %s", kind, command)
	case (command == "eval" || kind == "judgment") && (status == "settled" || status == "recorded" || status == "submitted"):
		return errors.New("AllowIt reported a spend for a permission check")
	}
	return nil
}

// needsNetwork reports whether a valid result means something different on
// Local dev and on a wallet network: a recording, a transfer, or a ready
// transaction (owner signature on a wallet network). Pending, owner input,
// denied and a passed judgment mean the same everywhere.
func needsNetwork(r map[string]any) bool {
	switch str(r["status"]) {
	case "recorded", "settled", "submitted":
		return true
	case "ready":
		return str(r["kind"]) != "judgment"
	}
	return false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// scrubber removes credentials and terminal control sequences from everything
// the CLI prints, including server-supplied text. The full ALLOWIT_TOKEN value
// is always redacted, whatever its length; its secret part is redacted when it
// is long enough not to match ordinary text (valid secrets are at least 16).
type scrubber struct{ secrets []string }

func newScrubber(raw string) scrubber {
	var s scrubber
	for _, v := range []string{raw, strings.TrimSpace(raw)} {
		if v != "" {
			s.secrets = append(s.secrets, v)
		}
	}
	if parts := strings.Split(strings.TrimSpace(raw), "."); len(parts) == 3 && len(parts[2]) >= 8 {
		s.secrets = append(s.secrets, parts[2])
	}
	return s
}

func (s scrubber) clean(v string) string {
	for _, secret := range s.secrets {
		v = strings.ReplaceAll(v, secret, "[redacted]")
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return '?'
		}
		return r
	}, v)
}

type printer struct {
	w io.Writer
	s scrubber
}

func (p printer) printf(format string, a ...any) {
	fmt.Fprint(p.w, p.s.clean(fmt.Sprintf(format, a...)))
}

func (p printer) json(v any) {
	p.printf("%s\n", indentJSON(v))
}

func indentJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

var leadingFields = []string{"outcome", "status", "kind", "reason", "decisionCode", "workflowNodeId", "prompt", "requestId", "revision", "sourceHash", "expiresAt", "signature", "executed", "localRecorded"}

// printResult shows every field the server returned, known fields first, so
// diagnostics added by the server (codes, failing steps) are never hidden.
func (p printer) printResult(r map[string]any, res result, clientID string) {
	p.printf("state: %s\n", res.State)
	p.printf("%s\n", res.Note)
	if clientID != "" {
		p.printf("clientRequestId: %s\n", clientID)
	}
	seen := map[string]bool{}
	for _, k := range leadingFields {
		seen[k] = true
		p.field(k, r[k])
	}
	keys := make([]string, 0, len(r))
	for k := range r {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.field(k, r[k])
	}
}

// oneLine quotes a value that spans lines, so server text cannot add lines
// that read as fields (for example "state: settled").
func oneLine(s string) string {
	if strings.ContainsAny(s, "\r\n\u0085  ") {
		return strconv.Quote(s)
	}
	return s
}

func (p printer) field(key string, v any) {
	switch x := v.(type) {
	case nil:
	case string:
		if x != "" {
			p.printf("%s: %s\n", key, oneLine(x))
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p.field(key+"."+k, x[k])
		}
	case []any:
		if len(x) == 0 {
			return
		}
		parts := make([]string, len(x))
		simple := true
		for i, item := range x {
			s, ok := item.(string)
			simple = simple && ok
			parts[i] = s
		}
		if simple {
			p.printf("%s: %s\n", key, oneLine(strings.Join(parts, "; ")))
			return
		}
		for i, item := range x {
			p.field(fmt.Sprintf("%s[%d]", key, i), item)
		}
	default:
		b, _ := json.Marshal(x)
		p.printf("%s: %s\n", key, b)
	}
}
