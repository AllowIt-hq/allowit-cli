package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Exit codes. Scripts and agents branch on these; keep them stable.
const (
	exitOK             = 0
	exitUsage          = 2
	exitConfig         = 3
	exitRejected       = 4
	exitUncertain      = 5
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
	case r["executed"] == true || status == "settled":
		return result{"settled", exitOK, "The transfer is confirmed on chain."}
	case r["localRecorded"] == true || status == "recorded":
		return result{"recorded", exitOK, "Local dev: the action was recorded against the policy budget. No funds moved; a mock receipt is not proof of payment."}
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

func (p printer) field(key string, v any) {
	switch x := v.(type) {
	case nil:
	case string:
		if x != "" {
			p.printf("%s: %s\n", key, x)
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
			p.printf("%s: %s\n", key, strings.Join(parts, "; "))
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
