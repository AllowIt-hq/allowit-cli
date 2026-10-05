// This file is overlaid onto an archived AllowIt-app checkout by the Go runner.
// HTTP routes, policy persistence and the Rust WASM evaluator are real.
// Wallet identities and chain adapters use that backend's synthetic test helpers.
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type alignmentCLI struct {
	h      harnessClient
	server *httptest.Server
}

func alignmentClient(t *testing.T, h harnessClient) *alignmentCLI {
	t.Helper()
	a := &alignmentCLI{h: h}
	a.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.h.c.s.ServeHTTP(w, r)
	}))
	t.Cleanup(a.server.Close)
	h.c.s.Origins[a.server.URL] = true
	r := httptest.NewRequest("POST", "/api/micro/handoff", bytes.NewReader(encode(map[string]any{"id": h.p.ID, "revision": h.p.Revision})))
	r.Header.Set("Origin", a.server.URL)
	r.AddCookie(h.c.cookie)
	w := httptest.NewRecorder()
	h.c.s.ServeHTTP(w, r)
	var handoff struct {
		URL    string `json:"skillUrl"`
		Prompt string `json:"harnessPrompt"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &handoff) != nil {
		t.Fatalf("handoff HTTP %d", w.Code)
	}
	if handoff.URL != "" {
		u, err := url.Parse(handoff.URL)
		if err != nil {
			t.Fatal(err)
		}
		a.h.token = u.Query().Get("access_token")
	} else {
		parts := strings.Split(handoff.Prompt, "Authorization: Bearer ")
		if len(parts) != 2 {
			t.Fatal("handoff omitted bearer")
		}
		a.h.token = strings.Split(parts[1], ". Follow")[0]
	}
	if len(strings.Split(a.h.token, ".")) != 3 {
		t.Fatal("invalid handoff token")
	}
	return a
}

func (a *alignmentCLI) run(t *testing.T, code int, args ...string) map[string]any {
	t.Helper()
	// Protect gateway-generated IDs that may begin '-'.
	var wire []string
	switch args[0] {
	case "show", "status":
		wire = append([]string{args[0], "--json", "--"}, args[1:]...)
	default:
		wire = append([]string{args[0], "--json"}, args[2:]...)
		wire = append(wire, "--", args[1])
	}
	return a.raw(t, code, wire...)
}

func (a *alignmentCLI) raw(t *testing.T, code int, args ...string) map[string]any {
	t.Helper()
	bin := os.Getenv("ALLOWIT_ALIGNMENT_BINARY")
	if bin == "" {
		t.Fatal("use go run ./integration --app-repo /path/to/AllowIt-app")
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"ALLOWIT_URL=" + a.server.URL, "ALLOWIT_TOKEN=" + a.h.token}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	got := 0
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			got = e.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	secret := strings.Split(a.h.token, ".")[2]
	if strings.Contains(out.String()+errOut.String(), secret) {
		t.Fatal("CLI leaked bearer")
	}
	if got != code {
		t.Fatalf("%s: exit %d want %d\n%s\n%s", args[0], got, code, out.String(), errOut.String())
	}
	var result map[string]any
	if out.Len() > 0 && json.Unmarshal(out.Bytes(), &result) != nil {
		t.Fatal("CLI did not return JSON")
	}
	return result
}

func alignmentArgs(command, policy, id, amount, recipient string) []string {
	return []string{command, policy, "--request-id", id, "--rail", "solana", "--op", "transferUSDC", "--action", "transfer", "--addr", recipient, "--amount", amount, "--wait", "0s"}
}

func TestAlignmentAgentLifecycle(t *testing.T) {
	h := activePolicy(t, `pub async fn evaluate(ctx:&Context)->PolicyResult{set_cap(ctx,"10","USDC")?;cap_per_transaction(ctx,"6","USDC")?;Ok(())}`)
	a := alignmentClient(t, h)
	s := a.run(t, 0, "show", h.p.ID)
	if s["network"] != h.p.Network {
		t.Fatal("wrong policy network")
	}
	judgment := a.run(t, 0, alignmentArgs("eval", h.p.ID, "alignment-eval-001", "4", h.owner)...)
	if judgment["state"] != "passed" {
		t.Fatal(judgment)
	}
	q := h.request(t, judgment["requestId"].(string))
	if q.Kind != "judgment" {
		t.Fatal("eval used transaction route")
	}
	transaction := a.run(t, 10, alignmentArgs("exec", h.p.ID, "alignment-exec-001", "6", h.owner)...)
	if transaction["state"] != "owner_signature" || transaction["executed"] != false {
		t.Fatal(transaction)
	}
	q = h.request(t, transaction["requestId"].(string))
	if q.Kind != "transaction" || q.Action != "transfer" || q.Amount != "6" || q.Recipient != h.owner {
		t.Fatal("request fields did not reach gateway")
	}
	retry := a.run(t, 10, alignmentArgs("exec", h.p.ID, "alignment-exec-001", "6", h.owner)...)
	if retry["requestId"] != transaction["requestId"] {
		t.Fatal("retry created a new request")
	}
	a.run(t, 4, alignmentArgs("exec", h.p.ID, "alignment-exec-001", "5", h.owner)...)
	status := a.run(t, 10, "status", h.p.ID, q.ID)
	if status["requestId"] != q.ID || status["executed"] != false {
		t.Fatal(status)
	}
	a.run(t, 20, alignmentArgs("exec", h.p.ID, "alignment-exec-002", "5", h.owner)...)
	v, err := h.c.s.micro(context.Background(), h.owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := findPolicy(&v, h.p.ID)
	if err != nil || p.SpentUnits != 0 || reservedUnits(p, "", h.c.s.Now()) != 6000000 {
		t.Fatal("eval/retry changed spending or reservations")
	}
}

func TestAlignmentOwnerInput(t *testing.T) {
	h := activePolicy(t, `pub async fn evaluate(ctx:&Context)->PolicyResult{set_cap(ctx,"10","USDC")?;require_user_input(ctx,"Approve this transfer").await?;Ok(())}`)
	a := alignmentClient(t, h)
	r := a.run(t, 11, alignmentArgs("exec", h.p.ID, "alignment-approval", "1", h.owner)...)
	id := r["requestId"].(string)
	if r["prompt"] == "" {
		t.Fatal("owner prompt missing")
	}
	a.run(t, 11, "status", h.p.ID, id)
	q := h.request(t, id)
	h.c.ok(t, "micro/requests/answer", map[string]any{"id": h.p.ID, "revision": h.p.Revision, "requestId": id, "inputKey": q.InputKey, "approved": true})
	a.run(t, 10, "status", h.p.ID, id)
	if h.request(t, id).Status != "ready" {
		t.Fatal("owner input did not resume the same request")
	}
}
