package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	owner           = "local_owner123"
	policyID        = "policyAB12"
	secret          = "s3cretValue-_0123456789"
	token           = owner + "." + policyID + "." + secret
	stellarAccount  = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	stellarContract = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
	solanaAccount   = "11111111111111111111111111111111"
)

// fakeHarness mimics the AllowIt harness routes: bearer binding, strict body
// decoding, requestId idempotency (409 on changed details) and status lookups.
type fakeHarness struct {
	mu        sync.Mutex
	t         *testing.T
	network   string
	requests  []recorded
	byClient  map[string]stored
	byServer  map[string]map[string]any
	respond   func(action string, body map[string]any) map[string]any
	dropFirst int // hang up after reading this many transaction bodies
	hits      int
}
type recorded struct {
	Action string
	Raw    []byte
}
type stored struct {
	hash   string
	result map[string]any
}

func newFake(t *testing.T, network string) (*fakeHarness, *httptest.Server) {
	f := &fakeHarness{t: t, network: network, byClient: map[string]stored{}, byServer: map[string]map[string]any{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeHarness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if r.Header.Get("Authorization") != "Bearer "+token {
		http.Error(w, `{"error":"A scoped harness bearer token is required."}`, 401)
		return
	}
	prefix := "/api/harness/" + owner + "/" + policyID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, `{"error":"Endpoint not found."}`, 404)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, prefix)
	w.Header().Set("Content-Type", "application/json")
	if action == "skill" && r.Method == "GET" {
		json.NewEncoder(w).Encode(f.skill())
		return
	}
	raw, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, recorded{action, raw})
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var body struct {
		Execution *Plan           `json:"execution"`
		Context   json.RawMessage `json:"context"`
		RequestID string          `json:"requestId"`
		Amount    string          `json:"amount"`
		Token     string          `json:"token"`
		Action    string          `json:"action"`
		Merchant  string          `json:"merchant"`
		Recipient string          `json:"recipient"`
	}
	if d.Decode(&body) != nil {
		http.Error(w, `{"error":"Check the request fields and try again."}`, 400)
		return
	}
	if action == "status" {
		res, ok := f.byServer[body.RequestID]
		if !ok {
			http.Error(w, `{"error":"Request not found."}`, 404)
			return
		}
		json.NewEncoder(w).Encode(res)
		return
	}
	if len(body.RequestID) < 8 || body.Token != "USDC" {
		http.Error(w, `{"error":"Use a unique requestId of 8 to 100 characters."}`, 400)
		return
	}
	key := string(raw) + ":" + action
	if prev, ok := f.byClient[body.RequestID]; ok {
		if prev.hash != key {
			http.Error(w, `{"error":"That requestId was already used for different request details."}`, 409)
			return
		}
		f.reply(w, action, prev.result)
		return
	}
	var generic map[string]any
	json.Unmarshal(raw, &generic)
	res := map[string]any{"outcome": "pass", "status": "ready", "executed": false, "localRecorded": false, "reason": "Allowed.", "requestId": fmt.Sprintf("srv-%d-abcdefgh", len(f.byServer))}
	if action == "transactions" && f.network == localDev {
		res["status"], res["localRecorded"], res["reason"] = "recorded", true, "Mock execution recorded. No funds moved."
	}
	if f.respond != nil {
		res = f.respond(action, generic)
	}
	f.byClient[body.RequestID] = stored{key, res}
	f.byServer[str(res["requestId"])] = res
	f.reply(w, action, res)
}

// reply hangs up instead of answering while dropFirst is positive: the request
// was processed but the client cannot know.
func (f *fakeHarness) reply(w http.ResponseWriter, action string, res map[string]any) {
	if action == "transactions" && f.dropFirst > 0 {
		f.dropFirst--
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (f *fakeHarness) skill() map[string]any {
	s := map[string]any{
		"name": "AllowIt policy Research budget", "title": "Research budget", "policyId": policyID, "owner": owner, "status": "active",
		"network": f.network, "revision": 3, "sourceHash": "abcdef0123456789abcdef", "language": "allowit-rust-v1",
		"originalIntent": "Buy original research datasets.\n\nRevision request:\nNever above 5 USDC.",
		"policy":         "pub async fn evaluate(ctx:&Context)->PolicyResult{Ok(())}",
		"authorization":  "Bearer " + token, "accessUrl": "https://allowit.example/api/harness/x/y/skill.md?access_token=" + token,
		"budget":   map[string]any{"allocation": "10", "spent": "0.5"},
		"workflow": []any{map[string]any{"kind": "cap", "label": "Cap spending at 10 USDC", "description": "Hard limit"}},
	}
	if f.network == localDev {
		s["executionMode"] = "local"
		s["capabilities"] = map[string]any{"mode": "mock", "rails": map[string]any{"solana": []any{"SOL", "USDC"}, "stellar": []any{"XLM", "USDC"}}, "fixedTestRatesUSDC": map[string]any{"SOL": "100", "XLM": "0.1", "USDC": "1"}, "assetDecimals": map[string]any{"SOL": 9, "XLM": 7, "USDC": 6}, "callsRequireOwnerApproval": true}
	} else {
		s["executionMode"] = "owner_signed"
		s["capabilities"] = map[string]any{"rail": "solana", "assets": []any{"USDC"}, "rails": map[string]any{"solana": []any{"USDC"}}}
	}
	return s
}

func (f *fakeHarness) locked(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}
func (f *fakeHarness) clients() (n int) { f.locked(func() { n = len(f.byClient) }); return }
func (f *fakeHarness) sent() (r []recorded) {
	f.locked(func() { r = append(r, f.requests...) })
	return
}

func (f *fakeHarness) last(t *testing.T) (string, map[string]json.RawMessage) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		t.Fatal("no request")
	}
	r := f.requests[len(f.requests)-1]
	var m map[string]json.RawMessage
	json.Unmarshal(r.Raw, &m)
	return r.Action, m
}

type run struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, env map[string]string, args ...string) run {
	t.Helper()
	var out, errOut bytes.Buffer
	app := App{Getenv: func(k string) string { return env[k] }, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut, Sleep: func(time.Duration) {}, Timeout: 2 * time.Second, PollInterval: time.Millisecond}
	code := app.Run(args)
	r := run{code, out.String(), errOut.String()}
	if strings.Contains(r.stdout+r.stderr, secret) {
		t.Fatalf("secret leaked in output:\n%s\n%s", r.stdout, r.stderr)
	}
	return r
}

func env(srv *httptest.Server) map[string]string {
	return map[string]string{"ALLOWIT_URL": srv.URL, "ALLOWIT_TOKEN": token}
}

func TestExecStellarMockPlanSendsExactRequest(t *testing.T) {
	f, srv := newFake(t, localDev)
	ctx := `{ "decision": "Buy dataset", "price": 1.10000000000000000001, "note": "<b>&</b>" }`
	r := runCLI(t, env(srv), "exec", policyID, "--rail", "stellar", "--op", "transferXLM", "--addr", stellarAccount, "--amount", "5", "--data", `{"license":"ds-1"}`, "--memo", "Dataset license", "--context", ctx)
	if r.code != 0 || !strings.Contains(r.stdout, "state: recorded") || !strings.Contains(r.stdout, "No funds moved") {
		t.Fatalf("%d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	action, body := f.last(t)
	if action != "transactions" {
		t.Fatal(action)
	}
	if string(body["context"]) != `{"decision":"Buy dataset","price":1.10000000000000000001,"note":"<b>&</b>"}` {
		t.Fatal("context changed:", string(body["context"]))
	}
	if string(body["amount"]) != `"0.5"` || string(body["action"]) != `"transferXLM"` || string(body["recipient"]) != `"`+stellarAccount+`"` {
		t.Fatal(body)
	}
	var plan Plan
	json.Unmarshal(body["execution"], &plan)
	if plan.Rail != "stellar" || plan.Asset != "XLM" || plan.Quantity != "5" || plan.Data != "eyJsaWNlbnNlIjoiZHMtMSJ9" || plan.Memo != "Dataset license" {
		t.Fatal(plan)
	}
}

func TestSolanaPlanWithCallsChargesCallCosts(t *testing.T) {
	f, srv := newFake(t, localDev)
	after := `[{"type":"contract_call","contract":"` + solanaAccount + `","method":"record_receipt","args":{"ref":"x-1"},"maxCostUSDC":"0.25"}]`
	r := runCLI(t, env(srv), "eval", policyID, "--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "0.005", "--after", after, "--action", "research", "--budget", "0.75")
	if r.code != 0 || !strings.Contains(r.stdout, "state: passed") {
		t.Fatalf("%d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	action, body := f.last(t)
	if action != "judge" || string(body["amount"]) != `"0.75"` || !strings.Contains(string(body["execution"]), `"args":{"ref":"x-1"}`) {
		t.Fatal(action, body)
	}
	if r := runCLI(t, env(srv), "eval", policyID, "--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "0.005", "--after", after, "--budget", "0.5"); r.code != exitUsage {
		t.Fatal("budget mismatch accepted", r)
	}
}

func TestIdempotentRequestIDs(t *testing.T) {
	f, srv := newFake(t, localDev)
	args := []string{policyID, "--rail", "stellar", "--op", "transferUSDC", "--addr", stellarAccount, "--amount", "1", "--context", `{"a":1}`}
	id := func() string { _, b := f.last(t); return string(b["requestId"]) }
	runCLI(t, env(srv), append([]string{"exec"}, args...)...)
	first := id()
	// Whitespace-only differences in the context are the same request.
	again := append([]string{"exec"}, args...)
	again[len(again)-1] = `{ "a": 1 }`
	if r := runCLI(t, env(srv), again...); r.code != 0 || id() != first {
		t.Fatal("identical retry used a new request ID", r)
	}
	if f.clients() != 1 {
		t.Fatal("retry created a second request")
	}
	changed := append([]string{"exec"}, args...)
	changed[len(changed)-1] = `{"a":2}`
	runCLI(t, env(srv), changed...)
	if id() == first {
		t.Fatal("changed context reused the request ID")
	}
	runCLI(t, env(srv), append([]string{"eval"}, args...)...)
	if id() == first || !strings.HasPrefix(strings.Trim(id(), `"`), "cli-eval-") {
		t.Fatal("eval shares the exec ID")
	}
	explicit := runCLI(t, env(srv), append([]string{"exec", "--request-id", "order-0001"}, args...)...)
	if explicit.code != 0 || id() != `"order-0001"` {
		t.Fatal("explicit ID ignored")
	}
	// Reusing an explicit ID for different details is refused by the server.
	conflict := runCLI(t, env(srv), "exec", policyID, "--request-id", "order-0001", "--rail", "stellar", "--op", "transferUSDC", "--addr", stellarAccount, "--amount", "2")
	if conflict.code != exitRejected || !strings.Contains(conflict.stderr, "already used") {
		t.Fatal(conflict)
	}
}

func TestUncertainFailureRetriesSameRequest(t *testing.T) {
	f, srv := newFake(t, localDev)
	f.locked(func() { f.dropFirst = 1 })
	r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1")
	if r.code != 0 || f.clients() != 1 {
		t.Fatalf("retry was not idempotent: %d %d\n%s", r.code, f.clients(), r.stderr)
	}
	ids := map[string]bool{}
	sent := f.sent()
	for _, q := range sent {
		var m map[string]any
		json.Unmarshal(q.Raw, &m)
		ids[str(m["requestId"])] = true
	}
	if len(sent) != 2 || len(ids) != 1 {
		t.Fatal("retry changed the request", len(sent), ids)
	}
	f.locked(func() { f.dropFirst = 10 })
	r = runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "2")
	if r.code != exitUncertain || !strings.Contains(r.stderr, "Rerun the identical command") || !strings.Contains(r.stderr, "cli-exec-") {
		t.Fatal(r)
	}
	f.locked(func() { f.dropFirst = 0 })
	if again := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "2"); again.code != 0 || f.clients() != 2 {
		t.Fatal("rerun after uncertain failure created another spend", again, f.clients())
	}
}

func TestStatesAndExitCodes(t *testing.T) {
	cases := []struct {
		network, cmd string
		res          map[string]any
		state        string
		code         int
	}{
		{localDev, "exec", map[string]any{"outcome": "awaiting_input", "status": "awaiting_input", "prompt": "Approve the transfer and its contract calls?", "requestId": "srv-a-12345678"}, "awaiting_input", exitAwaitingInput},
		{localDev, "exec", map[string]any{"outcome": "fail", "status": "denied", "reason": "The remaining allocation is too small for this request.", "code": "BUDGET_EXCEEDED", "step": "cap", "requestId": "srv-b-12345678"}, "denied", exitDenied},
		{"solana:devnet", "exec", map[string]any{"outcome": "pass", "status": "ready", "requestId": "srv-c-12345678"}, "owner_signature", exitOwnerSignature},
		{"solana:devnet", "eval", map[string]any{"outcome": "pass", "status": "ready", "requestId": "srv-d-12345678"}, "passed", exitOK},
		{"solana:devnet", "exec", map[string]any{"outcome": "pass", "status": "settled", "executed": true, "signature": "sig", "requestId": "srv-e-12345678"}, "settled", exitOK},
	}
	for _, c := range cases {
		f, srv := newFake(t, c.network)
		f.respond = func(string, map[string]any) map[string]any { return c.res }
		r := runCLI(t, env(srv), c.cmd, policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--action", "research")
		if r.code != c.code || !strings.Contains(r.stdout, "state: "+c.state) {
			t.Fatalf("%v: %d\n%s%s", c.res, r.code, r.stdout, r.stderr)
		}
		// Every diagnostic the server returns is shown verbatim.
		for _, k := range []string{"reason", "prompt", "code", "step"} {
			if v := str(c.res[k]); v != "" && !strings.Contains(r.stdout, k+": "+v) {
				t.Fatalf("missing %s in\n%s", k, r.stdout)
			}
		}
	}
}

func TestPendingIsPolledThroughStatus(t *testing.T) {
	f, srv := newFake(t, localDev)
	f.respond = func(string, map[string]any) map[string]any {
		return map[string]any{"outcome": "pending", "status": "evaluating", "requestId": "srv-pending-1"}
	}
	go func() {
		for {
			f.mu.Lock()
			if res, ok := f.byServer["srv-pending-1"]; ok {
				res["outcome"], res["status"], res["localRecorded"] = "pass", "recorded", true
				f.mu.Unlock()
				return
			}
			f.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()
	r := runCLI(t, env(srv), "exec", policyID, "--amount", "1", "--action", "research", "--wait", "5s")
	if r.code != 0 || !strings.Contains(r.stdout, "state: recorded") {
		t.Fatal(r)
	}
	st := runCLI(t, env(srv), "status", policyID, "srv-pending-1", "--json")
	var out map[string]any
	if json.Unmarshal([]byte(st.stdout), &out) != nil || out["state"] != "recorded" || st.code != 0 {
		t.Fatal(st)
	}
	if nf := runCLI(t, env(srv), "status", policyID, "srv-missing-1"); nf.code != exitRejected || !strings.Contains(nf.stderr, "Request not found") {
		t.Fatal(nf)
	}
}

func TestWalletPolicyRules(t *testing.T) {
	f, srv := newFake(t, "solana:mainnet")
	if r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--data", "x"); r.code != exitUsage {
		t.Fatal("mock data accepted on wallet network", r)
	}
	if r := runCLI(t, env(srv), "exec", policyID, "--rail", "stellar", "--op", "transferXLM", "--addr", stellarAccount, "--amount", "1"); r.code != exitUsage {
		t.Fatal("stellar accepted on wallet network", r)
	}
	if r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--amount", "1"); r.code != exitUsage {
		t.Fatal("wallet exec without recipient", r)
	}
	r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "2.5", "--action", "research", "--merchant", "research.example")
	if r.code != exitOwnerSignature {
		t.Fatal(r)
	}
	_, body := f.last(t)
	if _, has := body["execution"]; has || string(body["amount"]) != `"2.5"` || string(body["merchant"]) != `"research.example"` {
		t.Fatal(body)
	}
}

func TestLocalValidationBeforeNetwork(t *testing.T) {
	f, srv := newFake(t, localDev)
	for _, args := range [][]string{
		{"--rail", "ethereum", "--op", "transferETH", "--addr", solanaAccount, "--amount", "1"},
		{"--rail", "solana", "--op", "transferXLM", "--addr", solanaAccount, "--amount", "1"},
		{"--rail", "solana", "--op", "transferSOL", "--addr", stellarAccount, "--amount", "1"},
		{"--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "1e-3"},
		{"--rail", "stellar", "--op", "transferXLM", "--addr", stellarAccount, "--amount", "0.00000001"},
		{"--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "1", "--context", "[1]"},
		{"--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "1", "--before", `[{"type":"http","contract":"x","method":"m","args":{},"maxCostUSDC":"0"}]`},
		{"--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "1", "--after", `[{"type":"contract_call","contract":"` + solanaAccount + `","method":"m","args":{},"maxCostUSDC":"0","rpc":"http://x"}]`},
		{"--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "1", "--data", strings.Repeat("x", 1025)},
		{"--rail", "solana", "--amount", "1"},
		{"--amount", "1"},
	} {
		before := len(f.sent())
		if r := runCLI(t, env(srv), append([]string{"exec", policyID}, args...)...); r.code != exitUsage || len(f.sent()) != before {
			t.Fatalf("%v: %d %s", args, r.code, r.stderr)
		}
	}
}

func TestConfigAndPolicyBinding(t *testing.T) {
	f, srv := newFake(t, localDev)
	var hits int
	r := runCLI(t, env(srv), "show", "otherPolicy")
	f.locked(func() { hits = f.hits })
	if r.code != exitConfig || hits != 0 {
		t.Fatal("policy mismatch reached the network", r)
	}
	bad := env(srv)
	bad["ALLOWIT_URL"] = "http://allowit.example"
	if r := runCLI(t, bad, "show", policyID); r.code != exitConfig {
		t.Fatal("plain http accepted", r)
	}
	bad = env(srv)
	bad["ALLOWIT_URL"] = srv.URL + "/api"
	if r := runCLI(t, bad, "show", policyID); r.code != exitConfig {
		t.Fatal("path accepted", r)
	}
	bad = env(srv)
	bad["ALLOWIT_TOKEN"] = owner + "." + policyID + ".wrongsecretvalue"
	if r := runCLI(t, bad, "show", policyID); r.code != exitConfig || strings.Contains(r.stderr, "wrongsecretvalue") {
		t.Fatal("401 not reported as auth failure", r)
	}
}

func TestRedirectIsNeverFollowed(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = leaked || r.Header.Get("Authorization") != ""
		w.Write([]byte(`{}`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if r := runCLI(t, env(srv), "show", policyID); r.code != exitConfig || leaked {
		t.Fatal("redirect followed", r, leaked)
	}
}

func TestServerTextIsScrubbed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":"bad token %s \u001b[2J %s"}`, token, secret)
	}))
	defer srv.Close()
	r := runCLI(t, env(srv), "show", policyID)
	if r.code != exitRejected || strings.Contains(r.stderr, "\x1b") || !strings.Contains(r.stderr, "[redacted]") {
		t.Fatal(r)
	}
}

func TestShortTokenIsNeverPrinted(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, args := range [][]string{{"a.b.c"}, {"show", "a.b.c"}, {"status", "a.b.c", "a.b.c.request"}, {"exec", "a.b.c", "--context", "a.b.c"}} {
		code := App{Getenv: func(k string) string { return map[string]string{"ALLOWIT_TOKEN": "a.b.c", "ALLOWIT_URL": "https://allowit.example"}[k] }, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut}.Run(args)
		if code == 0 || strings.Contains(out.String()+errOut.String(), "a.b.c") {
			t.Fatalf("%v: %d %q %q", args, code, out.String(), errOut.String())
		}
	}
}

// A server that echoes the credential back must never get it printed, in
// errors or in --json output, for any command.
func TestEchoedCredentialIsRedactedEverywhere(t *testing.T) {
	f, srv := newFake(t, localDev)
	f.respond = func(string, map[string]any) map[string]any {
		return map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment", "requestId": "srv-echo-1", "reason": "echo " + token + " " + secret, "nested": map[string]any{"x": []any{secret}}}
	}
	for _, args := range [][]string{
		{"eval", policyID, "--amount", "1", "--action", "research", "--json"},
		{"eval", policyID, "--amount", "1", "--action", "research"},
		{"status", policyID, "srv-echo-1", "--json"},
		{"show", policyID, "--json"},
		{"show", policyID, "--json", "--source"},
	} {
		if r := runCLI(t, env(srv), args...); r.code != 0 {
			t.Fatal(args, r)
		}
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		fmt.Fprintf(w, `{"error":"conflict for %s (%s)"}`, token, secret)
	}))
	defer bad.Close()
	for _, args := range [][]string{
		{"show", policyID}, {"status", policyID, "srv-echo-1"}, {"status", policyID, "srv-echo-1", "--json"},
	} {
		if r := runCLI(t, env(bad), args...); r.code != exitRejected || !strings.Contains(r.stderr, "[redacted]") {
			t.Fatal(args, r)
		}
	}
}

func TestStatusUsesKind(t *testing.T) {
	f, srv := newFake(t, "solana:devnet")
	f.locked(func() {
		f.byServer["srv-judge-1"] = map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment", "requestId": "srv-judge-1", "decisionCode": "OK", "workflowNodeId": "n2", "revision": 3, "sourceHash": "abc"}
		f.byServer["srv-trans-1"] = map[string]any{"outcome": "pass", "status": "ready", "kind": "transaction", "requestId": "srv-trans-1"}
		f.byServer["srv-old-1"] = map[string]any{"outcome": "pass", "status": "ready", "requestId": "srv-old-1"}
	})
	if r := runCLI(t, env(srv), "status", policyID, "srv-judge-1"); r.code != 0 || !strings.Contains(r.stdout, "state: passed") || !strings.Contains(r.stdout, "decisionCode: OK") || !strings.Contains(r.stdout, "workflowNodeId: n2") || !strings.Contains(r.stdout, "revision: 3") {
		t.Fatal(r)
	}
	if r := runCLI(t, env(srv), "status", policyID, "srv-trans-1"); r.code != exitOwnerSignature || !strings.Contains(r.stdout, "state: owner_signature") {
		t.Fatal(r)
	}
	if r := runCLI(t, env(srv), "status", policyID, "srv-old-1"); r.code != exitOwnerSignature || !strings.Contains(r.stdout, "state: ready") || !strings.Contains(r.stdout, "not complete") {
		t.Fatal(r)
	}
}

func TestMalformedJSONInputsAndResponses(t *testing.T) {
	_, srv := newFake(t, localDev)
	call := `{"type":"contract_call","contract":"` + solanaAccount + `","method":"m","args":{},"maxCostUSDC":"0"}`
	for _, after := range []string{"[" + call + "] ]", "[" + call + "] x", "[" + call + "][]", call} {
		if r := runCLI(t, env(srv), "eval", policyID, "--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "1", "--after", after); r.code != exitUsage {
			t.Fatal(after, r)
		}
	}
	for _, wait := range []string{"-1s", "11m"} {
		if r := runCLI(t, env(srv), "status", policyID, "srv-anything", "--wait", wait); r.code != exitUsage {
			t.Fatal(wait, r)
		}
	}
	trailing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"network":"local:dev"} {"network":"solana:mainnet"}`))
	}))
	defer trailing.Close()
	if r := runCLI(t, env(trailing), "show", policyID); r.code != exitUncertain {
		t.Fatal("trailing response JSON accepted", r)
	}
}

func TestResponseSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"x":"`))
		w.Write(bytes.Repeat([]byte("a"), maxResponse+10))
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()
	if r := runCLI(t, env(srv), "show", policyID); r.code != exitUncertain || !strings.Contains(r.stderr, "2 MB") {
		t.Fatal(r)
	}
}

func TestShow(t *testing.T) {
	_, srv := newFake(t, localDev)
	r := runCLI(t, env(srv), "show", policyID)
	for _, want := range []string{"Research budget", "revision 3", "local:dev", "stellar (XLM, USDC)", "XLM=0.1", "Cap spending at 10 USDC", "Never above 5 USDC.", "10 USDC allocated, 0.5 USDC spent"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("missing %q in\n%s", want, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "pub async fn") {
		t.Fatal("source printed without --source")
	}
	j := runCLI(t, env(srv), "show", policyID, "--json")
	var m map[string]any
	if json.Unmarshal([]byte(j.stdout), &m) != nil || m["authorization"] != nil || m["accessUrl"] != nil || m["network"] != localDev {
		t.Fatal(j.stdout)
	}
	if s := runCLI(t, env(srv), "show", policyID, "--source"); !strings.Contains(s.stdout, "pub async fn") {
		t.Fatal("source missing")
	}
}

func TestTLSWithCAFile(t *testing.T) {
	f := &fakeHarness{t: t, network: localDev, byClient: map[string]stored{}, byServer: map[string]map[string]any{}}
	srv := httptest.NewUnstartedServer(f)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failure
	srv.StartTLS()
	defer srv.Close()
	e := env(srv)
	if r := runCLI(t, e, "show", policyID); r.code != exitConfig || !strings.Contains(r.stderr, "not trusted") {
		t.Fatal("untrusted TLS accepted", r)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	e["ALLOWIT_CA_FILE"] = ca
	if r := runCLI(t, e, "show", policyID); r.code != 0 {
		t.Fatal(r)
	}
}
