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
	revision  int            // policy revision published by /skill (default 3)
	rails     map[string]any // wallet rails published by /skill
	editSkill func(map[string]any)
	skillFail int    // answer GET /skill with this HTTP status
	skillBody string // ... and this body
	skillGets int
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
		f.skillGets++
		if f.skillFail != 0 {
			w.WriteHeader(f.skillFail)
			io.WriteString(w, f.skillBody)
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		json.NewEncoder(w).Encode(f.skill(scheme + "://" + r.Host))
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

// skill is the current backend's /skill shape (owner, policyId, absolute
// endpoints, typed contract) unless editSkill changes it.
func (f *fakeHarness) skill(base string) map[string]any {
	endpoints := map[string]any{}
	for _, a := range []string{"judge", "transactions", "status"} {
		endpoints[a] = base + "/api/harness/" + owner + "/" + policyID + "/" + a
	}
	s := map[string]any{
		"name":"AllowIt policy Research budget", "title": "Research budget", "policyId": policyID, "owner": owner, "status": "active",
		"network": f.network, "revision": 3 + f.revision, "sourceHash": fmt.Sprintf("abcdef0123456789abcdef%d", f.revision), "language": "allowit-rust-v1",
		"originalIntent": "Buy original research datasets.\n\nRevision request:\nNever above 5 USDC.",
		"policy":         "pub async fn evaluate(ctx:&Context)->PolicyResult{Ok(())}",
		"authorization":  "Bearer " + token, "accessUrl": "https://allowit.example/api/harness/x/y/skill.md?access_token=" + token,
		"budget":   map[string]any{"allocation": "10", "spent": "0.5"},
		"workflow": []any{map[string]any{"kind": "cap", "label": "Cap spending at 10 USDC", "description": "Hard limit"}},
	}
	s["endpoints"] = endpoints
	binding := map[string]any{"sourceHash": s["sourceHash"], "irHash": "fedcba9876543210fedcba", "registryVersion": "1", "requirements": map[string]any{"version": 1, "features": []any{}, "context_u64_keys": []any{}}}
	if f.network == localDev {
		rails := map[string]any{"solana": []any{"SOL", "USDC"}, "stellar": []any{"XLM", "USDC"}}
		rates, decimals := map[string]any{"SOL": "100", "XLM": "0.1", "USDC": "1"}, map[string]any{"SOL": 9, "XLM": 7, "USDC": 6}
		s["executionMode"] = "local"
		s["capabilities"] = map[string]any{"mode": "mock", "rails": rails, "fixedTestRatesUSDC": rates, "assetDecimals": decimals, "callsRequireOwnerApproval": true}
		s["contract"] = map[string]any{"version": 1, "profile": "local_dev", "interface": "http", "binding": binding, "contextU64Keys": []any{},
			"capabilities": map[string]any{"protocol": "http_json", "execution": "mock", "rails": rails, "executionPlans": true, "memoData": true, "contractCalls": true, "fixedTestRatesUSDC": rates, "assetDecimals": decimals, "ownerAnswerRequiredForCalls": true}}
	} else {
		rails := map[string]any{"solana": []any{"USDC"}}
		if f.rails != nil {
			rails = f.rails
		}
		s["executionMode"] = "owner_signed"
		s["capabilities"] = map[string]any{"rail": "solana", "assets": []any{"USDC"}, "rails": rails, "execution": "owner_signed"}
		s["contract"] = map[string]any{"version": 1, "profile": "solana_owner_signed", "interface": "http", "binding": binding, "contextU64Keys": []any{},
			"capabilities": map[string]any{"protocol": "http_json", "execution": "owner_signed", "rails": rails, "recipientRequired": true, "ownerSignatureRequired": true}}
	}
	if f.editSkill != nil {
		f.editSkill(s)
	}
	return s
}

// legacySkill is the pre-contract shape: no endpoints or contract.
func legacySkill(s map[string]any) {
	delete(s, "endpoints")
	delete(s, "contract")
	delete(s, "owner")
}

// customerSkill is the customer-workspace server's shape: name, network,
// executionMode and relative endpoints; no title, policyId, owner,
// capabilities or contract.
func customerSkill(s map[string]any) {
	keep := map[string]bool{"name": true, "network": true, "executionMode": true, "status": true, "budget": true}
	for k := range s {
		if !keep[k] {
			delete(s, k)
		}
	}
	s["name"] = "Customer research"
	s["endpoints"] = map[string]any{"judge": "/api/harness/" + owner + "/" + policyID + "/judge", "transactions": "transactions", "status": "./status"}
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
	r := runCLI(t, env(srv), "exec", policyID, "--rail", "stellar", "--op", "transferXLM", "--addr", stellarAccount, "--amount", "5", "--action", "research", "--data", `{"license":"ds-1"}`, "--memo", "Dataset license", "--context", ctx)
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
	if string(body["amount"]) != `"0.5"` || string(body["action"]) != `"research"` || string(body["recipient"]) != `"`+stellarAccount+`"` {
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
	if r := runCLI(t, env(srv), "eval", policyID, "--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "0.005", "--after", after, "--action", "research", "--budget", "0.5"); r.code != exitUsage || !strings.Contains(r.stderr, "--budget 0.5 does not match") {
		t.Fatal("budget mismatch accepted", r)
	}
}

func TestIdempotentRequestIDs(t *testing.T) {
	f, srv := newFake(t, localDev)
	args := []string{policyID, "--rail", "stellar", "--op", "transferUSDC", "--addr", stellarAccount, "--amount", "1", "--action", "research", "--context", `{"a":1}`}
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
	conflict := runCLI(t, env(srv), "exec", policyID, "--request-id", "order-0001", "--rail", "stellar", "--op", "transferUSDC", "--addr", stellarAccount, "--amount", "2", "--action", "research")
	if conflict.code != exitRejected || !strings.Contains(conflict.stderr, "already used") {
		t.Fatal(conflict)
	}
}

func TestUncertainFailureRetriesSameRequest(t *testing.T) {
	f, srv := newFake(t, localDev)
	f.locked(func() { f.dropFirst = 1 })
	r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--action", "transfer")
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
	r = runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "2", "--action", "transfer")
	_, last := f.last(t)
	id := strings.Trim(string(last["requestId"]), `"`)
	if r.code != exitUncertain || !strings.Contains(r.stderr, "Retry only by rerunning the same command with --request-id "+id) || !strings.Contains(r.stderr, "Do not retry with a new request ID") {
		t.Fatal(r)
	}
	// The ID is printed before the request is sent.
	if !strings.HasPrefix(r.stderr, "allowit: exec request "+id) || !strings.Contains(r.stderr, "retry only with --request-id "+id) {
		t.Fatal(r.stderr)
	}
	// The owner edits the policy before the retry: the derived ID must not change.
	f.locked(func() { f.dropFirst, f.revision = 0, 1 })
	if again := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "2", "--action", "transfer"); again.code != 0 || f.clients() != 2 {
		t.Fatal("rerun after a policy revision created another spend", again, f.clients())
	}
	// So does the printed explicit retry.
	if again := runCLI(t, env(srv), "exec", policyID, "--request-id", id, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "2", "--action", "transfer"); again.code != 0 || f.clients() != 2 {
		t.Fatal("explicit retry created another spend", again, f.clients())
	}
}

// harnessWith serves f, except for the actions override answers.
func harnessWith(t *testing.T, f *fakeHarness, override func(action string) (int, string, bool)) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if code, body, ok := override(action); ok {
			f.locked(func() { f.requests = append(f.requests, recorded{Action: action}) })
			w.WriteHeader(code)
			io.WriteString(w, body)
			return
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAcceptedExecWithUnreadableStatusIsUncertain(t *testing.T) {
	for _, status := range []struct {
		code int
		body string
	}{{400, `{"error":"Check the request fields and try again."}`}, {404, `{"error":"Request not found."}`}, {429, `{"error":"Slow down."}`}, {403, `{"error":"Forbidden."}`}, {200, `null`}, {200, `{}`}, {200, `{"outcome":"pass","status":"ready","requestId":"srv-other-99"}`}} {
		f, _ := newFake(t, localDev)
		f.respond = func(string, map[string]any) map[string]any {
			return map[string]any{"outcome": "pending", "status": "evaluating", "requestId": "srv-pending-7"}
		}
		srv := harnessWith(t, f, func(action string) (int, string, bool) { return status.code, status.body, action == "status" })
		for _, extra := range [][]string{nil, {"--json"}} {
			r := runCLI(t, env(srv), append([]string{"exec", policyID, "--amount", "1", "--action", "research", "--request-id", "order-0007"}, extra...)...)
			if r.code != exitUncertain || strings.Contains(r.stdout, "state:") || !strings.Contains(r.stderr, "AllowIt accepted exec request order-0007 (server requestId srv-pending-7)") ||
				!strings.Contains(r.stderr, "allowit status --wait 60s -- "+policyID+" srv-pending-7") || !strings.Contains(r.stderr, "--request-id order-0007") || !strings.Contains(r.stderr, "Do not retry with a new request ID") {
				t.Fatalf("%d %s: %+v", status.code, status.body, r)
			}
		}
		if f.clients() != 1 {
			t.Fatal("retry created a second request")
		}
	}
	// Without a server requestId the pending result cannot be polled; the client ID remains.
	f, srv := newFake(t, localDev)
	f.respond = func(string, map[string]any) map[string]any {
		return map[string]any{"outcome": "pending", "status": "evaluating"}
	}
	r := runCLI(t, env(srv), "exec", policyID, "--amount", "1", "--action", "research", "--request-id", "order-0008")
	if r.code != exitUncertain || !strings.Contains(r.stderr, "without a valid requestId") || !strings.Contains(r.stderr, "--request-id order-0008") || strings.Contains(r.stderr, "allowit status") {
		t.Fatal(r)
	}
}

func TestInvalidResultsAreUncertain(t *testing.T) {
	for _, c := range []struct {
		network, cmd, body string
	}{
		{localDev, "exec", `null`},
		{localDev, "exec", `{}`},
		{localDev, "eval", `{}`},
		{localDev, "exec", `{"outcome":"weird","requestId":"srv-x-12345678"}`},
		{localDev, "exec", `{"outcome":1}`},
		{localDev, "exec", `{"outcome":"pass","executed":"true"}`},
		{localDev, "exec", `{"outcome":"fail","status":"recorded","localRecorded":true}`},
		{localDev, "exec", `{"outcome":"fail","status":"ready"}`},
		{localDev, "exec", `{"outcome":"pass","status":"denied"}`},
		{localDev, "exec", `{"outcome":"pass","status":"settled","executed":true}`},
		{localDev, "exec", `{"outcome":"pass","status":"recorded","localRecorded":true,"executed":true}`},
		{"solana:devnet", "exec", `{"outcome":"pass","status":"recorded","localRecorded":true}`},
		{"solana:devnet", "exec", `{"outcome":"pass","status":"ready","kind":"judgment"}`},
		{"solana:devnet", "eval", `{"outcome":"pass","status":"ready","kind":"transaction"}`},
		{"solana:devnet", "eval", `{"outcome":"pass","status":"settled","executed":true}`},
		{"solana:devnet", "exec", `{"outcome":"pending","status":"settled","executed":true,"requestId":"srv-x-12345678"}`},
		// Known outcomes with missing or contradicting state evidence.
		{"solana:devnet", "exec", `{"outcome":"pass","status":"ready","executed":true}`},
		{"solana:devnet", "eval", `{"outcome":"pass"}`},
		{"solana:devnet", "exec", `{"outcome":"pass","status":"evaluating"}`},
		{"solana:devnet", "exec", `{"outcome":"pending","status":"denied","requestId":"srv-x-12345678"}`},
		{"solana:devnet", "exec", `{"outcome":"pass","status":"settled","executed":false}`},
		{localDev, "exec", `{"outcome":"pass","status":"recorded","localRecorded":false}`},
		{"solana:devnet", "exec", `{"outcome":"fail"}`},
		{"solana:devnet", "exec", `{"outcome":"fail","status":"denied","kind":"payout"}`},
	} {
		f, _ := newFake(t, c.network)
		srv := harnessWith(t, f, func(action string) (int, string, bool) {
			return 200, c.body, action == "judge" || action == "transactions"
		})
		for _, extra := range [][]string{nil, {"--json"}} {
			args := append([]string{c.cmd, policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--action", "transfer"}, extra...)
			r := runCLI(t, env(srv), args...)
			if r.code != exitUncertain || r.stdout != "" || !strings.Contains(r.stderr, "but its result is unknown") {
				t.Fatalf("%s %s %v: %+v", c.network, c.body, extra, r)
			}
		}
	}
	// The same checks apply to status results.
	for _, body := range []string{`null`, `{}`, `{"outcome":"pass","status":"settled","executed":true}`, `{"outcome":"pass","status":"ready","requestId":"srv-other-99"}`} {
		f, _ := newFake(t, localDev)
		srv := harnessWith(t, f, func(action string) (int, string, bool) { return 200, body, action == "status" })
		for _, extra := range [][]string{nil, {"--json"}} {
			if r := runCLI(t, env(srv), append([]string{"status", policyID, "srv-status-1"}, extra...)...); r.code != exitUncertain || r.stdout != "" {
				t.Fatal(body, r)
			}
		}
	}
}

// A retry that gets a definite refusal cannot undo the uncertainty of an
// earlier attempt that the server processed.
func TestDefiniteRetryAnswerAfterProcessedAttemptIsUncertain(t *testing.T) {
	for _, gateway := range []bool{false, true} {
		for _, code := range []int{400, 401, 409, 429} {
			f, _ := newFake(t, localDev)
			if !gateway {
				f.locked(func() { f.dropFirst = 1 })
			}
			var hits int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/transactions") {
					f.ServeHTTP(w, r)
					return
				}
				f.locked(func() { hits++ })
				switch {
				case hits > 1:
					w.WriteHeader(code)
					io.WriteString(w, `{"error":"refused"}`)
				case gateway: // processed, then the gateway fails
					f.ServeHTTP(httptest.NewRecorder(), r)
					w.WriteHeader(502)
				default: // processed, then the connection drops
					f.ServeHTTP(w, r)
				}
			}))
			r := runCLI(t, env(srv), "exec", policyID, "--amount", "1", "--action", "research", "--request-id", "order-0010")
			srv.Close()
			var n int
			f.locked(func() { n = hits })
			if r.code != exitUncertain || !strings.Contains(r.stderr, "HTTP "+fmt.Sprint(code)) || !strings.Contains(r.stderr, "earlier attempt that may have been processed") ||
				!strings.Contains(r.stderr, "Retry only by rerunning the same command with --request-id order-0010") || f.clients() != 1 || n != 2 {
				t.Fatalf("gateway=%v %d: clients=%d hits=%d %+v", gateway, code, f.clients(), n, r)
			}
		}
	}
}

func TestUnexpectedHTTPAnswersToPostAreUncertain(t *testing.T) {
	for _, code := range []int{201, 202, 204, 303, 307} {
		f, _ := newFake(t, localDev)
		srv := harnessWith(t, f, func(action string) (int, string, bool) {
			return code, `{"outcome":"fail"}`, action == "transactions"
		})
		if r := runCLI(t, env(srv), "exec", policyID, "--amount", "1", "--action", "research", "--request-id", "order-0009"); r.code != exitUncertain || !strings.Contains(r.stderr, "--request-id order-0009") {
			t.Fatal(code, r)
		}
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
	if r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--action", "transfer", "--data", "x"); r.code != exitUsage || !strings.Contains(r.stderr, "only for Local dev") {
		t.Fatal("mock data accepted on wallet network", r)
	}
	if r := runCLI(t, env(srv), "exec", policyID, "--rail", "stellar", "--op", "transferXLM", "--addr", stellarAccount, "--amount", "1", "--action", "transfer"); r.code != exitUsage || !strings.Contains(r.stderr, "not available") {
		t.Fatal("stellar accepted on wallet network", r)
	}
	if r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--amount", "1", "--action", "transfer"); r.code != exitUsage || !strings.Contains(r.stderr, "Solana address") {
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
	// Even if the service advertises other assets, wallet requests carry no
	// asset and are always USDC; anything else must not be sent as USDC.
	f.locked(func() { f.rails = map[string]any{"solana": []any{"SOL", "USDC"}, "stellar": []any{"XLM", "USDC"}} })
	before := len(f.sent())
	for _, args := range [][]string{{"--rail", "solana", "--op", "transferSOL"}, {"--rail", "stellar", "--op", "transferUSDC"}} {
		if r := runCLI(t, env(srv), append(append([]string{"exec", policyID}, args...), "--addr", solanaAccount, "--amount", "5", "--action", "transfer")...); r.code != exitUsage || len(f.sent()) != before || strings.Contains(r.stderr, "--action is required") {
			t.Fatal(args, r)
		}
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
		{"--amount", "1.0000001"},
	} {
		before := len(f.sent())
		if r := runCLI(t, env(srv), append([]string{"exec", policyID, "--action", "research"}, args...)...); r.code != exitUsage || len(f.sent()) != before {
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
		if r := runCLI(t, env(srv), "eval", policyID, "--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "1", "--action", "research", "--after", after); r.code != exitUsage || !strings.Contains(r.stderr, "--after must be") {
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

// --op is the transfer, never the policy action. A missing --action is refused
// before anything is sent; explicit actions keep their exact request IDs, and
// --action set to the op reproduces a 0.1.1 request (which defaulted to it).
func TestActionIsRequired(t *testing.T) {
	f, srv := newFake(t, "solana:devnet")
	transfer := []string{"exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1"}
	r := runCLI(t, env(srv), transfer...)
	if r.code != exitUsage || len(f.sent()) != 0 || !strings.Contains(r.stderr, "--action is required") || !strings.Contains(r.stderr, "--action transferUSDC") {
		t.Fatal(r)
	}
	// Request IDs derived by allowit 0.1.1 for the same requests.
	for _, c := range []struct {
		network string
		args    []string
		action  string
		id      string
	}{
		{"solana:devnet", append(transfer, "--action", "transferUSDC"), "transferUSDC", "cli-exec-5723433f047e41429165aa32f3767cef452bd40a"},
		{"solana:devnet", append(transfer, "--action", "transfer"), "transfer", "cli-exec-6f6f72f46421e896d6c2ed5ce68d3e7195a4187c"},
		{"solana:devnet", []string{"eval", policyID, "--amount", "2.5", "--action", "research"}, "research", "cli-eval-5e694a94a381d458d88f6afe39a602eff1cc76c7"},
		{localDev, []string{"exec", policyID, "--rail", "stellar", "--op", "transferXLM", "--addr", stellarAccount, "--amount", "5", "--action", "transferXLM"}, "transferXLM", "cli-exec-7c6195d63526749fef258655da56bb1b1df1deaf"},
	} {
		f, srv := newFake(t, c.network)
		r := runCLI(t, env(srv), c.args...)
		_, body := f.last(t)
		if r.code == exitUsage || string(body["requestId"]) != `"`+c.id+`"` || string(body["action"]) != `"`+c.action+`"` {
			t.Fatalf("%v: %+v %s", c.args, r, body["requestId"])
		}
	}
}

// The customer-workspace server publishes name, network, executionMode and
// relative endpoints only. The CLI works with it and shows what is missing.
func TestCustomerSkillShape(t *testing.T) {
	f, srv := newFake(t, "solana:devnet")
	f.editSkill = customerSkill
	s := runCLI(t, env(srv), "show", policyID)
	for _, want := range []string{"AllowIt policy: Customer research\n", "Policy:     " + policyID + " (from ALLOWIT_TOKEN; AllowIt did not report the policy ID)", "solana:devnet (every transfer needs the owner's wallet signature)", "Rails:      solana (USDC)"} {
		if s.code != 0 || !strings.Contains(s.stdout, want) {
			t.Fatalf("missing %q in %+v", want, s)
		}
	}
	if strings.Contains(s.stdout, "revision 0") || strings.Contains(s.stdout, "Original request") {
		t.Fatal(s.stdout)
	}
	r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--action", "transfer", "--request-id", "customer-0001")
	if r.code != exitOwnerSignature || !strings.Contains(r.stdout, "state: owner_signature") {
		t.Fatal(r)
	}
	action, body := f.last(t)
	if action != "transactions" || string(body["action"]) != `"transfer"` || string(body["amount"]) != `"1"` || string(body["recipient"]) != `"`+solanaAccount+`"` || body["execution"] != nil {
		t.Fatal(action, body)
	}
	if r := runCLI(t, env(srv), "eval", policyID, "--amount", "1", "--action", "research", "--request-id", "customer-0002"); r.code != 0 || !strings.Contains(r.stdout, "state: passed") {
		t.Fatal(r)
	}
	if st := runCLI(t, env(srv), "status", policyID, "srv-0-abcdefgh"); st.code != exitOwnerSignature || strings.Contains(st.stderr, "unavailable") {
		t.Fatal(st)
	}

	// Local dev without published rails or rates: plain requests only.
	f, srv = newFake(t, localDev)
	f.editSkill = customerSkill
	if s := runCLI(t, env(srv), "show", policyID); s.code != 0 || !strings.Contains(s.stdout, "mock execution") || !strings.Contains(s.stdout, "Rails:      none published") {
		t.Fatal(s)
	}
	if r := runCLI(t, env(srv), "exec", policyID, "--rail", "stellar", "--op", "transferXLM", "--addr", stellarAccount, "--amount", "5", "--action", "research"); r.code != exitUsage || len(f.sent()) != 0 || !strings.Contains(r.stderr, "published no rails") {
		t.Fatal(r)
	}
	if r := runCLI(t, env(srv), "exec", policyID, "--amount", "1", "--action", "research"); r.code != 0 || !strings.Contains(r.stdout, "state: recorded") {
		t.Fatal(r)
	}
}

// Services from before the typed contract omit endpoints, owner and contract.
func TestLegacySkillShape(t *testing.T) {
	for _, network := range []string{localDev, "solana:devnet"} {
		f, srv := newFake(t, network)
		f.editSkill = legacySkill
		if s := runCLI(t, env(srv), "show", policyID); s.code != 0 || !strings.Contains(s.stdout, "Research budget") || !strings.Contains(s.stdout, "revision 3") {
			t.Fatal(s)
		}
		r := runCLI(t, env(srv), "exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--action", "transfer")
		if network == localDev && r.code != 0 || network != localDev && r.code != exitOwnerSignature {
			t.Fatal(network, r)
		}
	}
}

// A description naming another owner, policy or route, or an unknown network
// or profile, stops every command before judge or transactions; the bearer
// token never goes anywhere but the configured canonical route.
func TestSkillMetadataRefusedBeforeSending(t *testing.T) {
	var leaked int
	var mu sync.Mutex
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked++
		mu.Unlock()
		w.Write([]byte(`{"outcome":"pass","status":"settled","executed":true}`))
	}))
	defer other.Close()
	set := func(k string, v any) func(map[string]any) { return func(s map[string]any) { s[k] = v } }
	contract := func(k string, v any) func(map[string]any) {
		return func(s map[string]any) { s["contract"].(map[string]any)[k] = v }
	}
	route := "/api/harness/" + owner + "/" + policyID + "/"
	for _, c := range []struct {
		name  string
		edit  func(map[string]any)
		bound bool // identity or route: status stops too
	}{
		{"owner", set("owner", "someone_else"), true},
		{"policy", set("policyId", "otherPolicy"), true},
		{"origin", set("endpoints", map[string]any{"transactions": other.URL + route + "transactions"}), true},
		{"path", set("endpoints", map[string]any{"judge": "../otherPolicy/judge"}), true},
		{"query", set("endpoints", map[string]any{"status": route + "status?debug=1"}), true},
		{"network", set("network", "stellar:testnet"), false},
		{"no network", func(s map[string]any) { delete(s, "network") }, false},
		{"mode", set("executionMode", "custodial"), false},
		{"mode for network", set("executionMode", "local"), false},
		{"profile", contract("profile", "solana_custodial"), false},
		{"version", contract("version", 2), false},
		{"binding", contract("binding", map[string]any{"sourceHash": "0000000000000000"}), false},
		{"unreadable", set("endpoints", map[string]any{"judge": map[string]any{"url": "judge"}}), false},
	} {
		f, srv := newFake(t, "solana:devnet")
		f.editSkill = c.edit
		f.locked(func() { f.byServer["srv-deny-0001"] = map[string]any{"outcome": "fail", "status": "denied", "requestId": "srv-deny-0001"} })
		for _, args := range [][]string{
			{"show", policyID},
			{"eval", policyID, "--amount", "1", "--action", "research"},
			{"exec", policyID, "--rail", "solana", "--op", "transferUSDC", "--addr", solanaAccount, "--amount", "1", "--action", "transfer"},
		} {
			if r := runCLI(t, env(srv), args...); r.code != exitConfig || r.stdout != "" || len(f.sent()) != 0 {
				t.Fatalf("%s %v: %+v", c.name, args, r)
			}
		}
		st := runCLI(t, env(srv), "status", policyID, "srv-deny-0001")
		if c.bound && (st.code != exitConfig || len(f.sent()) != 0) || !c.bound && (st.code != exitDenied || !strings.Contains(st.stderr, "policy description is unavailable")) {
			t.Fatalf("%s status: %+v", c.name, st)
		}
	}
	if leaked != 0 {
		t.Fatal("a request reached a published endpoint on another origin")
	}
}

// When the policy description is refused (e.g. HTTP 409 from typed skill
// assembly) status still reads the request through the canonical route.
// Results whose meaning depends on the network are uncertain, never complete.
func TestStatusRecoversWithoutPolicyDescription(t *testing.T) {
	results := map[string]struct {
		res   map[string]any
		state string
		code  int
	}{
		"srv-pend-0001": {map[string]any{"outcome": "pending", "status": "evaluating"}, "pending", exitPending},
		"srv-input-001": {map[string]any{"outcome": "awaiting_input", "status": "awaiting_input", "prompt": "Approve the dataset?"}, "awaiting_input", exitAwaitingInput},
		"srv-deny-0001": {map[string]any{"outcome": "fail", "status": "denied", "reason": "Over the cap."}, "denied", exitDenied},
		"srv-judge-001": {map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment"}, "passed", exitOK},
		"srv-ready-001": {map[string]any{"outcome": "pass", "status": "ready", "kind": "transaction"}, "", exitUncertain},
		"srv-old-00001": {map[string]any{"outcome": "pass", "status": "ready"}, "", exitUncertain},
		"srv-subm-0001": {map[string]any{"outcome": "pass", "status": "submitted", "kind": "transaction"}, "", exitUncertain},
		"srv-sett-0001": {map[string]any{"outcome": "pass", "status": "settled", "executed": true, "kind": "transaction"}, "", exitUncertain},
		"srv-rec-00001": {map[string]any{"outcome": "pass", "status": "recorded", "localRecorded": true, "kind": "transaction"}, "", exitUncertain},
	}
	for _, fail := range []struct {
		code int
		body string
	}{
		{409, `{"error":"An agent skill cannot be issued for this policy (UNRESOLVED_CONTEXT_KEYS): the policy reads request values whose names are computed during evaluation."}`},
		{400, `{"error":"Create a new agent skill from the app to refresh its endpoints."}`},
		{500, `{"error":"boom"}`},
		{200, ""}, // a description with an unsupported network
	} {
		f, srv := newFake(t, "solana:devnet")
		if fail.code == 200 {
			f.editSkill = func(s map[string]any) { s["network"] = "solana:localnet" }
		} else {
			f.skillFail, f.skillBody = fail.code, fail.body
		}
		f.locked(func() {
			for id, c := range results {
				res := map[string]any{"requestId": id}
				for k, v := range c.res {
					res[k] = v
				}
				f.byServer[id] = res
			}
		})
		for id, c := range results {
			for _, extra := range [][]string{nil, {"--json"}} {
				r := runCLI(t, env(srv), append([]string{"status", policyID, id}, extra...)...)
				ok := r.code == c.code && strings.Contains(r.stderr, "policy description is unavailable")
				if c.code == exitUncertain {
					ok = ok && r.stdout == "" && strings.Contains(r.stderr, "network could not be established") && strings.Contains(r.stderr, "Nothing is confirmed")
				} else if extra == nil {
					ok = ok && strings.Contains(r.stdout, "state: "+c.state)
				} else {
					var out map[string]any
					ok = ok && json.Unmarshal([]byte(r.stdout), &out) == nil && out["state"] == c.state
				}
				if !ok {
					t.Fatalf("skill %d, %s %v: %+v", fail.code, id, extra, r)
				}
			}
		}
		for _, q := range f.sent() {
			if q.Action != "status" {
				t.Fatal("status sent", q.Action)
			}
		}
	}
	// Authentication failures are never downgraded into a status read.
	for _, code := range []int{401, 403} {
		f, srv := newFake(t, "solana:devnet")
		f.skillFail, f.skillBody = code, `{"error":"Harness access expired or was revoked."}`
		if r := runCLI(t, env(srv), "status", policyID, "srv-deny-0001"); r.code != exitConfig || len(f.sent()) != 0 {
			t.Fatal(code, r)
		}
	}
}

// Waiting without the network: a request that completes while polled is
// still uncertain, and status never resends the request.
func TestStatusWaitWithoutNetworkStaysUncertain(t *testing.T) {
	f, srv := newFake(t, "solana:devnet")
	f.skillFail, f.skillBody = 409, `{"error":"An agent skill cannot be issued for this policy (UNKNOWN_PROFILE): no profile."}`
	f.locked(func() {
		f.byServer["srv-pending-2"] = map[string]any{"outcome": "pending", "status": "evaluating", "kind": "transaction", "requestId": "srv-pending-2"}
	})
	go func() {
		for {
			f.mu.Lock()
			if len(f.requests) > 0 {
				res := f.byServer["srv-pending-2"]
				res["outcome"], res["status"], res["executed"] = "pass", "settled", true
				f.mu.Unlock()
				return
			}
			f.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
	}()
	r := runCLI(t, env(srv), "status", policyID, "srv-pending-2", "--wait", "5s")
	if r.code != exitUncertain || r.stdout != "" || !strings.Contains(r.stderr, `status "settled"`) {
		t.Fatal(r)
	}
	for _, q := range f.sent() {
		if q.Action != "status" {
			t.Fatal("status sent", q.Action)
		}
	}
}

// A typed contract's capability flags gate plan features; the published
// context keys and binding are shown.
func TestTypedContractCapabilities(t *testing.T) {
	f, srv := newFake(t, localDev)
	after := `[{"type":"contract_call","contract":"` + solanaAccount + `","method":"m","args":{},"maxCostUSDC":"0"}]`
	plan := []string{"exec", policyID, "--rail", "solana", "--op", "transferSOL", "--addr", solanaAccount, "--amount", "0.01", "--action", "research"}
	f.editSkill = func(s map[string]any) {
		c := s["contract"].(map[string]any)
		c["capabilities"].(map[string]any)["contractCalls"] = false
		c["contextU64Keys"] = []any{"dataset_units", "price_cents"}
	}
	if r := runCLI(t, env(srv), append(plan, "--after", after)...); r.code != exitUsage || len(f.sent()) != 0 || !strings.Contains(r.stderr, "--before or --after") {
		t.Fatal(r)
	}
	if r := runCLI(t, env(srv), plan...); r.code != 0 {
		t.Fatal(r)
	}
	if s := runCLI(t, env(srv), "show", policyID); !strings.Contains(s.stdout, `Context:    the policy may read these --context fields as non-negative integers: "dataset_units", "price_cents"`) || !strings.Contains(s.stdout, "Binding:    IR fedcba987654") {
		t.Fatal(s.stdout)
	}
	f.locked(func() {
		f.editSkill = func(s map[string]any) { s["contract"].(map[string]any)["capabilities"].(map[string]any)["executionPlans"] = false }
	})
	before := len(f.sent())
	if r := runCLI(t, env(srv), plan...); r.code != exitUsage || len(f.sent()) != before || !strings.Contains(r.stderr, "does not accept execution plans") {
		t.Fatal(r)
	}
}
