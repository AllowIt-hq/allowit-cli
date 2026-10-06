package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestParseOrigin(t *testing.T) {
	good := map[string]string{
		"https://allowit.example":      "https://allowit.example",
		"https://AllowIt.Example/":     "https://allowit.example",
		"https://allowit.example:8443": "https://allowit.example:8443",
		"http://127.0.0.1:5173":        "http://127.0.0.1:5173",
		"http://localhost:3000":        "http://localhost:3000",
		"http://[::1]:8080":            "http://[::1]:8080",
	}
	for in, want := range good {
		if got, err := parseOrigin(in); err != nil || got != want {
			t.Errorf("%s: got %q %v", in, got, err)
		}
	}
	for _, in := range []string{
		"", "allowit.example", "http://allowit.example", "http://10.0.0.1", "ftp://allowit.example",
		"https://user:pw@allowit.example", "https://allowit.example/api", "https://allowit.example/?x=1",
		"https://allowit.example?", "https://allowit.example#f", "https:///path", "http://127.0.0.1.evil.example",
	} {
		if _, err := parseOrigin(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestParseToken(t *testing.T) {
	o, p, s, err := parseToken("local_abc.policy_1.secret-XYZ_123456")
	if err != nil || o != "local_abc" || p != "policy_1" || s != "secret-XYZ_123456" {
		t.Fatal(o, p, s, err)
	}
	for _, in := range []string{"", "a.b", "a.b.c", "a.b.short-secret", "a.b.c.d", "a..c", "a/b.c.d", "a.b.secret-XYZ_123456 ", "a.b.secret-XYZ_123456\n", "../x.y.z", "a.b.secret%2FXYZ_123456"} {
		if _, _, _, err := parseToken(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestBudgetChargeIsExact(t *testing.T) {
	cases := []struct {
		qty, rate string
		decimals  int
		calls     []Call
		want      string
	}{
		{"0.005", "100", 9, nil, "0.5"},
		{"0.000000001", "100", 9, nil, "0.000001"}, // rounds up to one micro-USDC
		{"0.0000001", "0.1", 7, nil, "0.000001"},
		{"0.1", "0.1", 7, nil, "0.01"},
		{"3", "0.1", 7, nil, "0.3"}, // float64 would give 0.30000000000000004
		{"0.5", "1", 6, []Call{{MaxCost: "0"}}, "0.5"},
		{"0.5", "1", 6, []Call{{MaxCost: "5.5"}}, "6"},
		{"1234567.123456789", "0.1", 9, nil, "123456.712346"},
	}
	for _, c := range cases {
		got, err := budgetCharge(c.qty, c.rate, c.decimals, c.calls)
		if err != nil || got != c.want {
			t.Errorf("%s×%s: got %q %v, want %s", c.qty, c.rate, got, err, c.want)
		}
	}
	for _, c := range []struct{ qty, rate string; decimals int }{
		{"0", "1", 6}, {"1e3", "1", 6}, {"-1", "1", 6}, {"0.0000001", "1", 6}, {"01", "1", 6},
		{"1.", "1", 6}, {" 1", "1", 6}, {"9999999.999999999", "100", 9}, {"1", "1e2", 6},
	} {
		if got, err := budgetCharge(c.qty, c.rate, c.decimals, nil); err == nil {
			t.Errorf("accepted %s×%s = %s", c.qty, c.rate, got)
		}
	}
	if _, err := budgetCharge("1", "1", 6, []Call{{MaxCost: "0.0000001"}}); err == nil {
		t.Error("accepted sub-micro call cost")
	}
}

func TestUSDCUnits(t *testing.T) {
	for in, want := range map[string]string{"1": "1", "0.5": "0.5", "1000000": "1000000", "0.000001": "0.000001", "2.500000": "2.5"} {
		n, err := usdcUnits(in)
		if err != nil || formatUnits(n) != want {
			t.Errorf("%s: %v %v", in, n, err)
		}
	}
	for _, in := range []string{"0", "0.0", "1000000.000001", "1.0000001", "1e2", "NaN", ".5"} {
		if _, err := usdcUnits(in); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
}

func TestAddresses(t *testing.T) {
	if !solanaAddress("11111111111111111111111111111111") || solanaAddress("0OIl1111111111111111111111111111") || solanaAddress("https://private.service") {
		t.Fatal("solana")
	}
	if !stellarAddress(stellarAccount, false) || stellarAddress(stellarAccount, true) || stellarAddress(strings.Replace(stellarAccount, "WHF", "WHG", 1), false) {
		t.Fatal("stellar account")
	}
	if !stellarAddress(stellarContract, true) {
		t.Fatal("stellar contract")
	}
}

func TestJSONObjectKeepsNumbersAndRejectsNonObjects(t *testing.T) {
	raw, err := jsonObject([]byte("{ \"price\": 1.10000000000000000001, \"n\": 12345678901234567890 }"))
	if err != nil || string(raw) != `{"price":1.10000000000000000001,"n":12345678901234567890}` {
		t.Fatal(string(raw), err)
	}
	for _, in := range []string{`[]`, `"x"`, `{} {}`, `{`, ``, `null`} {
		if _, err := jsonObject([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestScrubRemovesSecretsAndControlCharacters(t *testing.T) {
	s := newScrubber("owner.policy.supersecretvalue")
	got := s.clean("token owner.policy.supersecretvalue and supersecretvalue \x1b[31mred‮")
	if strings.Contains(got, "supersecret") || strings.Contains(got, "\x1b") || strings.Contains(got, "‮") {
		t.Fatal(got)
	}
	// Any configured token is redacted in full, however short.
	if got := newScrubber("a.b.c").clean(`unknown command "a.b.c"`); strings.Contains(got, "a.b.c") {
		t.Fatal(got)
	}
	if got := newScrubber(" a.b.c\n").clean("x a.b.c y"); strings.Contains(got, "a.b.c") {
		t.Fatal(got)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		r       map[string]any
		command string
		state   string
		code    int
	}{
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment"}, "status", "passed", exitOK},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "transaction"}, "status", "owner_signature", exitOwnerSignature},
		{map[string]any{"outcome": "pass", "status": "ready"}, "status", "ready", exitOwnerSignature},
		{map[string]any{"outcome": "pass", "status": "ready"}, "eval", "passed", exitOK},
		{map[string]any{"outcome": "pass", "status": "ready"}, "exec", "owner_signature", exitOwnerSignature},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "transaction"}, "eval", "owner_signature", exitOwnerSignature},
		{map[string]any{"outcome": "pass", "status": "submitted", "kind": "transaction"}, "status", "owner_signature", exitOwnerSignature},
		{map[string]any{"outcome": "pass", "status": "something-new"}, "status", "ready", exitOwnerSignature},
		{map[string]any{"outcome": "pass", "status": "recorded", "localRecorded": true, "kind": "transaction"}, "status", "recorded", exitOK},
		{map[string]any{"outcome": "pass", "status": "settled", "executed": true}, "status", "settled", exitOK},
		{map[string]any{"outcome": "fail", "status": "denied"}, "status", "denied", exitDenied},
		{map[string]any{"outcome": "weird"}, "status", "denied", exitDenied},
	}
	for _, c := range cases {
		if got := classify(c.r, c.command); got.State != c.state || got.Exit != c.code {
			t.Errorf("%v %s: got %s/%d", c.r, c.command, got.State, got.Exit)
		}
	}
}

func TestCheckResult(t *testing.T) {
	valid := []struct {
		r       map[string]any
		command string
		local   bool
	}{
		// The documented combinations, with and without the optional booleans and kind.
		{map[string]any{"outcome": "fail", "status": "denied", "code": "BUDGET_EXCEEDED"}, "exec", true},
		{map[string]any{"outcome": "fail", "status": "denied", "executed": false, "localRecorded": false, "kind": "judgment"}, "eval", false},
		{map[string]any{"outcome": "pass", "status": "ready", "executed": false, "localRecorded": false}, "eval", true},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment"}, "status", false},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "transaction", "executed": false}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "ready"}, "status", false},
		{map[string]any{"outcome": "pass", "status": "recorded", "localRecorded": true, "executed": false, "kind": "transaction"}, "exec", true},
		{map[string]any{"outcome": "pass", "status": "settled", "executed": true, "localRecorded": false, "kind": "transaction"}, "status", false},
		{map[string]any{"outcome": "pass", "status": "submitted", "executed": false}, "exec", false},
		{map[string]any{"outcome": "pending", "status": "evaluating", "requestId": "srv-1"}, "exec", false},
		{map[string]any{"outcome": "awaiting_input", "status": "awaiting_input", "prompt": "?"}, "exec", true},
	}
	for _, c := range valid {
		if err := checkResult(c.r, c.command, netOf(c.local)); err != nil {
			t.Errorf("%v %s: %v", c.r, c.command, err)
		}
	}
	invalid := []struct {
		r       map[string]any
		command string
		local   bool
	}{
		{nil, "exec", true},
		{map[string]any{}, "status", false},
		{map[string]any{"outcome": nil}, "exec", false},
		{map[string]any{"outcome": "weird"}, "exec", false},
		{map[string]any{"outcome": "pass", "status": 3}, "exec", false},
		{map[string]any{"outcome": "pass", "localRecorded": "yes"}, "exec", true},
		{map[string]any{"outcome": "fail", "executed": true}, "exec", false},
		{map[string]any{"outcome": "fail", "status": "submitted"}, "status", false},
		{map[string]any{"outcome": "pending", "status": "recorded"}, "exec", true},
		{map[string]any{"outcome": "pass", "status": "denied"}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "settled", "executed": true}, "status", true},
		{map[string]any{"outcome": "pass", "executed": true}, "exec", true},
		{map[string]any{"outcome": "pass", "status": "recorded"}, "status", false},
		{map[string]any{"outcome": "pass", "status": "settled", "localRecorded": true}, "status", true},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "transaction"}, "eval", false},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment"}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "submitted", "kind": "judgment"}, "status", false},
		{map[string]any{"outcome": "pass", "status": "recorded", "localRecorded": true}, "eval", true},
		// Incomplete or contradictory known outcomes.
		{map[string]any{"outcome": "pass"}, "eval", false},
		{map[string]any{"outcome": "pass", "status": ""}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "evaluating"}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "awaiting_input"}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "something-new"}, "status", false},
		{map[string]any{"outcome": "pending", "status": "denied"}, "exec", false},
		{map[string]any{"outcome": "pending"}, "exec", false},
		{map[string]any{"outcome": "awaiting_input", "status": "evaluating"}, "exec", false},
		{map[string]any{"outcome": "fail"}, "exec", false},
		{map[string]any{"outcome": "fail", "status": "evaluating"}, "exec", false},
		{map[string]any{"outcome": "deny", "status": "denied"}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "settled", "executed": false}, "status", false},
		{map[string]any{"outcome": "pass", "status": "settled"}, "status", false},
		{map[string]any{"outcome": "pass", "status": "recorded", "localRecorded": false}, "exec", true},
		{map[string]any{"outcome": "pass", "status": "recorded"}, "exec", true},
		{map[string]any{"outcome": "pass", "status": "ready", "executed": true}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "ready", "localRecorded": true}, "exec", true},
		{map[string]any{"outcome": "pass", "status": "submitted", "executed": true}, "status", false},
		{map[string]any{"outcome": "pass", "status": "submitted"}, "exec", true},
		{map[string]any{"outcome": "fail", "status": "denied", "executed": true}, "exec", false},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "payout"}, "status", false},
		{map[string]any{"outcome": "fail", "status": "denied", "kind": "payout"}, "exec", false},
	}
	for _, c := range invalid {
		if err := checkResult(c.r, c.command, netOf(c.local)); err == nil {
			t.Errorf("%v %s local=%v accepted", c.r, c.command, c.local)
		}
	}
}

func netOf(local bool) netKind {
	if local {
		return netLocal
	}
	return netWallet
}

// Without the network a result is still validated, but anything whose meaning
// depends on it must not be reported as complete.
func TestUnknownNetworkResults(t *testing.T) {
	for _, c := range []struct {
		r     map[string]any
		needs bool
	}{
		{map[string]any{"outcome": "pending", "status": "evaluating"}, false},
		{map[string]any{"outcome": "awaiting_input", "status": "awaiting_input"}, false},
		{map[string]any{"outcome": "fail", "status": "denied"}, false},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "judgment"}, false},
		{map[string]any{"outcome": "pass", "status": "ready", "kind": "transaction"}, true},
		{map[string]any{"outcome": "pass", "status": "ready"}, true},
		{map[string]any{"outcome": "pass", "status": "submitted"}, true},
		{map[string]any{"outcome": "pass", "status": "settled", "executed": true}, true},
		{map[string]any{"outcome": "pass", "status": "recorded", "localRecorded": true}, true},
	} {
		if err := checkResult(c.r, "status", netUnknown); err != nil {
			t.Errorf("%v: %v", c.r, err)
		}
		if needsNetwork(c.r) != c.needs {
			t.Errorf("%v: needsNetwork %v", c.r, !c.needs)
		}
	}
	// Self-contradictory results stay invalid without the network.
	if checkResult(map[string]any{"outcome": "pass", "status": "settled", "localRecorded": true}, "status", netUnknown) == nil {
		t.Error("contradiction accepted")
	}
}

func TestPublishedRoutes(t *testing.T) {
	cfg := &Config{Origin: "https://allowit.example", Owner: owner, Policy: policyID}
	canonical := "/api/harness/" + owner + "/" + policyID + "/judge"
	for _, raw := range []string{"https://allowit.example" + canonical, "HTTPS://AllowIt.Example" + canonical, canonical, "judge", "./judge", "../" + policyID + "/judge"} {
		if !cfg.isRoute("judge", raw) {
			t.Errorf("rejected %q", raw)
		}
	}
	for _, raw := range []string{
		"", "https://evil.example" + canonical, "//evil.example" + canonical, "http://allowit.example" + canonical,
		"https://allowit.example:8443" + canonical, "https://user@allowit.example" + canonical,
		canonical + "?x=1", canonical + "?", canonical + "#f", "transactions", "/api/harness/other/" + policyID + "/judge",
		"../otherPolicy/judge", "/api/harness/" + owner + "/" + policyID + "/judge/", `\\evil.example\judge`, "javascript:judge",
	} {
		if cfg.isRoute("judge", raw) {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestSkillCheck(t *testing.T) {
	cfg := &Config{Origin: "https://allowit.example", Owner: owner, Policy: policyID}
	contract := func(profile, execution string, version int) *Contract {
		c := &Contract{Version: version, Profile: profile}
		c.Capabilities.Execution = execution
		return c
	}
	ok := []Skill{
		{Network: "solana:devnet"},
		{Network: "solana:mainnet", ExecutionMode: "owner_signed", Endpoints: map[string]string{"judge": "judge", "status": "/api/harness/" + owner + "/" + policyID + "/status"}},
		{Network: localDev, ExecutionMode: "local", Owner: owner, PolicyID: policyID, Contract: contract("local_dev", "mock", 1)},
		{Network: "solana:testnet", Contract: contract("solana_owner_signed", "owner_signed", 1), Endpoints: map[string]string{"preferences": "https://elsewhere.example/x"}},
	}
	for _, s := range ok {
		if err := s.check(cfg); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	bound := []Skill{
		{Network: "solana:devnet", Owner: "someone_else"},
		{Network: "solana:devnet", PolicyID: "otherPolicy"},
		{Network: "solana:devnet", Endpoints: map[string]string{"transactions": "https://evil.example/api/harness/" + owner + "/" + policyID + "/transactions"}},
		{Network: "solana:devnet", Endpoints: map[string]string{"status": "judge"}},
	}
	for _, s := range bound {
		var ce *configError
		if err := s.check(cfg); !errors.As(err, &ce) {
			t.Errorf("%+v: %v", s, err)
		}
	}
	unsupported := []Skill{
		{},
		{Network: "stellar:testnet"},
		{Network: "solana:localnet", ExecutionMode: "owner_signed"},
		{Network: "solana:devnet", ExecutionMode: "custodial"},
		{Network: "solana:devnet", ExecutionMode: "local"},
		{Network: localDev, ExecutionMode: "owner_signed"},
		{Network: localDev, Contract: contract("solana_owner_signed", "", 1)},
		{Network: "solana:devnet", Contract: contract("solana_custodial", "", 1)},
		{Network: "solana:devnet", Contract: contract("solana_owner_signed", "mock", 1)},
		{Network: "solana:devnet", Contract: contract("solana_owner_signed", "owner_signed", 2)},
	}
	for _, s := range unsupported {
		var ue *unsupportedError
		if err := s.check(cfg); !errors.As(err, &ue) {
			t.Errorf("%+v: %v", s, err)
		}
	}
	mismatch := Skill{Network: localDev, SourceHash: "aaaa", Contract: contract("local_dev", "mock", 1)}
	mismatch.Contract.Binding.SourceHash = "bbbb"
	if err := mismatch.check(cfg); err == nil {
		t.Error("contract bound to another source accepted")
	}
}

func TestRequestIDIgnoresServerState(t *testing.T) {
	cfg := &Config{Owner: owner, Policy: policyID}
	plan := func(amount string) *Body {
		return &Body{Amount: amount, Token: "USDC", Action: "transferXLM", Recipient: stellarAccount, Execution: &Plan{Rail: "stellar", Asset: "XLM", Quantity: "5"}}
	}
	// A plan's charge follows the published test rate; the plan is the request.
	if requestID("exec", cfg, plan("0.5")) != requestID("exec", cfg, plan("0.6")) {
		t.Error("a published rate change changed the plan request ID")
	}
	budget := func(amount string) *Body { return &Body{Amount: amount, Token: "USDC", Action: "research"} }
	if requestID("exec", cfg, budget("1")) == requestID("exec", cfg, budget("2")) {
		t.Error("different USDC amounts share a request ID")
	}
	if requestID("exec", cfg, budget("1")) == requestID("eval", cfg, budget("1")) {
		t.Error("eval shares the exec ID")
	}
}

func TestRuntimeContextLimits(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 9) + "1" + strings.Repeat("}", 9)
	if _, err := runtimeContext([]byte(deep)); err == nil {
		t.Error("accepted 9 levels")
	}
	ok := strings.Repeat(`{"a":`, 8) + "1" + strings.Repeat("}", 8)
	if _, err := runtimeContext([]byte(ok)); err != nil {
		t.Error("rejected 8 levels:", err)
	}
	many := `{"a":[` + strings.TrimSuffix(strings.Repeat("1,", 128), ",") + `]}`
	if _, err := runtimeContext([]byte(many)); err == nil {
		t.Error("accepted 129 values")
	}
	for _, in := range []string{
		`{"a":1,"a":2}`, `{"x":{"b":1,"b":1}}`, `{"allowitExecution":{}}`, `{} ]`, `{}{}`, `{"a":1} x`,
		`{"a":"` + strings.Repeat("x", 16<<10) + `"}`,
	} {
		if _, err := runtimeContext([]byte(in)); err == nil {
			t.Errorf("accepted %.40q", in)
		}
	}
	if _, err := runtimeContext([]byte(`{"nested":{"allowitExecution":1}}`)); err != nil {
		t.Error("nested key is not reserved:", err)
	}
}
