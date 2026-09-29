package cli

import (
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
