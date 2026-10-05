package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Plan and Call mirror the server's ExecutionPlan v1 exactly.
type Plan struct {
	Rail     string `json:"rail"`
	Asset    string `json:"asset"`
	Quantity string `json:"quantity"`
	Memo     string `json:"memo,omitempty"`
	Data     string `json:"data,omitempty"`
	Before   []Call `json:"before,omitempty"`
	After    []Call `json:"after,omitempty"`
}
type Call struct {
	Type     string          `json:"type"`
	Contract string          `json:"contract"`
	Method   string          `json:"method"`
	Args     json.RawMessage `json:"args"`
	MaxCost  string          `json:"maxCostUSDC"`
}

// Body is the judge/transactions request. Context is forwarded as the exact
// JSON value supplied by the caller.
type Body struct {
	RequestID string          `json:"requestId"`
	Amount    string          `json:"amount"`
	Token     string          `json:"token"`
	Action    string          `json:"action"`
	Merchant  string          `json:"merchant,omitempty"`
	Recipient string          `json:"recipient,omitempty"`
	Context   json.RawMessage `json:"context,omitempty"`
	Execution *Plan           `json:"execution,omitempty"`
}

type requestFlags struct {
	rail, op, addr, amount, action, merchant string
	context, memo, data, before, after        string
	requestID, budget                         string
}

var (
	opPattern        = regexp.MustCompile(`^transfer([A-Z]{2,10})$`)
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,100}$`)
	methodPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }
func usagef(format string, a ...any) error {
	return &usageError{fmt.Sprintf(format, a...)}
}

// actionRequired explains why --op no longer supplies the action, and how to
// resend a 0.1.1 request (which defaulted the action to the op) unchanged.
const actionRequired = "--action is required: it is the action the policy evaluates (e.g. --action transfer or --action research); --op only selects the transfer. To retry a request sent without --action by allowit 0.1.1, add --action with its --op value (e.g. --action transferUSDC) and keep every other flag: that is the same request and request ID"

// buildBody turns flags into the exact server request. kind is "eval" or "exec".
func buildBody(kind string, f requestFlags, s *Skill, stdin io.Reader) (*Body, error) {
	b := &Body{Token: "USDC", Action: f.action, Merchant: f.merchant}
	if b.Action == "" {
		return nil, usagef("%s", actionRequired)
	}
	if len(b.Action) > 100 || len(b.Merchant) > 200 {
		return nil, usagef("--action is limited to 100 bytes and --merchant to 200 bytes")
	}
	if f.context != "" {
		raw, err := readValue(f.context, stdin, 16<<10)
		if err != nil {
			return nil, usagef("--context: %v", err)
		}
		ctx, err := runtimeContext(raw)
		if err != nil {
			return nil, usagef("--context: %v", err)
		}
		b.Context = ctx
	}
	if f.amount == "" {
		return nil, usagef("--amount is required")
	}
	if (f.rail == "") != (f.op == "") {
		return nil, usagef("--rail and --op are used together; omit both to send --amount as a plain USDC amount")
	}
	planOnly := f.memo != "" || f.data != "" || f.before != "" || f.after != ""
	if f.rail == "" {
		// A plain budget request: amount is USDC.
		if planOnly {
			return nil, usagef("--memo, --data, --before and --after need --rail and --op")
		}
		if _, err := usdcUnits(f.amount); err != nil {
			return nil, usagef("--amount: %v", err)
		}
		b.Amount = f.amount
		if f.addr != "" {
			b.Recipient = f.addr
		}
		return b, checkWallet(kind, b, s)
	}
	m := opPattern.FindStringSubmatch(f.op)
	if m == nil {
		return nil, usagef("--op must look like transferSOL, transferXLM or transferUSDC")
	}
	asset := m[1]
	rails := s.rails()
	if len(rails) == 0 {
		return nil, usagef("AllowIt published no rails for this policy; send a plain USDC request with --amount and --action, without --rail and --op")
	}
	assets, ok := rails[f.rail]
	if !ok {
		return nil, usagef("--rail %q is not available for this policy (%s)", f.rail, describeRails(rails))
	}
	if !contains(assets, asset) {
		return nil, usagef("%s is not available on %s (%s)", asset, f.rail, strings.Join(assets, ", "))
	}
	if !s.local() {
		// Wallet policies: owner-signed USDC transfers without an execution plan.
		if planOnly {
			return nil, usagef("--memo, --data, --before and --after are available only for Local dev policies")
		}
		// The request carries no asset, so anything else would silently become USDC.
		if f.rail != "solana" || asset != "USDC" {
			return nil, usagef("wallet policies accept only --rail solana --op transferUSDC")
		}
		if _, err := usdcUnits(f.amount); err != nil {
			return nil, usagef("--amount: %v", err)
		}
		b.Amount = f.amount
		b.Recipient = f.addr
		return b, checkWallet(kind, b, s)
	}
	if err := s.planSupport(f.memo != "" || f.data != "", f.before != "" || f.after != ""); err != nil {
		return nil, usagef("%v", err)
	}
	if f.addr == "" {
		return nil, usagef("--addr is required with --rail")
	}
	if !railAddress(f.rail, f.addr, false) {
		return nil, usagef("--addr is not a valid %s address", f.rail)
	}
	plan := &Plan{Rail: f.rail, Asset: asset, Quantity: f.amount, Memo: f.memo}
	if len(plan.Memo) > 256 {
		return nil, usagef("--memo is limited to 256 bytes")
	}
	if f.data != "" {
		data, err := readValue(f.data, stdin, 1024)
		if err != nil {
			return nil, usagef("--data: %v", err)
		}
		plan.Data = base64.StdEncoding.EncodeToString(data)
	}
	var err error
	if plan.Before, err = readCalls("--before", f.before, f.rail, stdin); err != nil {
		return nil, err
	}
	if plan.After, err = readCalls("--after", f.after, f.rail, stdin); err != nil {
		return nil, err
	}
	rates, published := s.rates()
	rate, ok := rates[asset]
	if !ok {
		return nil, usagef("the service did not publish a rate for %s", asset)
	}
	decimals, ok := published[asset]
	if !ok {
		decimals = defaultDecimals[asset]
	}
	charge, err := budgetCharge(plan.Quantity, rate, decimals, append(append([]Call{}, plan.Before...), plan.After...))
	if err != nil {
		return nil, usagef("--amount: %v", err)
	}
	b.Amount = charge
	b.Recipient = f.addr
	b.Execution = plan
	return b, nil
}

func checkWallet(kind string, b *Body, s *Skill) error {
	if s.local() || b.Recipient == "" && kind == "eval" {
		return nil
	}
	if !solanaAddress(b.Recipient) {
		return usagef("--addr must be the recipient's Solana address")
	}
	return nil
}

func readCalls(name, value, rail string, stdin io.Reader) ([]Call, error) {
	if value == "" {
		return nil, nil
	}
	raw, err := readValue(value, stdin, 32<<10)
	if err != nil {
		return nil, usagef("%s: %v", name, err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	var calls []Call
	if err := d.Decode(&calls); err != nil || d.Decode(new(any)) != io.EOF {
		return nil, usagef("%s must be a JSON array of {type, contract, method, args, maxCostUSDC}", name)
	}
	if len(calls) > 8 {
		return nil, usagef("%s allows at most 8 calls", name)
	}
	for i, c := range calls {
		if c.Type != "contract_call" || !railAddress(rail, c.Contract, true) || !methodPattern.MatchString(c.Method) {
			return nil, usagef("%s[%d] needs type contract_call, a valid %s contract and a method name", name, i, rail)
		}
		if _, err := jsonObject(c.Args); err != nil || len(c.Args) > 2048 {
			return nil, usagef("%s[%d].args must be a JSON object of at most 2048 bytes", name, i)
		}
		if c.MaxCost == "" {
			return nil, usagef("%s[%d] needs maxCostUSDC (use \"0\" for none)", name, i)
		}
	}
	return calls, nil
}

// readValue reads a literal, @file or - (stdin).
func readValue(v string, stdin io.Reader, limit int64) ([]byte, error) {
	var r io.Reader
	switch {
	case v == "-":
		r = stdin
	case strings.HasPrefix(v, "@"):
		f, err := os.Open(v[1:])
		if err != nil {
			return nil, errors.New("cannot read file")
		}
		defer f.Close()
		r = f
	default:
		if int64(len(v)) > limit {
			return nil, fmt.Errorf("larger than %d bytes", limit)
		}
		return []byte(v), nil
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, errors.New("cannot read input")
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}

// jsonObject validates a single JSON object and returns it compacted. Number
// literals and key order are preserved exactly.
func jsonObject(raw []byte) (json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, errors.New("must be a JSON object")
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("must be a JSON object")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("must contain exactly one JSON object")
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return nil, errors.New("must be a JSON object")
	}
	return out.Bytes(), nil
}

// runtimeContext applies the server's context limits early (the server still
// enforces them): one object, at most 16 KB, depth 8, 128 values, no repeated
// keys, and no caller-supplied allowitExecution, which the server reserves.
func runtimeContext(raw []byte) (json.RawMessage, error) {
	ctx, err := jsonObject(raw)
	if err != nil {
		return nil, err
	}
	if len(ctx) > 16<<10 {
		return nil, errors.New("must be at most 16 KB")
	}
	d := json.NewDecoder(bytes.NewReader(ctx))
	d.UseNumber()
	count := 0
	var scan func(depth int, top bool) error
	scan = func(depth int, top bool) error {
		if depth > 9 {
			return errors.New("is nested more than 8 levels deep")
		}
		t, err := d.Token()
		if err != nil {
			return errors.New("must be a JSON object")
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, _ := d.Token()
				key, _ := k.(string)
				if seen[key] {
					return fmt.Errorf("repeats the field %q", key)
				}
				if top && key == "allowitExecution" {
					return errors.New("must not contain allowitExecution; AllowIt supplies it")
				}
				seen[key] = true
				if count++; count > 128 {
					return errors.New("has more than 128 values")
				}
				if err := scan(depth+1, false); err != nil {
					return err
				}
			}
			_, err = d.Token()
		case json.Delim('['):
			for d.More() {
				if count++; count > 128 {
					return errors.New("has more than 128 values")
				}
				if err := scan(depth+1, false); err != nil {
					return err
				}
			}
			_, err = d.Token()
		}
		return err
	}
	if err := scan(1, true); err != nil {
		return nil, err
	}
	return ctx, nil
}

func encodeJSON(v any) []byte {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// requestID derives a stable client request ID from what the caller asked for,
// so an identical retry reuses it and any change produces a new one. Server
// state (policy revision, source hash, published test rates) is left out: a
// retry after an unknown result must keep its ID even if the policy changed.
// A plan's charge is derived from the published rates, so the plan itself
// identifies the request instead.
func requestID(kind string, cfg *Config, b *Body) string {
	copy := *b
	copy.RequestID = ""
	if copy.Execution != nil {
		copy.Amount = ""
	}
	h := sha256.New()
	fmt.Fprintf(h, "allowit-cli/v2\n%s\n%s\n%s\n", cfg.Owner, cfg.Policy, kind)
	h.Write(encodeJSON(copy))
	return "cli-" + kind + "-" + hex.EncodeToString(h.Sum(nil))[:40]
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
