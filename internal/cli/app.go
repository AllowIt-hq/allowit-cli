// Package cli implements the allowit command: a thin, strict client for an
// AllowIt policy's harness API. Policy enforcement stays on the server.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const Version = "0.2.0-dev"

const usage = `allowit sends actions through an AllowIt policy.

Configuration (environment only):
  ALLOWIT_URL      service origin, e.g. https://allowit.example
  ALLOWIT_TOKEN    the policy's harness token (owner.policy.secret)
  ALLOWIT_CA_FILE  optional extra PEM root certificates

Commands:
  allowit show   POLICY [--json] [--source]
  allowit eval   POLICY [request flags]     check permission; spends nothing
  allowit exec   POLICY [request flags]     submit the request
  allowit status POLICY REQUEST_ID [--wait 60s] [--json]
  allowit version

Request flags:
  --action NAME        required: the action the policy evaluates, e.g. transfer
  --rail solana|stellar --op transferSOL|transferXLM|transferUSDC --addr ADDRESS
  --amount DECIMAL     asset quantity (USDC amount without --op)
  --merchant NAME      optional merchant
  --context JSON       runtime context object: literal, @file or - for stdin
  --memo TEXT          mock plan memo (Local dev)
  --data TEXT          mock plan data bytes, literal or @file (Local dev)
  --before JSON        contract calls before the transfer (Local dev)
  --after JSON         contract calls after the transfer (Local dev)
  --request-id ID      explicit request ID (default: derived from the request)
  --budget DECIMAL     assert the computed USDC budget charge
  --wait DURATION      how long to wait for a pending evaluation (default 60s)
  --json               machine-readable output

Exit codes: 0 passed/recorded/settled, 2 usage, 3 config, auth or unsupported
policy description, 4 rejected,
5 uncertain result (retry only as printed, with the same --request-id), 10 owner
signature (or passed but not yet complete), 11 awaiting owner input, 12 pending,
20 denied.

Request IDs: give each intended operation its own --request-id and separate IDs
for eval and exec; rerun with the same ID only to retry the same request. After
exit 5 never retry with a new ID: rerun with the printed --request-id, or check
the printed server requestId with allowit status.
`

// App holds the process environment so tests can run commands in-process.
type App struct {
	Getenv       func(string) string
	Stdin        io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
	Sleep        func(time.Duration)
	Timeout      time.Duration
	PollInterval time.Duration
}

func (a App) Run(args []string) int {
	if a.Sleep == nil {
		a.Sleep = time.Sleep
	}
	if a.Timeout == 0 {
		a.Timeout = 60 * time.Second
	}
	if a.PollInterval == 0 {
		a.PollInterval = 2 * time.Second
	}
	s := newScrubber(a.Getenv("ALLOWIT_TOKEN"))
	out, errOut := printer{a.Stdout, s}, printer{a.Stderr, s}
	if len(args) == 0 {
		errOut.printf("%s", usage)
		return exitUsage
	}
	var code int
	var err error
	switch args[0] {
	case "show":
		code, err = a.show(args[1:], out, errOut)
	case "eval", "exec":
		code, err = a.request(args[0], args[1:], out, errOut)
	case "status":
		code, err = a.status(args[1:], out, errOut)
	case "version", "--version":
		out.printf("allowit %s\n", Version)
		return exitOK
	case "help", "-h", "--help":
		out.printf("%s", usage)
		return exitOK
	default:
		err = usagef("unknown command %q (show, eval, exec, status)", args[0])
	}
	if err != nil {
		errOut.printf("allowit: %v\n", err)
		return exitCode(err)
	}
	return code
}

func exitCode(err error) int {
	var ue *usageError
	var ce *configError
	var ae *apiError
	var un *uncertainError
	var us *unsupportedError
	switch {
	case errors.As(err, &ue):
		return exitUsage
	case errors.As(err, &us):
		return exitConfig
	case errors.As(err, &un):
		return exitUncertain
	case errors.As(err, &ae):
		if ae.Status == 401 || ae.Status == 403 {
			return exitConfig
		}
		return exitRejected
	case errors.As(err, &ce):
		return exitConfig
	}
	return exitConfig
}

// parse accepts flags and positional arguments in any order. The gateway's
// generated commands use -- before a dash-prefixed policy and put flags after
// it. Protect the command's remaining identifier slots, then resume flags.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	identifiers := 1
	if fs.Name() == "status" {
		identifiers = 2
	}
	var positional []string
	for len(args) > 0 {
		var literal []string
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if arg == "--" {
				literal, args = args[i+1:], args[:i]
				break
			}
			if !strings.HasPrefix(arg, "-") || arg == "-" {
				continue
			}
			name, _, inline := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
			if f := fs.Lookup(name); f != nil && !inline {
				b, boolean := f.Value.(interface{ IsBoolFlag() bool })
				if !boolean || !b.IsBoolFlag() {
					i++ // A string flag may itself have "--" as its value.
				}
			}
		}
		for len(args) > 0 {
			if err := fs.Parse(args); err != nil {
				return nil, usagef("%v", err)
			}
			rest := fs.Args()
			if len(rest) == 0 {
				break
			}
			positional = append(positional, rest[0])
			args = rest[1:]
		}
		n := min(max(identifiers-len(positional), 0), len(literal))
		positional = append(positional, literal[:n]...)
		args = literal[n:]
	}
	return positional, nil
}

// setup loads configuration and binds the positional POLICY to the token.
func (a App) setup(policy string) (*client, error) {
	cfg, err := loadConfig(a.Getenv)
	if err != nil {
		return nil, &configError{err}
	}
	if policy != cfg.Policy {
		return nil, &configError{fmt.Errorf("POLICY %q does not match the policy in ALLOWIT_TOKEN", policy)}
	}
	c, err := newClient(cfg, a.Timeout, a.Sleep)
	if err != nil {
		return nil, &configError{err}
	}
	return c, nil
}

// skill reads and validates the policy description; nothing is sent to judge
// or transactions unless it names this owner, policy and origin and a
// supported network.
func (c *client) skill() (*Skill, map[string]any, error) {
	var raw map[string]any
	if err := c.call("GET", "skill", nil, &raw); err != nil {
		return nil, nil, err
	}
	var s Skill
	if err := remarshal(raw, &s); err != nil {
		return nil, nil, unsupportedf("AllowIt returned a policy description this CLI cannot read: %v", err)
	}
	if err := s.check(c.cfg); err != nil {
		return nil, nil, err
	}
	return &s, raw, nil
}

// statusNetwork returns the policy's network for status, or netUnknown when
// the description is unavailable for a reason that does not stop a status
// read: an assembly refusal (HTTP 409), another non-auth HTTP error, an
// unreadable or unsupported description, or a failed GET. Auth failures and a
// description naming another policy, owner or route still stop.
func (c *client) statusNetwork(errOut printer) (netKind, error) {
	s, _, err := c.skill()
	if err == nil {
		return s.net(), nil
	}
	var ae *apiError
	var ce *configError
	if errors.As(err, &ce) || errors.As(err, &ae) && (ae.Status == 401 || ae.Status == 403) {
		return netUnknown, err
	}
	errOut.printf("allowit: the policy description is unavailable (%v); reading the status without the policy's network\n", err)
	return netUnknown, nil
}

func (a App) show(args []string, out, errOut printer) (int, error) {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	source := fs.Bool("source", false, "")
	pos, err := parse(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 1 {
		return 0, usagef("usage: allowit show POLICY [--json] [--source]")
	}
	c, err := a.setup(pos[0])
	if err != nil {
		return 0, err
	}
	s, raw, err := c.skill()
	if err != nil {
		return 0, err
	}
	if *asJSON {
		delete(raw, "authorization")
		delete(raw, "accessUrl")
		if !*source {
			delete(raw, "policy")
		}
		out.json(raw)
		return exitOK, nil
	}
	showPolicy(out, s, c.cfg.Policy, *source)
	return exitOK, nil
}

// showPolicy prints what AllowIt published; fields a service omits are left
// out or marked, never shown empty.
func showPolicy(p printer, s *Skill, policy string, source bool) {
	p.printf("AllowIt policy: %s\n", s.title())
	switch {
	case s.PolicyID == "":
		p.printf("Policy:     %s (from ALLOWIT_TOKEN; AllowIt did not report the policy ID)\n", policy)
	case s.Revision > 0 || s.SourceHash != "":
		p.printf("Policy:     %s (revision %d, source %s)\n", s.PolicyID, s.Revision, short(s.SourceHash))
	default:
		p.printf("Policy:     %s\n", s.PolicyID)
	}
	if c := s.Contract; c != nil && c.Binding.IRHash != "" {
		p.printf("Binding:    IR %s, registry %s\n", short(c.Binding.IRHash), c.Binding.RegistryVersion)
	}
	if s.local() {
		p.printf("Network:    %s (mock execution; no wallet, no funds move)\n", s.Network)
	} else {
		p.printf("Network:    %s (every transfer needs the owner's wallet signature)\n", s.Network)
	}
	if s.Status != "" {
		p.printf("Status:     %s\n", s.Status)
	}
	if s.ExpiresAt != "" {
		p.printf("Access:     expires %s\n", s.ExpiresAt)
	}
	if s.Budget != nil {
		p.printf("Budget:     %s USDC allocated, %s USDC spent\n", s.Budget.Allocation, s.Budget.Spent)
	} else if s.Allocation != nil {
		p.printf("Budget:     %s USDC allocated\n", s.Allocation.Amount)
	}
	if rails := s.rails(); len(rails) > 0 {
		p.printf("Rails:      %s\n", describeRails(rails))
	} else {
		p.printf("Rails:      none published (plain USDC requests with --amount and --action only)\n")
	}
	if rates, _ := s.rates(); s.local() && len(rates) > 0 {
		p.printf("Test rates: %s (USDC per unit; fixed, not market prices)\n", describeRates(rates))
	}
	if s.local() && s.callsNeedOwner() {
		p.printf("Calls:      contract calls in --before/--after always need the owner's approval\n")
	}
	if c := s.Contract; c != nil && len(c.ContextU64Keys) > 0 {
		keys := make([]string, len(c.ContextU64Keys))
		for i, k := range c.ContextU64Keys {
			keys[i] = fmt.Sprintf("%q", k)
		}
		p.printf("Context:    the policy may read these --context fields as non-negative integers: %s\n", strings.Join(keys, ", "))
	}
	if len(s.Workflow) > 0 {
		p.printf("Checks:\n")
		for i, step := range s.Workflow {
			line := step.Label
			if step.Description != "" && step.Description != step.Label {
				line += " — " + step.Description
			}
			p.printf("  %d. %s\n", i+1, line)
		}
	}
	if intent := strings.TrimSpace(s.OriginalIntent); intent != "" {
		p.printf("Original request:\n")
		for _, line := range strings.Split(intent, "\n") {
			p.printf("  %s\n", line)
		}
	}
	if source {
		p.printf("\nPolicy source (%s):\n%s\n", s.Language, s.Policy)
	}
}

func (a App) request(kind string, args []string, out, errOut printer) (int, error) {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	var f requestFlags
	for name, target := range map[string]*string{"rail": &f.rail, "op": &f.op, "addr": &f.addr, "amount": &f.amount, "action": &f.action, "merchant": &f.merchant, "context": &f.context, "memo": &f.memo, "data": &f.data, "before": &f.before, "after": &f.after, "request-id": &f.requestID, "budget": &f.budget} {
		fs.StringVar(target, name, "", "")
	}
	asJSON := fs.Bool("json", false, "")
	wait := fs.Duration("wait", 60*time.Second, "")
	pos, err := parse(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 1 {
		return 0, usagef("usage: allowit %s POLICY --action ACTION [--rail RAIL --op OP] --addr ADDRESS --amount QUANTITY [--context JSON]", kind)
	}
	if err := checkWait(*wait); err != nil {
		return 0, err
	}
	if f.requestID != "" && !requestIDPattern.MatchString(f.requestID) {
		return 0, usagef("--request-id must be 8 to 100 characters from A-Z a-z 0-9 . _ : -")
	}
	c, err := a.setup(pos[0])
	if err != nil {
		return 0, err
	}
	s, _, err := c.skill()
	if err != nil {
		return 0, err
	}
	body, err := buildBody(kind, f, s, a.Stdin)
	if err != nil {
		return 0, err
	}
	if f.budget != "" {
		want, err := usdcUnits(f.budget)
		if err != nil {
			return 0, usagef("--budget: %v", err)
		}
		if got, _ := usdcUnits(body.Amount); got == nil || got.Cmp(want) != 0 {
			return 0, usagef("--budget %s does not match the computed charge of %s USDC", f.budget, body.Amount)
		}
	}
	body.RequestID = f.requestID
	if body.RequestID == "" {
		body.RequestID = requestID(kind, c.cfg, body)
	}
	action := "judge"
	if kind == "exec" {
		action = "transactions"
	}
	// Print the ID before sending, so it survives even if this process does not.
	errOut.printf("allowit: %s request %s (budget charge %s USDC)\n", kind, body.RequestID, body.Amount)
	if kind == "exec" {
		errOut.printf("allowit: if the result is unknown, retry only with --request-id %s\n", body.RequestID)
	}
	var r map[string]any
	if err := c.call("POST", action, encodeJSON(body), &r); err != nil {
		var un *uncertainError
		if errors.As(err, &un) {
			return 0, fmt.Errorf("%w\nThe request may have reached AllowIt. Do not retry with a new request ID. Retry only by rerunning the same command with --request-id %s: AllowIt applies a request ID at most once", err, body.RequestID)
		}
		return 0, err
	}
	// From here AllowIt has accepted the request: any failure to read its
	// result is uncertain, never a rejection.
	unknown := func(err error) error {
		msg := fmt.Sprintf("%v\nAllowIt accepted %s request %s", err, kind, body.RequestID)
		next := ""
		if id := str(r["requestId"]); requestIDPattern.MatchString(id) {
			msg += " (server requestId " + id + ")"
			next = fmt.Sprintf("allowit status --wait 60s -- %s %s, or ", pos[0], id)
		}
		return &uncertainError{fmt.Errorf("%s, but its result is unknown. Do not retry with a new request ID. Check it with %srerun the same command with --request-id %s", msg, next, body.RequestID)}
	}
	if err := checkResult(r, kind, s.net()); err != nil {
		return 0, unknown(err)
	}
	if str(r["outcome"]) == "pending" {
		id := str(r["requestId"])
		if !requestIDPattern.MatchString(id) {
			return 0, unknown(errors.New("AllowIt returned a pending result without a valid requestId"))
		}
		next, err := a.poll(c, id, *wait, r, kind, s.net())
		if err != nil {
			return 0, unknown(err)
		}
		r = next
	}
	res := classify(r, kind)
	if *asJSON {
		r["state"], r["clientRequestId"], r["budgetChargeUSDC"], r["exitCode"] = res.State, body.RequestID, body.Amount, res.Exit
		out.json(r)
	} else {
		out.printResult(r, res, body.RequestID)
		out.printf("budgetChargeUSDC: %s\n", body.Amount)
	}
	return res.Exit, nil
}

func (a App) status(args []string, out, errOut printer) (int, error) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	wait := fs.Duration("wait", 0, "")
	pos, err := parse(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 2 {
		return 0, usagef("usage: allowit status POLICY REQUEST_ID [--wait 60s]")
	}
	if !requestIDPattern.MatchString(pos[1]) {
		return 0, usagef("REQUEST_ID is the requestId printed by eval or exec")
	}
	if err := checkWait(*wait); err != nil {
		return 0, err
	}
	c, err := a.setup(pos[0])
	if err != nil {
		return 0, err
	}
	// The network decides whether a completed result is a mock or on chain.
	// Status is a read, so it goes ahead without it; see needsNetwork.
	net, err := c.statusNetwork(errOut)
	if err != nil {
		return 0, err
	}
	var r map[string]any
	if err := c.call("POST", "status", encodeJSON(map[string]string{"requestId": pos[1]}), &r); err != nil {
		return 0, err
	}
	if err := checkStatus(r, pos[1], net); err != nil {
		return 0, &uncertainError{fmt.Errorf("%v\nThe state of request %s is unknown; check again with allowit status", err, pos[1])}
	}
	if o := str(r["outcome"]); o == "pending" || (o == "awaiting_input" || str(r["status"]) == "submitted" || str(r["status"]) == "ready") && *wait > 0 {
		if r, err = a.poll(c, pos[1], *wait, r, "status", net); err != nil {
			return 0, &uncertainError{fmt.Errorf("%v\nThe state of request %s is unknown; check again with allowit status", err, pos[1])}
		}
	}
	if net == netUnknown && needsNetwork(r) {
		return 0, &uncertainError{fmt.Errorf("AllowIt reported outcome %q with status %q for request %s, but the policy's network could not be established, so the CLI cannot tell a Local dev mock recording from a wallet transfer. Nothing is confirmed as recorded, signed or paid. Check again with allowit status once allowit show works", str(r["outcome"]), str(r["status"]), pos[1])}
	}
	res := classify(r, "status")
	if *asJSON {
		r["state"], r["exitCode"] = res.State, res.Exit
		out.json(r)
	} else {
		out.printResult(r, res, "")
	}
	return res.Exit, nil
}

// poll re-reads a request until its state changes or wait elapses. The request
// is known to exist, so every failure here means its state is unknown.
func (a App) poll(c *client, id string, wait time.Duration, r map[string]any, command string, net netKind) (map[string]any, error) {
	start := str(r["status"])
	for elapsed := time.Duration(0); elapsed < wait; elapsed += a.PollInterval {
		a.Sleep(a.PollInterval)
		var next map[string]any
		if err := c.call("POST", "status", encodeJSON(map[string]string{"requestId": id}), &next); err != nil {
			return nil, fmt.Errorf("checking the request status failed: %v", err)
		}
		if err := checkStatus(next, id, net); err != nil {
			return nil, err
		}
		if command != "status" {
			if err := checkResult(next, command, net); err != nil {
				return nil, err
			}
		}
		r = next
		if str(r["status"]) != start {
			break
		}
	}
	return r, nil
}

// checkStatus validates a /status result for the request that was asked for.
func checkStatus(r map[string]any, id string, net netKind) error {
	if err := checkResult(r, "status", net); err != nil {
		return err
	}
	if got := str(r["requestId"]); got == "" {
		return errors.New("AllowIt returned a status without its requestId")
	} else if got != id {
		return fmt.Errorf("AllowIt returned the status of a different request (%s)", got)
	}
	return nil
}

const maxWait = 10 * time.Minute

func checkWait(d time.Duration) error {
	if d < 0 || d > maxWait {
		return usagef("--wait must be between 0s and %s", maxWait)
	}
	return nil
}

func remarshal(in any, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func describeRails(rails map[string][]string) string {
	names := make([]string, 0, len(rails))
	for name := range rails {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = name + " (" + strings.Join(rails[name], ", ") + ")"
	}
	return strings.Join(parts, "; ")
}

func describeRates(rates map[string]string) string {
	names := make([]string, 0, len(rates))
	for name := range rates {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = name + "=" + rates[name]
	}
	return strings.Join(parts, " ")
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
