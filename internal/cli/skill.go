package cli

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const localDev = "local:dev"

// Skill is the subset of GET /skill the CLI relies on. Services differ in what
// they publish: the current backend sends owner, policyId, absolute endpoints
// and a typed contract; older and customer servers omit some of them. Omitted
// fields are accepted, published fields must agree (see check).
type Skill struct {
	Title          string            `json:"title"`
	Name           string            `json:"name"`
	Owner          string            `json:"owner"`
	PolicyID       string            `json:"policyId"`
	Status         string            `json:"status"`
	Network        string            `json:"network"`
	Revision       int               `json:"revision"`
	SourceHash     string            `json:"sourceHash"`
	Language       string            `json:"language"`
	OriginalIntent string            `json:"originalIntent"`
	ExecutionMode  string            `json:"executionMode"`
	ExpiresAt      string            `json:"expiresAt"`
	Policy         string            `json:"policy"`
	Endpoints      map[string]string `json:"endpoints"`
	Budget         *struct {
		Allocation string `json:"allocation"`
		Spent      string `json:"spent"`
	} `json:"budget"`
	Allocation *struct {
		Amount string `json:"amount"`
	} `json:"allocation"`
	Capabilities struct {
		Mode                      string              `json:"mode"`
		Execution                 string              `json:"execution"`
		Rail                      string              `json:"rail"`
		Assets                    []string            `json:"assets"`
		Rails                     map[string][]string `json:"rails"`
		Rates                     map[string]string   `json:"fixedTestRatesUSDC"`
		Decimals                  map[string]int      `json:"assetDecimals"`
		CallsRequireOwnerApproval bool                `json:"callsRequireOwnerApproval"`
	} `json:"capabilities"`
	Contract *Contract `json:"contract"`
	Workflow []struct {
		Kind        string `json:"kind"`
		Label       string `json:"label"`
		Description string `json:"description"`
	} `json:"workflow"`
}

// Contract is the typed skill contract (version 1) of the current backend.
type Contract struct {
	Version int    `json:"version"`
	Profile string `json:"profile"`
	Binding struct {
		SourceHash      string `json:"sourceHash"`
		IRHash          string `json:"irHash"`
		RegistryVersion string `json:"registryVersion"`
	} `json:"binding"`
	Capabilities struct {
		Execution           string              `json:"execution"`
		Rails               map[string][]string `json:"rails"`
		ExecutionPlans      bool                `json:"executionPlans"`
		MemoData            bool                `json:"memoData"`
		ContractCalls       bool                `json:"contractCalls"`
		Rates               map[string]string   `json:"fixedTestRatesUSDC"`
		Decimals            map[string]int      `json:"assetDecimals"`
		OwnerAnswerRequired bool                `json:"ownerAnswerRequiredForCalls"`
	} `json:"capabilities"`
	ContextU64Keys []string `json:"contextU64Keys"`
}

// netKind is what the CLI knows about where a policy's results land.
type netKind int

const (
	netUnknown netKind = iota // no usable policy description (status recovery only)
	netLocal                  // Local dev: mock recordings, never on chain
	netWallet                 // Solana: owner-signed USDC transfers
)

// The networks and profile labels this CLI supports. Anything else is refused
// rather than treated as a wallet network.
var (
	networks   = map[string]netKind{localDev: netLocal, "solana:devnet": netWallet, "solana:testnet": netWallet, "solana:mainnet": netWallet}
	modes      = map[string]netKind{"local": netLocal, "owner_signed": netWallet}
	profiles   = map[string]netKind{"local_dev": netLocal, "solana_owner_signed": netWallet}
	executions = map[string]netKind{"mock": netLocal, "owner_signed": netWallet}
)

// unsupportedError means AllowIt described the policy in a way this CLI cannot
// act on safely (unknown network, profile or contract version). Nothing was sent.
type unsupportedError struct{ Err error }

func (e *unsupportedError) Error() string { return e.Err.Error() }

func unsupportedf(format string, a ...any) error {
	return &unsupportedError{fmt.Errorf(format, a...)}
}

// check validates the description against the configured token and origin
// before anything is sent. A different owner, policy or route is a
// configError; an unknown network or profile is an unsupportedError.
func (s *Skill) check(cfg *Config) error {
	if s.Owner != "" && s.Owner != cfg.Owner || s.PolicyID != "" && s.PolicyID != cfg.Policy {
		return &configError{fmt.Errorf("AllowIt described policy %s of owner %s, not the policy in ALLOWIT_TOKEN", orUnset(s.PolicyID), orUnset(s.Owner))}
	}
	for _, action := range []string{"judge", "transactions", "status", "skill"} {
		raw, ok := s.Endpoints[action]
		if ok && !cfg.isRoute(action, raw) {
			return &configError{fmt.Errorf("AllowIt reported the %s endpoint %q, which is not %s; check ALLOWIT_URL", action, raw, cfg.route(action))}
		}
	}
	if s.Network == "" {
		return unsupportedf("AllowIt did not report the policy's network")
	}
	net, ok := networks[s.Network]
	if !ok {
		return unsupportedf("AllowIt reports network %q, which this CLI does not support", s.Network)
	}
	labels := []struct {
		name, value string
		known       map[string]netKind
	}{
		{"executionMode", s.ExecutionMode, modes},
		{"capabilities.mode", s.Capabilities.Mode, executions},
		{"capabilities.execution", s.Capabilities.Execution, executions},
	}
	if c := s.Contract; c != nil {
		if c.Version != 1 {
			return unsupportedf("AllowIt published skill contract version %d; this CLI supports version 1", c.Version)
		}
		if c.Binding.SourceHash != "" && s.SourceHash != "" && c.Binding.SourceHash != s.SourceHash {
			return unsupportedf("AllowIt published a contract bound to source %s for policy source %s", short(c.Binding.SourceHash), short(s.SourceHash))
		}
		labels = append(labels, []struct {
			name, value string
			known       map[string]netKind
		}{{"contract.profile", c.Profile, profiles}, {"contract.capabilities.execution", c.Capabilities.Execution, executions}}...)
	}
	for _, l := range labels {
		if l.value == "" {
			continue // not published by this service
		}
		if k, ok := l.known[l.value]; !ok || k != net {
			return unsupportedf("AllowIt reports %s %q for network %q, which this CLI does not support", l.name, l.value, s.Network)
		}
	}
	return nil
}

// net is only meaningful after check succeeded.
func (s *Skill) net() netKind { return networks[s.Network] }

func (s *Skill) local() bool { return s.net() == netLocal }

// rails are the published rails; a wallet policy that publishes none still
// supports the one transfer its profile defines.
func (s *Skill) rails() map[string][]string {
	switch {
	case s.Contract != nil && len(s.Contract.Capabilities.Rails) > 0:
		return s.Contract.Capabilities.Rails
	case len(s.Capabilities.Rails) > 0:
		return s.Capabilities.Rails
	case s.Capabilities.Rail != "":
		return map[string][]string{s.Capabilities.Rail: s.Capabilities.Assets}
	case s.net() == netWallet:
		return map[string][]string{"solana": {"USDC"}}
	}
	return nil
}

func (s *Skill) rates() (map[string]string, map[string]int) {
	if s.Contract != nil && len(s.Contract.Capabilities.Rates) > 0 {
		return s.Contract.Capabilities.Rates, s.Contract.Capabilities.Decimals
	}
	return s.Capabilities.Rates, s.Capabilities.Decimals
}

func (s *Skill) callsNeedOwner() bool {
	return s.Capabilities.CallsRequireOwnerApproval || s.Contract != nil && s.Contract.Capabilities.OwnerAnswerRequired
}

// planSupport refuses plan features a typed contract says the service lacks.
// Without a contract, Local dev plans are accepted as before.
func (s *Skill) planSupport(memoData, calls bool) error {
	c := s.Contract
	switch {
	case c == nil:
		return nil
	case !c.Capabilities.ExecutionPlans:
		return errors.New("AllowIt does not accept execution plans for this policy; send a plain request with --amount and --action")
	case memoData && !c.Capabilities.MemoData:
		return errors.New("AllowIt does not accept --memo or --data for this policy")
	case calls && !c.Capabilities.ContractCalls:
		return errors.New("AllowIt does not accept --before or --after contract calls for this policy")
	}
	return nil
}

func (s *Skill) title() string {
	if s.Title != "" {
		return s.Title
	}
	if t := strings.TrimPrefix(s.Name, "AllowIt policy "); t != "" {
		return t
	}
	return "(untitled)"
}

// route is the canonical policy-scoped harness URL; the bearer token is only
// ever sent here.
func (c *Config) route(action string) string {
	return c.Origin + "/api/harness/" + c.Owner + "/" + c.Policy + "/" + action
}

// isRoute reports whether a published endpoint, absolute or relative to the
// skill URL, names exactly the canonical route on the configured origin.
func (c *Config) isRoute(action, raw string) bool {
	base, err := url.Parse(c.route("skill"))
	if err != nil || raw == "" {
		return false
	}
	ref, err := url.Parse(raw)
	if err != nil || ref.ForceQuery || strings.ContainsAny(raw, "?#\\") {
		return false
	}
	u := base.ResolveReference(ref)
	return u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host) == c.Origin &&
		u.EscapedPath() == "/api/harness/"+c.Owner+"/"+c.Policy+"/"+action
}

func orUnset(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}
