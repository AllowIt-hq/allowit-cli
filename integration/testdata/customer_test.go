// Only Igor's customer-workspace snapshot defines the structured editor API.
package app

import (
	"encoding/json"
	"testing"
)

func TestAlignmentCustomerPolicy(t *testing.T) {
	c, owner := microClient(t)
	c.s.Chain = &requestChain{}
	terms := baseTerms()
	terms.Budget, terms.PerAction, terms.ReviewAbove = "10", "6", "3"
	input := map[string]any{"id": "cli-customer-policy", "version": 1, "previousRevision": 0, "name": "Customer transfer policy", "instructions": "Transfer within these limits", "terms": terms}
	var binding templateBinding
	if json.Unmarshal(c.ok(t, "policy-template/save", input), &binding) != nil {
		t.Fatal("invalid saved binding")
	}
	if status, _ := c.call("POST", "micro/handoff", map[string]any{"id": binding.ID, "revision": binding.Revision}); status == 200 {
		t.Fatal("draft issued agent authority")
	}
	c.ok(t, "micro/allocation/prepare", map[string]any{"id": binding.ID, "revision": binding.Revision, "amount": "10", "token": "USDC"})
	c.ok(t, "micro/allocation/confirm", map[string]any{"id": binding.ID, "revision": binding.Revision, "signature": "fixture-finalized"})
	h := harnessClient{c: c, owner: owner, p: MicroPolicy{ID: binding.ID, Revision: binding.Revision}}
	a := alignmentClient(t, h)
	a.run(t, 0, alignmentArgs("eval", binding.ID, "customer-at-threshold", "3", owner)...)
	r := a.run(t, 11, alignmentArgs("exec", binding.ID, "customer-above-threshold", "3.000001", owner)...)
	id := r["requestId"].(string)
	q := h.request(t, id)
	c.ok(t, "micro/requests/answer", map[string]any{"id": binding.ID, "revision": binding.Revision, "requestId": id, "inputKey": q.InputKey, "approved": true})
	a.run(t, 10, "status", binding.ID, id)
	a.run(t, 20, alignmentArgs("exec", binding.ID, "customer-over-hard-cap", "6.000001", owner)...)
	unsupported := alignmentArgs("exec", binding.ID, "customer-unsupported", "1", owner)
	for i, arg := range unsupported {
		if arg == "--action" {
			unsupported[i+1] = "swap"
		}
	}
	a.run(t, 20, unsupported...)
}
