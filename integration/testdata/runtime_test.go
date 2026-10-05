package app

import (
	"context"
	"net/url"
	"testing"
)

func TestAlignmentGeneratedSkillDashPolicy(t *testing.T) {
	h := activePolicy(t, `pub async fn evaluate(ctx:&Context)->PolicyResult{set_cap(ctx,"10","USDC")?;Ok(())}`)
	_, err := h.c.s.micro(context.Background(), h.owner, func(v *MicroWorkspace) error {
		p, e := findPolicy(v, h.p.ID)
		if e != nil {
			return e
		}
		p.ID = "-policy0123456789"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.p.ID = "-policy0123456789"
	a := alignmentClient(t, h)
	skillURL := a.server.URL + "/api/harness/" + h.owner + "/" + h.p.ID + "/skill.md?access_token=" + url.QueryEscape(a.h.token) + "&interface=cli"
	w := getSkill(h.c.s, skillURL)
	if w.Code != 200 {
		t.Fatalf("skill HTTP %d", w.Code)
	}
	f := parseSkill(t, w.Body.String())
	args := generatedExec(t, f, "generated-skill-001", h.owner, "transfer")
	if len(args) < 3 || args[1] != "--" || args[2] != h.p.ID {
		t.Fatal("not the actual dash-policy skill format")
	}
	r := a.raw(t, 10, append(args, "--json")...)
	id := r["requestId"].(string)
	a.raw(t, 10, "status", "--", h.p.ID, id, "--wait", "0s", "--json")
}

func TestAlignmentStatusSurvivesSkillRefusal(t *testing.T) {
	h := activePolicy(t, `pub async fn evaluate(ctx:&Context)->PolicyResult{set_cap(ctx,"10","USDC")?;require_user_input(ctx,"Approve this transfer").await?;Ok(())}`)
	a := alignmentClient(t, h)
	r := a.run(t, 11, alignmentArgs("exec", h.p.ID, "runtime-recovery", "1", h.owner)...)
	id := r["requestId"].(string)
	// Simulate a stored compiler binding that the current assembler cannot
	// issue. The request already exists and status has no execution effect.
	_, err := h.c.s.micro(context.Background(), h.owner, func(v *MicroWorkspace) error {
		p, err := findPolicy(v, h.p.ID)
		if err != nil {
			return err
		}
		p.IRHash = "unavailable-old-artifact"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a.run(t, 4, "show", h.p.ID)
	status := a.run(t, 11, "status", h.p.ID, id)
	if status["requestId"] != id || status["state"] != "awaiting_input" || status["executed"] != false {
		t.Fatal("existing request could not be recovered", status)
	}
	if h.request(t, id).Status != "awaiting_input" {
		t.Fatal("status altered request")
	}
}
