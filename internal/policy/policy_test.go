package policy

import (
	"strings"
	"testing"
	"time"
)

const validPolicy = `
scopes:
  - name: github-bot-pat
    provider: onepassword-connect
    ref: "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba"
    fields:
      token: credential
subjects:
  - serviceAccount: agents/pr-reviewer
    claimBytesPerDay: 1048576
    grants:
      - scope: github-bot-pat
        ttlDefault: 15m
        ttlMax: 1h
        renewable: true
        issueWindows:
          - cron: "55 11 * * *"
            duration: 45m
`

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Hash, "sha256:") {
		t.Fatalf("hash: %q", p.Hash)
	}
	g := p.Grant("agents/pr-reviewer", "github-bot-pat")
	if g == nil || !g.Renewable || g.TTLMax.D() != time.Hour {
		t.Fatalf("grant: %+v", g)
	}
	if p.Grant("agents/pr-reviewer", "nonexistent") != nil {
		t.Fatal("unknown scope must be nil grant")
	}
	if p.Grant("agents/other", "github-bot-pat") != nil {
		t.Fatal("ungranted subject must be nil grant")
	}
	if p.ClaimBytesCap("agents/pr-reviewer") != 1048576 {
		t.Fatal("claim bytes cap not loaded")
	}
	if p.ClaimBytesCap("agents/other") != 0 {
		t.Fatal("unknown subject cap must be 0 (unlimited)")
	}
}

func TestIssueWindow(t *testing.T) {
	p, err := Parse([]byte(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	g := p.Grant("agents/pr-reviewer", "github-bot-pat")
	day := func(h, m int) time.Time { return time.Date(2026, 7, 3, h, m, 0, 0, time.UTC) }
	if !g.WindowOpen(day(11, 55)) {
		t.Fatal("window should open at 11:55")
	}
	if !g.WindowOpen(day(12, 30)) {
		t.Fatal("window should be open at 12:30")
	}
	if g.WindowOpen(day(12, 41)) {
		t.Fatal("window should be closed at 12:41")
	}
	if g.WindowOpen(day(3, 0)) {
		t.Fatal("window should be closed at 03:00")
	}
}

func TestNoWindowsMeansAlways(t *testing.T) {
	g := &Grant{}
	if !g.WindowOpen(time.Now()) {
		t.Fatal("grant without windows must always be open")
	}
}

func TestParseRejections(t *testing.T) {
	cases := map[string]string{
		"bad ref": `
scopes:
  - name: x
    provider: onepassword-connect
    ref: "../health"
    fields: {token: t}
subjects: []`,
		"ref with query": `
scopes:
  - name: x
    provider: onepassword-connect
    ref: "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba?x=1"
    fields: {token: t}
subjects: []`,
		"unknown provider": `
scopes:
  - name: x
    provider: hashicorp-vault
    ref: "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba"
    fields: {token: t}
subjects: []`,
		"grant for unknown scope": `
scopes: []
subjects:
  - serviceAccount: a/b
    grants: [{scope: nope, ttlDefault: 1m, ttlMax: 2m}]`,
		"ttlDefault > ttlMax": `
scopes:
  - name: x
    provider: onepassword-connect
    ref: "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba"
    fields: {token: t}
subjects:
  - serviceAccount: a/b
    grants: [{scope: x, ttlDefault: 2h, ttlMax: 1h}]`,
		"bad subject key": `
scopes: []
subjects:
  - serviceAccount: "not-namespaced"
    grants: []`,
		"bad cron": `
scopes:
  - name: x
    provider: onepassword-connect
    ref: "vaults/abcdefghijklmnopqrstuvwxyz/items/zyxwvutsrqponmlkjihgfedcba"
    fields: {token: t}
subjects:
  - serviceAccount: a/b
    grants:
      - scope: x
        ttlDefault: 1m
        ttlMax: 2m
        issueWindows: [{cron: "not a cron", duration: 5m}]`,
	}
	for name, yamlSrc := range cases {
		if _, err := Parse([]byte(yamlSrc)); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}
