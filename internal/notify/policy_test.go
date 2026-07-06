package notify

import "testing"

const validNotifyPolicy = `
subjects:
  - serviceAccount: agents/alert-triage
    grants:
      - kind: push
        targets: [mobile_app_test_phone]
      - kind: persistent_create
        idPrefix: "alert-triage-"
      - kind: persistent_dismiss
        idPrefix: "alert-triage-"
  - serviceAccount: agents/house-hunt-digest
    grants:
      - kind: push
        targets: [mobile_app_test_phone]
`

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(validNotifyPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if p.Grant("agents/alert-triage", KindPush) == nil {
		t.Fatal("alert-triage should hold push")
	}
	if p.PushTarget("agents/alert-triage") != "mobile_app_test_phone" {
		t.Fatalf("push target: %q", p.PushTarget("agents/alert-triage"))
	}
	// digest may push but NOT create/dismiss persistent notifications.
	if p.Grant("agents/house-hunt-digest", KindPush) == nil {
		t.Fatal("digest should hold push")
	}
	if p.Grant("agents/house-hunt-digest", KindPersistentCreate) != nil {
		t.Fatal("digest must NOT hold persistent_create")
	}
	// ungranted subject = nil (deny).
	if p.Grant("agents/someone-else", KindPush) != nil {
		t.Fatal("ungranted subject must be nil")
	}
}

func TestParseRejections(t *testing.T) {
	cases := map[string]string{
		"bad subject key": `
subjects:
  - serviceAccount: "not-namespaced"
    grants: [{kind: push, targets: [x]}]`,
		"unknown kind": `
subjects:
  - serviceAccount: a/b
    grants: [{kind: unlock_door, targets: [x]}]`,
		"push without targets": `
subjects:
  - serviceAccount: a/b
    grants: [{kind: push}]`,
		"push bad target charset": `
subjects:
  - serviceAccount: a/b
    grants: [{kind: push, targets: ["mobile_app/../lock"]}]`,
		"persistent without idPrefix": `
subjects:
  - serviceAccount: a/b
    grants: [{kind: persistent_create}]`,
		"duplicate kind": `
subjects:
  - serviceAccount: a/b
    grants:
      - {kind: push, targets: [x]}
      - {kind: push, targets: [y]}`,
		"duplicate subject": `
subjects:
  - serviceAccount: a/b
    grants: [{kind: push, targets: [x]}]
  - serviceAccount: a/b
    grants: [{kind: push, targets: [y]}]`,
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
	}
}
