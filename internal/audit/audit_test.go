package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newTestEmitter(t *testing.T) (*Emitter, *bytes.Buffer, *Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner(priv)
	buf := &bytes.Buffer{}
	e := NewEmitter(buf, signer, "test-instance")
	e.SetClock(func() time.Time { return time.Date(2026, 7, 3, 12, 0, 2, 0, time.UTC) })
	return e, buf, signer
}

func TestSignVerifyRoundTrip(t *testing.T) {
	e, buf, signer := newTestEmitter(t)
	err := e.Emit(Event{
		Type:      TypeLeaseIssued,
		RequestID: "req_test",
		Subject:   &Subject{Namespace: "agents", ServiceAccount: "pr-reviewer", Pod: "pr-reviewer-abc"},
		Attested:  map[string]any{"scope": "github-bot-pat", "decision": "issued"},
		Asserted:  map[string]string{"reason": "review PRs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.TrimSpace(buf.Bytes())
	ev, err := Verify(line, signer.Public())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ev.Broker.Seq != 1 || ev.Broker.KID != signer.KID() || ev.TS != "2026-07-03T12:00:02Z" {
		t.Fatalf("unexpected envelope: %+v", ev.Broker)
	}
}

func TestTamperDetected(t *testing.T) {
	e, buf, signer := newTestEmitter(t)
	if err := e.Emit(Event{Type: TypeLeaseIssued, Attested: map[string]any{"scope": "a"}}); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(buf.Bytes(), []byte(`"scope":"a"`), []byte(`"scope":"b"`), 1)
	if bytes.Equal(tampered, buf.Bytes()) {
		t.Fatal("tamper substitution did not apply")
	}
	if _, err := Verify(bytes.TrimSpace(tampered), signer.Public()); err == nil {
		t.Fatal("tampered event verified")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	e, buf, _ := newTestEmitter(t)
	if err := e.Emit(Event{Type: TypeClaimRecorded}); err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(bytes.TrimSpace(buf.Bytes()), otherPub); err == nil {
		t.Fatal("event verified under wrong key")
	}
}

// TestSingleLineInvariant: no caller-supplied byte may introduce a line break
// or unescaped control character — the log-injection defense.
func TestSingleLineInvariant(t *testing.T) {
	e, buf, signer := newTestEmitter(t)
	hostile := "done\n{\"v\":1,\"kind\":\"act-claim\",\"type\":\"lease.issued\",\"attested\":{\"scope\":\"prod\"}}\r\x00\x1b[31m"
	err := e.Emit(Event{
		Type:     TypeClaimRecorded,
		Subject:  &Subject{Namespace: "agents", ServiceAccount: "evil"},
		Asserted: map[string]string{"reason": hostile, "action": "gh.pr.merge"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("event is not exactly one line: %q", out)
	}
	body := strings.TrimSuffix(out, "\n")
	for _, r := range body {
		if r < 0x20 {
			t.Fatalf("unescaped control character %q in output", r)
		}
	}
	// And the hostile content must round-trip intact + verify.
	ev, err := Verify([]byte(body), signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Asserted["reason"] != hostile {
		t.Fatal("asserted content did not round-trip verbatim")
	}
}

func TestSeqMonotonic(t *testing.T) {
	e, buf, _ := newTestEmitter(t)
	for i := 0; i < 3; i++ {
		if err := e.Emit(Event{Type: TypeLeaseIssued}); err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	for i, line := range lines {
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Broker.Seq != uint64(i+1) {
			t.Fatalf("line %d: seq=%d", i, ev.Broker.Seq)
		}
	}
}
