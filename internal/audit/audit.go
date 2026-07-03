// Package audit emits signed act-claim events: one JSON object per line on the
// configured writer (stdout in production), Ed25519-signed over the RFC 8785
// canonical form of the event with the sig field removed.
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
)

const (
	// Version of the audit envelope, independent of the API version.
	Version = 1
	Kind    = "act-claim"
)

// Event types. lease.*, policy.*, auth.* and broker.* are broker-attested;
// claim.recorded wraps agent-asserted content.
const (
	TypeLeaseIssued        = "lease.issued"
	TypeLeaseDenied        = "lease.denied"
	TypeLeaseRenewed       = "lease.renewed"
	TypeLeaseSurrendered   = "lease.surrendered"
	TypeLeaseExpired       = "lease.expired"
	TypeClaimRecorded      = "claim.recorded"
	TypePolicyReloaded     = "policy.reloaded"
	TypePolicyReloadFailed = "policy.reload_failed"
	TypeAuthFailed         = "auth.failed"
	TypeBrokerStarted      = "broker.started"
)

// Subject is the authenticated caller identity as established by TokenReview.
type Subject struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceaccount"`
	Pod            string `json:"pod,omitempty"`
	PodUID         string `json:"pod_uid,omitempty"`
}

// Key returns the policy lookup key, "<namespace>/<serviceaccount>".
func (s Subject) Key() string { return s.Namespace + "/" + s.ServiceAccount }

// Source describes where a request came from, as observed by the broker.
type Source struct {
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// BrokerInfo identifies the emitting broker instance and signing key.
type BrokerInfo struct {
	Instance string `json:"instance"`
	KID      string `json:"kid"`
	Seq      uint64 `json:"seq"`
}

// Event is the audit envelope. Attested holds only broker-observed facts;
// Asserted holds only caller-supplied content. The split is structural so
// consumers cannot confuse the two.
type Event struct {
	V         int               `json:"v"`
	Kind      string            `json:"kind"`
	Type      string            `json:"type"`
	TS        string            `json:"ts"`
	RequestID string            `json:"request_id,omitempty"`
	Broker    BrokerInfo        `json:"broker"`
	Subject   *Subject          `json:"subject,omitempty"`
	Source    *Source           `json:"source,omitempty"`
	Attested  map[string]any    `json:"attested,omitempty"`
	Asserted  map[string]string `json:"asserted,omitempty"`
	Sig       string            `json:"sig,omitempty"`
}

// Signer holds the Ed25519 signing key and its derived key ID.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

// NewSigner wraps an Ed25519 private key; the kid is derived from the
// public key so it is stable across restarts with the same key.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &Signer{priv: priv, pub: pub, kid: "k" + hex.EncodeToString(sum[:4])}
}

func (s *Signer) KID() string               { return s.kid }
func (s *Signer) Public() ed25519.PublicKey { return s.pub }

// PublicBase64 returns the base64 raw public key as served by /v1/audit/verify-key.
func (s *Signer) PublicBase64() string { return base64.StdEncoding.EncodeToString(s.pub) }

// Emitter serializes, signs and writes events. Writes are serialized behind a
// mutex — one atomic line per event — so concurrent requests cannot interleave
// bytes into unverifiable JSON.
type Emitter struct {
	mu       sync.Mutex
	w        io.Writer
	signer   *Signer
	instance string
	seq      uint64
	now      func() time.Time
	counts   func(eventType string) // optional metrics hook
}

// NewEmitter creates an Emitter writing signed events to w, tagged with the
// given instance name.
func NewEmitter(w io.Writer, signer *Signer, instance string) *Emitter {
	return &Emitter{w: w, signer: signer, instance: instance, now: time.Now}
}

// SetClock overrides the timestamp source (tests only).
func (e *Emitter) SetClock(now func() time.Time) { e.now = now }

// SetCounter installs a per-event-type metrics hook.
func (e *Emitter) SetCounter(f func(eventType string)) { e.counts = f }

// Emit fills the envelope, signs, and writes the event as a single line.
// The event passed in must not have Broker, TS, V, Kind or Sig set.
//
// The sequence number is committed only after a successful write, so a
// marshal or write failure does not leave a gap that acb-verify would
// misread as event deletion. (A partial write can still produce a corrupt
// line followed by a reused seq — the verifier reports duplicates
// separately for exactly this case.)
func (e *Emitter) Emit(ev Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	seq := e.seq + 1
	ev.V = Version
	ev.Kind = Kind
	ev.TS = e.now().UTC().Format(time.RFC3339)
	ev.Broker = BrokerInfo{Instance: e.instance, KID: e.signer.kid, Seq: seq}
	ev.Sig = ""

	unsigned, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	canonical, err := jcs.Transform(unsigned)
	if err != nil {
		return fmt.Errorf("canonicalize audit event: %w", err)
	}
	ev.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(e.signer.priv, canonical))

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal signed audit event: %w", err)
	}
	if _, err := e.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	e.seq = seq
	if e.counts != nil {
		e.counts(ev.Type)
	}
	return nil
}

// Verify checks one event line against a public key. It returns the decoded
// event on success. Used by acb-verify and tests.
func Verify(line []byte, pub ed25519.PublicKey) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}
	if ev.Sig == "" {
		return nil, fmt.Errorf("event has no sig")
	}
	sig, err := base64.StdEncoding.DecodeString(ev.Sig)
	if err != nil {
		return nil, fmt.Errorf("decode sig: %w", err)
	}

	// Reconstruct the signed form: the event object with sig removed.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("parse event object: %w", err)
	}
	delete(raw, "sig")
	unsigned, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-marshal event: %w", err)
	}
	canonical, err := jcs.Transform(unsigned)
	if err != nil {
		return nil, fmt.Errorf("canonicalize event: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, fmt.Errorf("signature verification failed")
	}
	return &ev, nil
}
