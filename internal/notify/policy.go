// Package notify implements the ha-notify-proxy: a workload-identity-gated
// capability that narrows Home Assistant's all-or-nothing access token down to
// three notify actions (ADR-0006). Agents authenticate with their own bound
// k8s ServiceAccount token and hold no HA credential; the proxy leases the HA
// token from the broker per request, makes exactly one HA call, and drops it.
package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Notification kinds. These map 1:1 to the compiled HA allowlist in ha.go — the
// binary can address nothing outside this set no matter what the policy says.
const (
	KindPush              = "push"
	KindPersistentCreate  = "persistent_create"
	KindPersistentDismiss = "persistent_dismiss"
)

var knownKinds = map[string]bool{
	KindPush: true, KindPersistentCreate: true, KindPersistentDismiss: true,
}

var subjectKeyPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// haTargetPattern bounds a notify target (a mobile_app service name). The proxy
// never string-concatenates a caller value into the HA URL, but the policy's
// targets ARE used to build it, so they are charset-constrained at load time.
var haTargetPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// Grant is one permission for a subject: a kind plus its constraint.
type Grant struct {
	Kind string `yaml:"kind"`
	// Targets: for push, the allowed notify service names (e.g.
	// mobile_app_x). The proxy pins the FIRST as the device the agent cannot
	// choose; the agent sends no target of its own.
	Targets []string `yaml:"targets"`
	// IDPrefix: for persistent_* kinds, the allowed notification_id prefix, so
	// a hijacked caller can only touch its OWN notifications.
	IDPrefix string `yaml:"idPrefix"`
}

// SubjectPolicy grants a caller ServiceAccount ("<namespace>/<name>") a set of
// notify capabilities.
type SubjectPolicy struct {
	ServiceAccount string  `yaml:"serviceAccount"`
	Grants         []Grant `yaml:"grants"`
}

// Policy is the deny-by-default notify policy. No grant, no notification.
type Policy struct {
	Subjects []SubjectPolicy `yaml:"subjects"`

	Hash string `yaml:"-"`

	byKey map[string]map[string]*Grant // subjectKey -> kind -> grant
}

// Parse validates policy bytes. A malformed policy is fatal at startup and
// retained-on-reload, exactly like the broker's.
func Parse(raw []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse notify policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	p.Hash = "sha256:" + hex.EncodeToString(sum[:])

	p.byKey = make(map[string]map[string]*Grant, len(p.Subjects))
	for i := range p.Subjects {
		sp := &p.Subjects[i]
		if !subjectKeyPattern.MatchString(sp.ServiceAccount) {
			return nil, fmt.Errorf("subject %d: serviceAccount must be \"<namespace>/<name>\", got %q", i, sp.ServiceAccount)
		}
		if _, dup := p.byKey[sp.ServiceAccount]; dup {
			return nil, fmt.Errorf("duplicate subject %q", sp.ServiceAccount)
		}
		grants := make(map[string]*Grant, len(sp.Grants))
		for j := range sp.Grants {
			g := &sp.Grants[j]
			if !knownKinds[g.Kind] {
				return nil, fmt.Errorf("subject %q: unknown kind %q", sp.ServiceAccount, g.Kind)
			}
			if _, dup := grants[g.Kind]; dup {
				return nil, fmt.Errorf("subject %q: duplicate grant for kind %q", sp.ServiceAccount, g.Kind)
			}
			switch g.Kind {
			case KindPush:
				if len(g.Targets) == 0 {
					return nil, fmt.Errorf("subject %q: push grant needs at least one target", sp.ServiceAccount)
				}
				for _, t := range g.Targets {
					if !haTargetPattern.MatchString(t) {
						return nil, fmt.Errorf("subject %q: invalid push target %q", sp.ServiceAccount, t)
					}
				}
			case KindPersistentCreate, KindPersistentDismiss:
				if g.IDPrefix == "" {
					return nil, fmt.Errorf("subject %q: %s grant needs a non-empty idPrefix", sp.ServiceAccount, g.Kind)
				}
			}
			grants[g.Kind] = g
		}
		p.byKey[sp.ServiceAccount] = grants
	}
	return &p, nil
}

// Grant returns the grant for (subjectKey, kind), or nil for deny. Unknown and
// ungranted are indistinguishable by design.
func (p *Policy) Grant(subjectKey, kind string) *Grant {
	return p.byKey[subjectKey][kind]
}

// PushTarget returns the pinned notify target for a subject's push grant, or ""
// if the subject may not push. The agent cannot influence this — it is the
// policy's first target.
func (p *Policy) PushTarget(subjectKey string) string {
	g := p.Grant(subjectKey, KindPush)
	if g == nil || len(g.Targets) == 0 {
		return ""
	}
	return g.Targets[0]
}
