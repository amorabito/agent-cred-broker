// Package policy loads and validates the deny-by-default grant policy from a
// YAML file (a GitOps-managed ConfigMap in production). No grant, no lease.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

// opRefPattern is the 1Password Connect reference format. Refs are validated
// at load time and upstream URLs are built from parsed components, never by
// string concatenation, so a malformed ref cannot redirect the broker's
// authenticated request.
var opRefPattern = regexp.MustCompile(`^vaults/[a-z0-9]{26}/items/[a-z0-9]{26}$`)

// github-app scope validation. The ref names an installation; permissions and
// repositories are policy-pinned (a subject can never widen them), so they are
// validated structurally at load time and fail the broker fast if malformed.
var (
	ghInstallationRefPattern = regexp.MustCompile(`^installations/[0-9]+$`)
	ghPermissionsPattern     = regexp.MustCompile(`^[a-z_]+=(read|write|admin)(,[a-z_]+=(read|write|admin))*$`)
	ghRepositoriesPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$`)
)

var subjectKeyPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// KnownProviders lists providers the broker can construct: the static
// 1Password Connect provider and the revocable GitHub App provider. A provider
// being "known" (a valid policy value) is separate from being configured at
// runtime — a policy may reference github-app on a broker that has no App key,
// in which case issuance denies with provider-unconfigured.
var KnownProviders = map[string]bool{"onepassword-connect": true, "github-app": true}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Scope struct {
	Name     string `yaml:"name"`
	Provider string `yaml:"provider"`
	Ref      string `yaml:"ref"`
	// Fields maps lease field name -> provider output key/label.
	Fields map[string]string `yaml:"fields"`
	// Params carries provider-specific static configuration (e.g. GitHub
	// repositories/permissions). Policy-pinned, never caller-supplied.
	Params map[string]string `yaml:"params"`
}

type IssueWindow struct {
	Cron     string   `yaml:"cron"`
	Duration Duration `yaml:"duration"`

	sched cron.Schedule `yaml:"-"`
}

// Open reports whether the window is open at t: some cron fire time f exists
// with t-duration < f <= t. Evaluation is pinned to UTC — cron expressions
// are security enforcement here, and a pod-level TZ env var must not shift
// an issuance window by hours.
func (w *IssueWindow) Open(t time.Time) bool {
	t = t.UTC()
	fire := w.sched.Next(t.Add(-w.Duration.D()))
	return !fire.After(t)
}

type Grant struct {
	Scope        string        `yaml:"scope"`
	TTLDefault   Duration      `yaml:"ttlDefault"`
	TTLMax       Duration      `yaml:"ttlMax"`
	Renewable    bool          `yaml:"renewable"`
	IssueWindows []IssueWindow `yaml:"issueWindows"`
}

// WindowOpen reports whether issuance is allowed at t. No windows = any time.
func (g *Grant) WindowOpen(t time.Time) bool {
	if len(g.IssueWindows) == 0 {
		return true
	}
	for i := range g.IssueWindows {
		if g.IssueWindows[i].Open(t) {
			return true
		}
	}
	return false
}

type SubjectPolicy struct {
	ServiceAccount string  `yaml:"serviceAccount"` // "<namespace>/<name>"
	Grants         []Grant `yaml:"grants"`
	// ClaimBytesPerDay caps the audit bytes a subject can submit via
	// /v1/claims per UTC day. 0 = unlimited. Exists to bound audit
	// flooding (threat model §4).
	ClaimBytesPerDay int64 `yaml:"claimBytesPerDay"`
}

type Policy struct {
	Scopes   []Scope         `yaml:"scopes"`
	Subjects []SubjectPolicy `yaml:"subjects"`

	Hash string `yaml:"-"`

	scopeByName map[string]*Scope
	grantBySubj map[string]map[string]*Grant
}

// Parse validates policy bytes. Validation failures at startup are fatal to
// the broker; on reload the previous policy is retained.
func Parse(raw []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	sum := sha256.Sum256(raw)
	p.Hash = "sha256:" + hex.EncodeToString(sum[:])

	p.scopeByName = make(map[string]*Scope, len(p.Scopes))
	for i := range p.Scopes {
		s := &p.Scopes[i]
		if s.Name == "" {
			return nil, fmt.Errorf("scope %d: missing name", i)
		}
		if _, dup := p.scopeByName[s.Name]; dup {
			return nil, fmt.Errorf("duplicate scope %q", s.Name)
		}
		if !KnownProviders[s.Provider] {
			return nil, fmt.Errorf("scope %q: unknown provider %q", s.Name, s.Provider)
		}
		if len(s.Fields) == 0 {
			return nil, fmt.Errorf("scope %q: at least one field mapping required", s.Name)
		}
		switch s.Provider {
		case "onepassword-connect":
			if !opRefPattern.MatchString(s.Ref) {
				return nil, fmt.Errorf("scope %q: ref must match %s", s.Name, opRefPattern)
			}
		case "github-app":
			if !ghInstallationRefPattern.MatchString(s.Ref) {
				return nil, fmt.Errorf("scope %q: github-app ref must match %s", s.Name, ghInstallationRefPattern)
			}
			// permissions are mandatory: a permission-less installation token
			// inherits the installation's whole scope — the opposite of least
			// privilege. repositories are optional (omitting = all installation
			// repos), but must be well-formed if present.
			if !ghPermissionsPattern.MatchString(s.Params["permissions"]) {
				return nil, fmt.Errorf("scope %q: github-app requires params.permissions like \"contents=read,pull_requests=write\"", s.Name)
			}
			if repos := s.Params["repositories"]; repos != "" && !ghRepositoriesPattern.MatchString(repos) {
				return nil, fmt.Errorf("scope %q: github-app params.repositories must be a comma-separated repo-name list", s.Name)
			}
			// The provider's only output key is "token"; every field must map
			// to it (fail-fast rather than at first issuance).
			for lf, key := range s.Fields {
				if key != "token" {
					return nil, fmt.Errorf("scope %q: github-app field %q must map to \"token\"", s.Name, lf)
				}
			}
		}
		p.scopeByName[s.Name] = s
	}

	p.grantBySubj = make(map[string]map[string]*Grant, len(p.Subjects))
	for i := range p.Subjects {
		sp := &p.Subjects[i]
		if !subjectKeyPattern.MatchString(sp.ServiceAccount) {
			return nil, fmt.Errorf("subject %d: serviceAccount must be \"<namespace>/<name>\", got %q", i, sp.ServiceAccount)
		}
		if _, dup := p.grantBySubj[sp.ServiceAccount]; dup {
			return nil, fmt.Errorf("duplicate subject %q", sp.ServiceAccount)
		}
		grants := make(map[string]*Grant, len(sp.Grants))
		for j := range sp.Grants {
			g := &sp.Grants[j]
			if _, ok := p.scopeByName[g.Scope]; !ok {
				return nil, fmt.Errorf("subject %q: grant for unknown scope %q", sp.ServiceAccount, g.Scope)
			}
			if _, dup := grants[g.Scope]; dup {
				return nil, fmt.Errorf("subject %q: duplicate grant for scope %q", sp.ServiceAccount, g.Scope)
			}
			if g.TTLDefault.D() <= 0 || g.TTLMax.D() <= 0 {
				return nil, fmt.Errorf("subject %q scope %q: ttlDefault and ttlMax must be positive", sp.ServiceAccount, g.Scope)
			}
			if g.TTLDefault.D() > g.TTLMax.D() {
				return nil, fmt.Errorf("subject %q scope %q: ttlDefault exceeds ttlMax", sp.ServiceAccount, g.Scope)
			}
			for k := range g.IssueWindows {
				w := &g.IssueWindows[k]
				sched, err := cronParser.Parse(w.Cron)
				if err != nil {
					return nil, fmt.Errorf("subject %q scope %q window %d: %w", sp.ServiceAccount, g.Scope, k, err)
				}
				if w.Duration.D() <= 0 {
					return nil, fmt.Errorf("subject %q scope %q window %d: duration must be positive", sp.ServiceAccount, g.Scope, k)
				}
				w.sched = sched
			}
			grants[g.Scope] = g
		}
		p.grantBySubj[sp.ServiceAccount] = grants
	}
	return &p, nil
}

// Scope returns a scope definition by name, or nil.
func (p *Policy) Scope(name string) *Scope { return p.scopeByName[name] }

// Grant returns the grant for (subjectKey, scope), or nil. A nil return means
// deny — unknown scope and ungranted scope are indistinguishable by design.
func (p *Policy) Grant(subjectKey, scope string) *Grant {
	return p.grantBySubj[subjectKey][scope]
}

// ClaimBytesCap returns the subject's daily claim-bytes cap (0 = unlimited).
func (p *Policy) ClaimBytesCap(subjectKey string) int64 {
	for i := range p.Subjects {
		if p.Subjects[i].ServiceAccount == subjectKey {
			return p.Subjects[i].ClaimBytesPerDay
		}
	}
	return 0
}

// GrantsFor lists a subject's grants for /v1/whoami (names + TTL caps only).
func (p *Policy) GrantsFor(subjectKey string) []Grant {
	m := p.grantBySubj[subjectKey]
	out := make([]Grant, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// SubjectKeys returns all subject keys (for reload diff summaries).
func (p *Policy) SubjectKeys() []string {
	keys := make([]string, 0, len(p.grantBySubj))
	for k := range p.grantBySubj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ScopeNames returns all scope names (for reload diff summaries).
func (p *Policy) ScopeNames() []string {
	names := make([]string, 0, len(p.scopeByName))
	for n := range p.scopeByName {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
