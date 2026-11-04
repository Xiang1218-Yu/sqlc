package vetaudit

import (
	"fmt"
	"slices"
)

// ParseChangeTypes validates and normalizes caller-supplied change type
// filters. Values are matched against ChangeTypes, de-duplicated and
// returned in canonical order. An unknown value is an invalid filter.
func ParseChangeTypes(values []string) ([]ChangeType, error) {
	known := ChangeTypes()
	var out []ChangeType
	for _, v := range values {
		t := ChangeType(v)
		if !slices.Contains(known, t) {
			return nil, fmt.Errorf("invalid change type %q: must be one of %s",
				v, joinChangeTypes(known))
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b ChangeType) int {
		return changeTypeOrder[a] - changeTypeOrder[b]
	})
	return out, nil
}

func joinChangeTypes(types []ChangeType) string {
	s := ""
	for i, t := range types {
		if i > 0 {
			s += ", "
		}
		s += string(t)
	}
	return s
}

// NormalizeStringSet de-duplicates and sorts a caller-supplied filter
// value list so repeated runs with different flag ordering are identical.
func NormalizeStringSet(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// ValidateFilter ensures every requested package and rule exists. It is
// called before any package is checked so an invalid filter never leaves
// partial state behind.
func ValidateFilter(f Filter, knownPackages, knownRules []string) error {
	knownPackages = NormalizeStringSet(knownPackages)
	knownRules = NormalizeStringSet(knownRules)
	for _, p := range f.Packages {
		if !slices.Contains(knownPackages, p) {
			return fmt.Errorf("invalid package filter %q: must be one of %v", p, knownPackages)
		}
	}
	for _, r := range f.Rules {
		if !slices.Contains(knownRules, r) {
			return fmt.Errorf("invalid rule filter %q: must be one of %v", r, knownRules)
		}
	}
	for _, t := range f.Changes {
		if !slices.Contains(ChangeTypes(), t) {
			return fmt.Errorf("invalid change filter %q", t)
		}
	}
	return nil
}

// ApplyFilter returns the changes selected by the filter. Empty package,
// rule or change sets select everything.
func ApplyFilter(changes []Change, f Filter) []Change {
	packages := sliceSet(f.Packages)
	rules := sliceSet(f.Rules)
	types := make(map[ChangeType]struct{}, len(f.Changes))
	for _, t := range f.Changes {
		types[t] = struct{}{}
	}
	out := make([]Change, 0, len(changes))
	for _, ch := range changes {
		if len(packages) > 0 {
			if _, ok := packages[ch.Package]; !ok {
				continue
			}
		}
		if len(rules) > 0 {
			if _, ok := rules[ch.Rule]; !ok {
				continue
			}
		}
		if len(types) > 0 {
			if _, ok := types[ch.Type]; !ok {
				continue
			}
		}
		out = append(out, ch)
	}
	return out
}

func sliceSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

// EffectiveFilter fills empty package/rule sets with the full known sets
// so scope filtering matches the packages and rules that were actually
// audited. Change types are left empty to mean "all types".
func EffectiveFilter(f Filter, knownPackages, knownRules []string) Filter {
	out := Filter{Changes: f.Changes}
	if len(f.Packages) == 0 {
		out.Packages = NormalizeStringSet(knownPackages)
	} else {
		out.Packages = NormalizeStringSet(f.Packages)
	}
	if len(f.Rules) == 0 {
		out.Rules = NormalizeStringSet(knownRules)
	} else {
		out.Rules = NormalizeStringSet(f.Rules)
	}
	return out
}

// GateFailure describes a change that forces the audit gate to fail.
type GateFailure struct {
	Change Change
	Reason string
}

// EvaluateGate returns the changes that fail the severity gate. Only
// problems introduced or escalated relative to the baseline are gated:
//
//   - a new diagnostic at or above the threshold fails;
//   - a severity increase whose new severity is at or above the threshold
//     fails;
//   - resolved, unchanged, moved and message-only changes never fail, and
//     severity decreases never fail.
//
// The gate is evaluated over the supplied (already filtered) changes, so
// report filters and exit status stay consistent for every filter
// combination.
func EvaluateGate(changes []Change, threshold Severity) []GateFailure {
	var failures []GateFailure
	for _, ch := range changes {
		switch ch.Type {
		case ChangeNew:
			cur := *ch.Current
			if cur.Severity.AtLeast(threshold) {
				failures = append(failures, GateFailure{
					Change: ch,
					Reason: fmt.Sprintf("new %s diagnostic", cur.Severity),
				})
			}
		case ChangeSeverity:
			old, cur := *ch.Baseline, *ch.Current
			if cur.Severity.Rank() > old.Severity.Rank() && cur.Severity.AtLeast(threshold) {
				failures = append(failures, GateFailure{
					Change: ch,
					Reason: fmt.Sprintf("severity increased from %s to %s", old.Severity, cur.Severity),
				})
			}
		}
	}
	return failures
}
