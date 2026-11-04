package vetaudit

import (
	"cmp"
	"slices"
)

// identityKey is the stable identity of a diagnostic: package, query name
// and rule. Position, message and severity are deliberately excluded so
// that movement, message edits and severity edits are recognized as the
// same diagnostic changing rather than as one diagnostic disappearing and
// another appearing.
func identityKey(d Diagnostic) string {
	return d.Package + "\x00" + d.Query.Name + "\x00" + d.Rule
}

// SortDiagnostics deterministically orders diagnostics by package,
// position, query name and rule.
func SortDiagnostics(diags []Diagnostic) {
	slices.SortFunc(diags, func(a, b Diagnostic) int {
		if c := cmp.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		if c := comparePosition(a.Position, b.Position); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Query.Name, b.Query.Name); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Rule, b.Rule); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Message, b.Message); c != 0 {
			return c
		}
		return cmp.Compare(a.Severity.Rank(), b.Severity.Rank())
	})
}

func comparePosition(a, b Position) int {
	if c := cmp.Compare(a.Filename, b.Filename); c != 0 {
		return c
	}
	return cmp.Compare(a.Line, b.Line)
}

// changeTypeOrder pins the section ordering used by every report.
var changeTypeOrder = func() map[ChangeType]int {
	order := map[ChangeType]int{}
	for i, t := range ChangeTypes() {
		order[t] = i
	}
	return order
}()

// SortChanges deterministically orders changes by the canonical change
// type order and then by package, position, query and rule. Resolved
// diagnostics sort using their baseline position; every other type uses
// its current position.
func SortChanges(changes []Change) {
	slices.SortFunc(changes, func(a, b Change) int {
		if c := cmp.Compare(changeTypeOrder[a.Type], changeTypeOrder[b.Type]); c != 0 {
			return c
		}
		pa, pb := changePosition(a), changePosition(b)
		if c := cmp.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		if c := comparePosition(pa, pb); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Query.Name, b.Query.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Rule, b.Rule)
	})
}

func changePosition(c Change) Position {
	if c.Current != nil {
		return c.Current.Position
	}
	if c.Baseline != nil {
		return c.Baseline.Position
	}
	return Position{}
}

// Classify compares a baseline diagnostic set with the current results
// and returns one Change per diagnostic identity.
//
// When an identity exists on both sides, precedence is deterministic: a
// severity difference is reported as a severity change, otherwise a
// message difference is a message change, otherwise a position difference
// is a move, and otherwise the diagnostic is unchanged.
func Classify(baseline, current []Diagnostic) []Change {
	SortDiagnostics(baseline)
	SortDiagnostics(current)

	baseByID := make(map[string]Diagnostic, len(baseline))
	for _, d := range baseline {
		// Baselines are produced sorted; the last entry wins on duplicate
		// identity, which is itself deterministic.
		baseByID[identityKey(d)] = d
	}
	currByID := make(map[string]Diagnostic, len(current))
	for _, d := range current {
		currByID[identityKey(d)] = d
	}

	ids := make(map[string]struct{}, len(baseByID)+len(currByID))
	for id := range baseByID {
		ids[id] = struct{}{}
	}
	for id := range currByID {
		ids[id] = struct{}{}
	}

	changes := make([]Change, 0, len(ids))
	for id := range ids {
		b, inBase := baseByID[id]
		c, inCurrent := currByID[id]
		switch {
		case inBase && !inCurrent:
			changes = append(changes, Change{
				Type: ChangeResolved, Package: b.Package, Query: b.Query,
				Rule: b.Rule, Baseline: &b,
			})
		case !inBase && inCurrent:
			changes = append(changes, Change{
				Type: ChangeNew, Package: c.Package, Query: c.Query,
				Rule: c.Rule, Current: &c,
			})
		default:
			changes = append(changes, pairChange(b, c))
		}
	}
	SortChanges(changes)
	return changes
}

func pairChange(b, c Diagnostic) Change {
	ch := Change{
		Package: c.Package, Query: c.Query, Rule: c.Rule,
		Baseline: &b, Current: &c,
	}
	switch {
	case b.Severity != c.Severity:
		ch.Type = ChangeSeverity
	case b.Message != c.Message:
		ch.Type = ChangeMessage
	case comparePosition(b.Position, c.Position) != 0:
		ch.Type = ChangeMoved
	default:
		ch.Type = ChangeUnchanged
	}
	return ch
}

// Summarize counts changes of each type in canonical order.
func Summarize(changes []Change) Summary {
	var s Summary
	for _, ch := range changes {
		switch ch.Type {
		case ChangeNew:
			s.New++
		case ChangeResolved:
			s.Resolved++
		case ChangeUnchanged:
			s.Unchanged++
		case ChangeMoved:
			s.Moved++
		case ChangeMessage:
			s.Message++
		case ChangeSeverity:
			s.Severity++
		}
	}
	return s
}
