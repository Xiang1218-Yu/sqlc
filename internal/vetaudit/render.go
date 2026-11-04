package vetaudit

import (
	"fmt"
	"strings"
)

// RenderText renders the deterministic, human-readable audit report. The
// layout never depends on map iteration, timestamps or host data, so the
// same report always renders to identical bytes.
func RenderText(r *Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "sqlc vet audit (%s)\n", r.Mode)
	fmt.Fprintf(&b, "baseline: %s\n", r.BaselinePath)
	if r.BaselineDigest != "" {
		fmt.Fprintf(&b, "baseline digest: %s\n", r.BaselineDigest)
	}
	fmt.Fprintf(&b, "packages: %s\n", joinOrAll(r.Filters.Packages))
	fmt.Fprintf(&b, "rules: %s\n", joinOrAll(r.Filters.Rules))
	fmt.Fprintf(&b, "changes: %s\n", joinChangesOrAll(r.Filters.Changes))
	fmt.Fprintf(&b, "fail-on: %s\n", r.FailOn)
	b.WriteString("\n")

	grouped := groupChanges(r.Changes)
	sectionTitles := map[ChangeType]string{
		ChangeNew:       "New",
		ChangeResolved:  "Resolved",
		ChangeUnchanged: "Unchanged",
		ChangeMoved:     "Moved",
		ChangeMessage:   "Message changed",
		ChangeSeverity:  "Severity changed",
	}
	for _, t := range ChangeTypes() {
		fmt.Fprintf(&b, "%s (%d):\n", sectionTitles[t], len(grouped[t]))
		for _, ch := range grouped[t] {
			renderChange(&b, ch)
		}
	}

	s := r.Summary
	fmt.Fprintf(&b, "\nSummary: new=%d resolved=%d unchanged=%d moved=%d message=%d severity=%d\n",
		s.New, s.Resolved, s.Unchanged, s.Moved, s.Message, s.Severity)
	return b.String()
}

func groupChanges(changes []Change) map[ChangeType][]Change {
	out := map[ChangeType][]Change{}
	for _, t := range ChangeTypes() {
		out[t] = []Change{}
	}
	for _, ch := range changes {
		out[ch.Type] = append(out[ch.Type], ch)
	}
	return out
}

func renderChange(b *strings.Builder, ch Change) {
	switch ch.Type {
	case ChangeNew:
		fmt.Fprintf(b, "  %s\n", FormatDiagnostic(*ch.Current))
	case ChangeResolved:
		fmt.Fprintf(b, "  %s\n", FormatDiagnostic(*ch.Baseline))
	case ChangeMoved:
		fmt.Fprintf(b, "  %s %s %s: %s\n", ch.Package, ch.Query.Filename, ch.Query.Name, ch.Rule)
		fmt.Fprintf(b, "    baseline: %s\n", FormatPosition(ch.Baseline.Position))
		fmt.Fprintf(b, "    current:  %s\n", FormatPosition(ch.Current.Position))
	case ChangeMessage:
		fmt.Fprintf(b, "  %s %s %s: %s\n", ch.Package, ch.Query.Filename, ch.Query.Name, ch.Rule)
		fmt.Fprintf(b, "    baseline: %s\n", ch.Baseline.Message)
		fmt.Fprintf(b, "    current:  %s\n", ch.Current.Message)
	case ChangeSeverity:
		fmt.Fprintf(b, "  %s %s %s: %s\n", ch.Package, ch.Query.Filename, ch.Query.Name, ch.Rule)
		fmt.Fprintf(b, "    baseline: %s\n", ch.Baseline.Severity)
		fmt.Fprintf(b, "    current:  %s\n", ch.Current.Severity)
	case ChangeUnchanged:
		fmt.Fprintf(b, "  %s\n", FormatDiagnostic(*ch.Current))
	}
}

// FormatDiagnostic renders one diagnostic as
// "package position query: rule: message", omitting the message suffix and
// the line colon when they are empty.
func FormatDiagnostic(d Diagnostic) string {
	pos := FormatPosition(d.Position)
	head := fmt.Sprintf("%s %s %s: %s", d.Package, pos, d.Query.Name, d.Rule)
	if d.Message != "" {
		head += ": " + d.Message
	}
	return head
}

// FormatPosition renders "filename:line", or just the filename when the
// line is unknown.
func FormatPosition(p Position) string {
	if p.Line > 0 {
		return fmt.Sprintf("%s:%d", p.Filename, p.Line)
	}
	return p.Filename
}

func joinOrAll(values []string) string {
	if len(values) == 0 {
		return "all"
	}
	return strings.Join(values, ", ")
}

func joinChangesOrAll(types []ChangeType) string {
	if len(types) == 0 {
		return "all"
	}
	values := make([]string, len(types))
	for i, t := range types {
		values[i] = string(t)
	}
	return strings.Join(values, ", ")
}
