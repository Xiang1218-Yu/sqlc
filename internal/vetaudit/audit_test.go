package vetaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func diag(pkg, query, rule, file string, line int, msg string, sev Severity) Diagnostic {
	return Diagnostic{
		Package:  pkg,
		Query:    QueryRef{Filename: file, Name: query},
		Rule:     rule,
		Message:  msg,
		Severity: sev,
		Position: Position{Filename: file, Line: line},
	}
}

func TestClassifyAllChangeTypes(t *testing.T) {
	baseline := []Diagnostic{
		diag("db", "ResolvedQ", "rule-a", "q.sql", 3, "old resolved", SeverityError),
		diag("db", "SameQ", "rule-a", "q.sql", 5, "same", SeverityError),
		diag("db", "MovedQ", "rule-a", "q.sql", 8, "moved", SeverityError),
		diag("db", "MsgQ", "rule-a", "q.sql", 12, "old message", SeverityError),
		diag("db", "SevQ", "rule-a", "q.sql", 15, "sev", SeverityWarning),
	}
	current := []Diagnostic{
		diag("db", "SameQ", "rule-a", "q.sql", 5, "same", SeverityError),
		diag("db", "MovedQ", "rule-a", "q.sql", 20, "moved", SeverityError),
		diag("db", "MsgQ", "rule-a", "q.sql", 12, "new message", SeverityError),
		diag("db", "SevQ", "rule-a", "q.sql", 15, "sev", SeverityError),
		diag("db", "NewQ", "rule-a", "q.sql", 30, "brand new", SeverityError),
	}

	changes := Classify(baseline, current)
	byQuery := map[string]ChangeType{}
	for _, ch := range changes {
		byQuery[ch.Query.Name] = ch.Type
	}
	want := map[string]ChangeType{
		"ResolvedQ": ChangeResolved,
		"SameQ":     ChangeUnchanged,
		"MovedQ":    ChangeMoved,
		"MsgQ":      ChangeMessage,
		"SevQ":      ChangeSeverity,
		"NewQ":      ChangeNew,
	}
	for query, typ := range want {
		if got := byQuery[query]; got != typ {
			t.Errorf("query %s: got %s want %s", query, got, typ)
		}
	}

	summary := Summarize(changes)
	if summary != (Summary{New: 1, Resolved: 1, Unchanged: 1, Moved: 1, Message: 1, Severity: 1}) {
		t.Errorf("unexpected summary: %+v", summary)
	}
}

func TestClassifyPrecedence(t *testing.T) {
	base := diag("db", "Q", "r", "q.sql", 1, "a", SeverityError)
	cur := diag("db", "Q", "r", "other.sql", 9, "b", SeverityWarning)
	changes := Classify([]Diagnostic{base}, []Diagnostic{cur})
	if len(changes) != 1 || changes[0].Type != ChangeSeverity {
		t.Fatalf("severity must take precedence, got %+v", changes)
	}

	cur2 := diag("db", "Q", "r", "other.sql", 9, "b", SeverityError)
	changes = Classify([]Diagnostic{base}, []Diagnostic{cur2})
	if changes[0].Type != ChangeMessage {
		t.Fatalf("message must precede move, got %s", changes[0].Type)
	}

	cur3 := diag("db", "Q", "r", "other.sql", 9, "a", SeverityError)
	changes = Classify([]Diagnostic{base}, []Diagnostic{cur3})
	if changes[0].Type != ChangeMoved {
		t.Fatalf("position change must classify as moved, got %s", changes[0].Type)
	}
}

func TestClassifyIdentityIgnoresFile(t *testing.T) {
	// A query moving to a different file is a move, not new/resolved,
	// because identity is package + query + rule.
	base := diag("db", "Q", "r", "a.sql", 1, "m", SeverityError)
	cur := diag("db", "Q", "r", "b.sql", 1, "m", SeverityError)
	changes := Classify([]Diagnostic{base}, []Diagnostic{cur})
	if changes[0].Type != ChangeMoved {
		t.Fatalf("got %s want moved", changes[0].Type)
	}
}

func TestClassifyDeterministic(t *testing.T) {
	baseline := []Diagnostic{
		diag("db", "Q2", "r2", "q.sql", 4, "x", SeverityError),
		diag("aa", "Q1", "r1", "a.sql", 1, "y", SeverityWarning),
		diag("db", "Q1", "r1", "q.sql", 2, "z", SeverityError),
	}
	current := []Diagnostic{
		diag("db", "Q1", "r1", "q.sql", 2, "z", SeverityError),
		diag("aa", "Q1", "r1", "a.sql", 1, "y", SeverityWarning),
		diag("db", "Q3", "r2", "q.sql", 9, "x", SeverityError),
	}
	first, err := json.Marshal(Classify(baseline, current))
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(Classify(current, baseline))
	if err != nil {
		t.Fatal(err)
	}
	third, err := json.Marshal(Classify(
		[]Diagnostic{baseline[2], baseline[0], baseline[1]},
		[]Diagnostic{current[1], current[2], current[0]},
	))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(third) {
		t.Fatalf("classification is not order-independent:\n%s\nvs\n%s", first, third)
	}
	if string(first) == string(second) {
		t.Fatal("sanity check: swapping baseline/current must differ")
	}
}

func TestParseChangeTypes(t *testing.T) {
	got, err := ParseChangeTypes([]string{"severity", "new", "new", "moved"})
	if err != nil {
		t.Fatal(err)
	}
	want := []ChangeType{ChangeNew, ChangeMoved, ChangeSeverity}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v (canonical order)", got, want)
		}
	}
	if _, err := ParseChangeTypes([]string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown change type")
	}
}

func TestValidateFilter(t *testing.T) {
	pkgs := []string{"b", "a"}
	rules := []string{"r2", "r1"}
	if err := ValidateFilter(Filter{
		Packages: []string{"a"},
		Rules:    []string{"r1"},
		Changes:  []ChangeType{ChangeNew},
	}, pkgs, rules); err != nil {
		t.Fatalf("valid filter rejected: %v", err)
	}
	if err := ValidateFilter(Filter{Packages: []string{"x"}}, pkgs, rules); err == nil {
		t.Fatal("expected error for unknown package")
	}
	if err := ValidateFilter(Filter{Rules: []string{"x"}}, pkgs, rules); err == nil {
		t.Fatal("expected error for unknown rule")
	}
}

func TestApplyFilter(t *testing.T) {
	changes := Classify(
		[]Diagnostic{diag("a", "Q1", "r1", "f.sql", 1, "m", SeverityError)},
		[]Diagnostic{
			diag("a", "Q1", "r1", "f.sql", 1, "m", SeverityError),
			diag("b", "Q2", "r2", "g.sql", 2, "m2", SeverityError),
		},
	)
	if len(ApplyFilter(changes, Filter{Packages: []string{"b"}})) != 1 {
		t.Fatal("package filter did not select exactly one change")
	}
	if len(ApplyFilter(changes, Filter{Rules: []string{"r1"}})) != 1 {
		t.Fatal("rule filter did not select exactly one change")
	}
	if got := ApplyFilter(changes, Filter{Changes: []ChangeType{ChangeNew}}); len(got) != 1 || got[0].Type != ChangeNew {
		t.Fatalf("change filter did not select the new change: %+v", got)
	}
}

func TestEvaluateGate(t *testing.T) {
	newError := Classify(nil, []Diagnostic{diag("db", "Q", "r", "f.sql", 1, "m", SeverityError)})
	newWarning := Classify(nil, []Diagnostic{diag("db", "Q", "r", "f.sql", 1, "m", SeverityWarning)})
	escalated := Classify(
		[]Diagnostic{diag("db", "Q", "r", "f.sql", 1, "m", SeverityWarning)},
		[]Diagnostic{diag("db", "Q", "r", "f.sql", 1, "m", SeverityError)},
	)
	deEscalated := Classify(
		[]Diagnostic{diag("db", "Q", "r", "f.sql", 1, "m", SeverityError)},
		[]Diagnostic{diag("db", "Q", "r", "f.sql", 1, "m", SeverityWarning)},
	)
	moved := Classify(
		[]Diagnostic{diag("db", "Q", "r", "f.sql", 1, "m", SeverityError)},
		[]Diagnostic{diag("db", "Q", "r", "f.sql", 2, "m", SeverityError)},
	)

	if len(EvaluateGate(newError, SeverityError)) != 1 {
		t.Fatal("new error must fail the default gate")
	}
	if len(EvaluateGate(newWarning, SeverityError)) != 0 {
		t.Fatal("new warning must pass the error gate")
	}
	if len(EvaluateGate(newWarning, SeverityWarning)) != 1 {
		t.Fatal("new warning must fail the warning gate")
	}
	if len(EvaluateGate(newWarning, SeverityInfo)) != 1 {
		t.Fatal("new warning must fail the info gate")
	}
	if len(EvaluateGate(escalated, SeverityError)) != 1 {
		t.Fatal("severity escalation to error must fail")
	}
	if len(EvaluateGate(deEscalated, SeverityError)) != 0 {
		t.Fatal("severity de-escalation must not fail")
	}
	if len(EvaluateGate(moved, SeverityError)) != 0 {
		t.Fatal("moved diagnostics with unchanged severity must not fail")
	}
}

func TestBaselineRoundTripAndDeterminism(t *testing.T) {
	b := &Baseline{
		Version: BaselineVersion,
		Config: ConfigFingerprint{
			Path:   "sqlc.yaml",
			Digest: "sha256:abc",
		},
		Packages: []PackageFingerprint{{
			Name:    "db",
			Engine:  "sqlite",
			Schema:  []FileFingerprint{{Path: "schema.sql", Digest: "sha256:s"}},
			Queries: []FileFingerprint{{Path: "query.sql", Digest: "sha256:q"}},
			Rules:   []string{"r1"},
		}},
		Rules: map[string]RuleIdentity{
			"r1": {Rule: "true", Message: "m", Severity: SeverityError},
		},
		Diagnostics: []Diagnostic{diag("db", "Q", "r1", "q.sql", 2, "m", SeverityError)},
	}
	first, err := MarshalBaseline(b)
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalBaseline(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("baseline marshalling is not deterministic")
	}
	restored, err := UnmarshalBaseline(first)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Config.Digest != "sha256:abc" || restored.Rules["r1"].Severity != SeverityError {
		t.Fatalf("round trip lost data: %+v", restored)
	}

	var raw map[string]any
	if err := json.Unmarshal(first, &raw); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"generated_at", "timestamp", "time"} {
		if _, ok := raw[banned]; ok {
			t.Fatalf("baseline contains volatile field %q", banned)
		}
	}

	bad := *b
	bad.Version = 99
	if _, err := MarshalBaseline(&bad); err == nil {
		t.Fatal("expected error for unsupported baseline version")
	}
}

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := AtomicWriteFile(path, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "payload" {
		t.Fatalf("content mismatch: %q %v", got, err)
	}
	if leftovers := globHidden(dir); len(leftovers) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", leftovers)
	}
}

func TestAtomicWriteFilesRollsBackOnStageFailure(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	readonly := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readonly, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(readonly, 0o755)
	bad := filepath.Join(readonly, "bad.json")

	if err := AtomicWriteFiles(map[string][]byte{good: []byte("x"), bad: []byte("y")}); err == nil {
		t.Fatal("expected write failure")
	}
	if _, err := os.Stat(good); !os.IsNotExist(err) {
		t.Fatal("valid target must not be committed when staging another file fails")
	}
	if leftovers := globHidden(dir); len(leftovers) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", leftovers)
	}
}

func globHidden(dir string) []string {
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		if len(e.Name()) > 0 && e.Name()[0] == '.' && e.Name() != "." && e.Name() != ".." {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestRenderTextStable(t *testing.T) {
	changes := Classify(
		[]Diagnostic{
			diag("db", "Gone", "r", "q.sql", 1, "resolved", SeverityError),
			diag("db", "Same", "r", "q.sql", 4, "same", SeverityError),
		},
		[]Diagnostic{
			diag("db", "Same", "r", "q.sql", 4, "same", SeverityError),
			diag("db", "Fresh", "r", "q.sql", 7, "new", SeverityError),
		},
	)
	report := &Report{
		Version:      BaselineVersion,
		Mode:         ModeCompare,
		BaselinePath: "baseline.json",
		FailOn:       SeverityError,
		Filters: FilterView{
			Packages: []string{},
			Rules:    []string{},
			Changes:  []ChangeType{},
		},
		Summary: Summarize(changes),
		Changes: changes,
	}
	first := RenderText(report)
	second := RenderText(report)
	if first != second {
		t.Fatal("text rendering is not deterministic")
	}
	for _, want := range []string{
		"sqlc vet audit (compare)",
		"New (1):",
		"Resolved (1):",
		"Unchanged (1):",
		"Summary: new=1 resolved=1 unchanged=1 moved=0 message=0 severity=0",
	} {
		if !contains(first, want) {
			t.Errorf("text report missing %q:\n%s", want, first)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
