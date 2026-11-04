package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sqlc-dev/sqlc/internal/vetaudit"
)

const auditTestConfig = `version: "2"
sql:
  - name: db
    engine: "sqlite"
    schema: "schema.sql"
    queries: "queries.sql"
    gen:
      go:
        package: "db"
        out: "db"
    rules:
      - no-delete
      - exec-warn
      - many-info
rules:
  - name: no-delete
    message: "don't use delete statements"
    rule: "query.sql.contains(\"DELETE\")"
  - name: exec-warn
    severity: warning
    message: "exec is discouraged"
    rule: "query.cmd == \"exec\""
  - name: many-info
    severity: info
    message: "many is noisy"
    rule: "query.cmd == \"many\""
`

const auditTestSchema = `CREATE TABLE books (id INTEGER PRIMARY KEY, title TEXT NOT NULL);
`

const auditTestQueriesV1 = `-- name: GetBook :one
SELECT * FROM books WHERE id = ?;

-- name: ListBooks :many
SELECT * FROM books;

-- name: DeleteBook :exec
DELETE FROM books WHERE id = ?;
`

const auditTestQueriesV2 = `-- name: GetBook :one
SELECT * FROM books WHERE id = ?;

-- name: ListBooks :many
SELECT * FROM books;

-- name: DeleteBook2 :exec
DELETE FROM books WHERE id = ?;
`

const auditTestQueriesReordered = `-- name: GetBook :one
SELECT * FROM books WHERE id = ?;

-- name: DeleteBook :exec
DELETE FROM books WHERE id = ?;

-- name: ListBooks :many
SELECT * FROM books;
`

func writeAuditProject(t *testing.T, dir, configYAML, queries string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "sqlc.yaml"), []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(auditTestSchema), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "queries.sql"), []byte(queries), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runAuditVet(t *testing.T, dir string, ao *AuditOptions) (error, string, string) {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	err := Vet(context.Background(), dir, "", &Options{
		Stdout: stdout,
		Stderr: stderr,
		Audit:  ao,
	})
	return err, stdout.String(), stderr.String()
}

func auditOpts(mode string, extra func(*AuditOptions)) *AuditOptions {
	ao := &AuditOptions{
		BaselinePath: filepath.Join("audit", "baseline.json"),
		ReportPath:   filepath.Join("audit", "report.txt"),
		JSONPath:     filepath.Join("audit", "report.json"),
	}
	if mode == "update" {
		ao.Update = true
	}
	if extra != nil {
		extra(ao)
	}
	return ao
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func loadReport(t *testing.T, dir string) vetaudit.Report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report vetaudit.Report
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func baselinePath(dir string) string {
	return filepath.Join(dir, "audit", "baseline.json")
}

func noLeftoverTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".sqlc-audit-") {
			t.Fatalf("leftover temporary artifact: %s", e.Name())
		}
	}
}

func TestVetAuditUpdateCreatesDeterministicBaseline(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)

	err, _, _ := runAuditVet(t, dir, auditOpts("update", nil))
	if err != nil {
		t.Fatalf("initial baseline update failed: %v", err)
	}

	first := fileDigest(t, baselinePath(dir))

	b, _, err := vetaudit.LoadBaseline(baselinePath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != vetaudit.BaselineVersion {
		t.Fatalf("baseline version = %d", b.Version)
	}
	if b.Config.Digest == "" || filepath.ToSlash(b.Config.Path) != "sqlc.yaml" {
		t.Fatalf("config identity not recorded: %+v", b.Config)
	}
	if len(b.Packages) != 1 || b.Packages[0].Name != "db" || b.Packages[0].Engine != "sqlite" {
		t.Fatalf("package fingerprint wrong: %+v", b.Packages)
	}
	rule, ok := b.Rules["no-delete"]
	if !ok || rule.Severity != vetaudit.SeverityError || rule.Rule == "" {
		t.Fatalf("rule identity wrong: %+v", b.Rules)
	}
	if b.Rules["exec-warn"].Severity != vetaudit.SeverityWarning {
		t.Fatalf("warning severity not recorded: %+v", b.Rules)
	}
	if len(b.Diagnostics) != 3 {
		t.Fatalf("want 3 baseline diagnostics, got %d: %+v", len(b.Diagnostics), b.Diagnostics)
	}

	// Re-running update must produce byte-identical content.
	err, _, _ = runAuditVet(t, dir, auditOpts("update", nil))
	if err != nil {
		t.Fatalf("second update failed: %v", err)
	}
	if second := fileDigest(t, baselinePath(dir)); second != first {
		t.Fatal("baseline is not deterministic across repeated updates")
	}
	noLeftoverTempFiles(t, dir)
}

func TestVetAuditCompareUnchangedPasses(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}

	err, stdout, _ := runAuditVet(t, dir, auditOpts("compare", nil))
	if err != nil {
		t.Fatalf("unchanged compare should pass: %v", err)
	}
	report := loadReport(t, dir)
	if report.Summary.Unchanged != 3 || report.Summary.New != 0 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	if !strings.Contains(stdout, "sqlc vet audit (compare)") {
		t.Fatalf("text report missing header:\n%s", stdout)
	}
}

func TestVetAuditNewErrorFailsGateAndKeepsBaseline(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}
	original := fileDigest(t, baselinePath(dir))

	if err := os.WriteFile(filepath.Join(dir, "queries.sql"),
		[]byte(auditTestQueriesV2), 0o644); err != nil {
		t.Fatal(err)
	}

	err, _, stderr := runAuditVet(t, dir, auditOpts("compare", nil))
	if !errors.Is(err, ErrFailedChecks) {
		t.Fatalf("new error diagnostic must fail the gate, got %v", err)
	}
	if !strings.Contains(stderr, "audit gate failed") {
		t.Fatalf("gate failure not reported:\n%s", stderr)
	}
	// Compare never touches the baseline, even when the gate fails.
	if got := fileDigest(t, baselinePath(dir)); got != original {
		t.Fatal("compare mode modified the baseline")
	}

	report := loadReport(t, dir)
	if report.Summary.New != 2 || report.Summary.Resolved != 2 || report.Summary.Unchanged != 1 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
	newError, newWarning := false, false
	for _, ch := range report.Changes {
		if ch.Type != vetaudit.ChangeNew {
			continue
		}
		switch ch.Current.Severity {
		case vetaudit.SeverityError:
			newError = true
		case vetaudit.SeverityWarning:
			newWarning = true
		}
	}
	if !newError || !newWarning {
		t.Fatalf("expected one new error and one new warning: %+v", report.Changes)
	}
}

func TestVetAuditWarningGate(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "queries.sql"),
		[]byte(auditTestQueriesV2), 0o644); err != nil {
		t.Fatal(err)
	}

	// The new warning passes the default error gate only for the warning
	// finding; the new error still fails. Re-baseline first, then add an
	// info-only change and test the info gate through a filter.
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}

	// After re-baselining, an unchanged comparison passes at error level.
	if err, _, _ := runAuditVet(t, dir, auditOpts("compare", nil)); err != nil {
		t.Fatalf("unchanged compare failed: %v", err)
	}

	// Filtering to the info rule and lowering the gate: no new findings,
	// so it still passes; assert the filter itself is honored in output.
	err, _, _ := runAuditVet(t, dir, auditOpts("compare", func(ao *AuditOptions) {
		ao.Rules = []string{"many-info"}
		ao.FailOn = "info"
	}))
	if err != nil {
		t.Fatalf("filtered unchanged compare failed: %v", err)
	}
	report := loadReport(t, dir)
	if len(report.Changes) != 1 || report.Changes[0].Rule != "many-info" {
		t.Fatalf("rule filter not honored: %+v", report.Changes)
	}
}

func TestVetAuditMoved(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "queries.sql"),
		[]byte(auditTestQueriesReordered), 0o644); err != nil {
		t.Fatal(err)
	}

	err, _, _ := runAuditVet(t, dir, auditOpts("compare", nil))
	if err != nil {
		t.Fatalf("moved findings must not fail the gate: %v", err)
	}
	report := loadReport(t, dir)
	if report.Summary.Moved == 0 || report.Summary.New != 0 || report.Summary.Resolved != 0 {
		t.Fatalf("expected only moves, got: %+v", report.Summary)
	}
}

func TestVetAuditSeverityChange(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}

	// De-escalate no-delete from error to warning.
	config := strings.Replace(auditTestConfig,
		"  - name: no-delete\n    message:",
		"  - name: no-delete\n    severity: warning\n    message:", 1)
	writeAuditProject(t, dir, config, auditTestQueriesV1)

	err, _, _ := runAuditVet(t, dir, auditOpts("compare", nil))
	if err != nil {
		t.Fatalf("severity de-escalation must pass the gate: %v", err)
	}
	report := loadReport(t, dir)
	var severityChanges int
	for _, ch := range report.Changes {
		if ch.Type == vetaudit.ChangeSeverity {
			severityChanges++
			if ch.Baseline.Severity != vetaudit.SeverityError ||
				ch.Current.Severity != vetaudit.SeverityWarning {
				t.Fatalf("severity pair wrong: %s -> %s", ch.Baseline.Severity, ch.Current.Severity)
			}
		}
	}
	if severityChanges != 1 {
		t.Fatalf("want 1 severity change, got %d (%+v)", severityChanges, report.Changes)
	}
}

func TestVetAuditInvalidFilterWritesNothing(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}
	original := fileDigest(t, baselinePath(dir))
	// Remove report artifacts so their absence proves nothing was written.
	for _, p := range []string{"report.txt", "report.json"} {
		if err := os.Remove(filepath.Join(dir, "audit", p)); err != nil {
			t.Fatal(err)
		}
	}

	err, _, _ := runAuditVet(t, dir, auditOpts("compare", func(ao *AuditOptions) {
		ao.Packages = []string{"ghost"}
	}))
	if err == nil || errors.Is(err, ErrFailedChecks) {
		t.Fatalf("invalid package filter must be a usage error, got %v", err)
	}
	if got := fileDigest(t, baselinePath(dir)); got != original {
		t.Fatal("invalid filter run modified the baseline")
	}
	for _, p := range []string{"report.txt", "report.json"} {
		if _, err := os.Stat(filepath.Join(dir, "audit", p)); !os.IsNotExist(err) {
			t.Fatalf("invalid filter run wrote %s", p)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVetAuditMissingBaseline(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	err, _, _ := runAuditVet(t, dir, auditOpts("compare", nil))
	if err == nil || errors.Is(err, ErrFailedChecks) {
		t.Fatalf("compare without a baseline must be a usage error, got %v", err)
	}
}

func TestVetAuditFilteredRunsAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	if err, _, _ := runAuditVet(t, dir, auditOpts("update", nil)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "queries.sql"),
		[]byte(auditTestQueriesV2), 0o644); err != nil {
		t.Fatal(err)
	}

	filter := func(ao *AuditOptions) {
		ao.Changes = []string{"new", "resolved"}
		ao.Rules = []string{"no-delete"}
	}
	if err, _, _ := runAuditVet(t, dir, auditOpts("compare", filter)); err == nil {
		t.Fatal("new error should fail gate")
	}
	first := mustRead(t, filepath.Join(dir, "audit", "report.json"))
	firstText := mustRead(t, filepath.Join(dir, "audit", "report.txt"))

	// Second run with the same filter combination is identical even
	// though the gate fails (and therefore exits non-zero).
	err, _, _ := runAuditVet(t, dir, auditOpts("compare", filter))
	if !errors.Is(err, ErrFailedChecks) {
		t.Fatalf("expected gate failure, got %v", err)
	}
	second := mustRead(t, filepath.Join(dir, "audit", "report.json"))
	secondText := mustRead(t, filepath.Join(dir, "audit", "report.txt"))
	if !bytes.Equal(first, second) || !bytes.Equal(firstText, secondText) {
		t.Fatal("repeated filtered runs produced different reports")
	}

	var report vetaudit.Report
	if err := json.Unmarshal(first, &report); err != nil {
		t.Fatal(err)
	}
	if report.Summary.New != 1 || report.Summary.Resolved != 1 {
		t.Fatalf("filtered summary wrong: %+v", report.Summary)
	}
}

func TestVetAuditDisabledBehaviorUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeAuditProject(t, dir, auditTestConfig, auditTestQueriesV1)
	stderr := &bytes.Buffer{}
	err := Vet(context.Background(), dir, "", &Options{
		Stderr: stderr,
	})
	if !errors.Is(err, ErrFailedChecks) {
		t.Fatalf("legacy vet must still fail on tripped rules, got %v", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "queries.sql: DeleteBook: no-delete") {
		t.Fatalf("legacy vet output changed:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit")); !os.IsNotExist(err) {
		t.Fatal("legacy vet created audit artifacts")
	}
}
