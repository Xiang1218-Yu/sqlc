package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/sqlc-dev/sqlc/internal/config"
	"github.com/sqlc-dev/sqlc/internal/info"
	"github.com/sqlc-dev/sqlc/internal/plugin"
	"github.com/sqlc-dev/sqlc/internal/sql/sqlpath"
	"github.com/sqlc-dev/sqlc/internal/vetaudit"
)

// queryLocator resolves deterministic, best-effort 1-based line positions
// for queries from the "name: <Query>" metadata comment. It reads query
// files once per package and never reports an error: positions are
// informational, so an unreadable file simply yields line 0.
type queryLocator struct {
	files map[string][]byte
}

func newQueryLocator(patterns []string) *queryLocator {
	loc := &queryLocator{files: map[string][]byte{}}
	files, err := sqlpath.Glob(patterns)
	if err != nil {
		return loc
	}
	sort.Strings(files)
	for _, f := range files {
		base := filepath.Base(f)
		if _, exists := loc.files[base]; exists {
			continue
		}
		if contents, err := os.ReadFile(f); err == nil {
			loc.files[base] = contents
		}
	}
	return loc
}

// line returns the 1-based line number of the query metadata comment for
// queryName within the named file, or 0 when it cannot be determined.
func (l *queryLocator) line(file, queryName string) int {
	if l == nil || queryName == "" {
		return 0
	}
	src, ok := l.files[file]
	if !ok {
		return 0
	}
	token := []byte("name: " + queryName)
	idx := bytes.Index(src, token)
	if idx < 0 {
		return 0
	}
	return bytes.Count(src[:idx], []byte{'\n'}) + 1
}

func (c *checker) recordFinding(r rule, name string, query *plugin.Query, locator *queryLocator, message string) {
	if c.Audit == nil {
		return
	}
	c.Audit.finding(vetaudit.Diagnostic{
		Package:  c.Pkg,
		Query:    vetaudit.QueryRef{Filename: query.Filename, Name: query.Name},
		Rule:     name,
		Message:  message,
		Severity: r.Severity,
		Position: vetaudit.Position{
			Filename: query.Filename,
			Line:     locator.line(query.Filename, query.Name),
		},
	})
}

// auditPlan is the validated, normalized configuration for one audit run.
type auditPlan struct {
	mode vetaudit.Mode
	dir  string

	baselinePath string
	reportPath   string
	jsonPath     string

	failOn vetaudit.Severity

	// provided is echoed into reports verbatim (empty sets mean "all").
	provided vetaudit.Filter
	// effective carries the resolved package and rule scope.
	effective vetaudit.Filter

	packageSet map[string]struct{}
}

func auditRuleScope(p *auditPlan) map[string]struct{} {
	if p == nil || len(p.provided.Rules) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(p.provided.Rules))
	for _, r := range p.provided.Rules {
		set[r] = struct{}{}
	}
	return set
}

func (p *auditPlan) includesPackage(name string) bool {
	_, ok := p.packageSet[name]
	return ok
}

// prepareAudit validates and normalizes audit options before any package
// is checked, so invalid filters, severities or a missing comparison
// baseline fail fast without side effects.
func prepareAudit(o *AuditOptions, dir string, packages, rules []string) (*auditPlan, error) {
	if o == nil || o.BaselinePath == "" {
		return nil, fmt.Errorf("the audit flow requires a baseline path")
	}

	mode := vetaudit.ModeCompare
	if o.Update {
		mode = vetaudit.ModeUpdate
	}

	failOn, err := vetaudit.NormalizeSeverity(o.FailOn)
	if err != nil {
		return nil, fmt.Errorf("invalid --audit-fail-on value: %w", err)
	}

	changes, err := vetaudit.ParseChangeTypes(o.Changes)
	if err != nil {
		return nil, err
	}

	provided := vetaudit.Filter{
		Packages: vetaudit.NormalizeStringSet(o.Packages),
		Rules:    vetaudit.NormalizeStringSet(o.Rules),
		Changes:  changes,
	}
	if err := vetaudit.ValidateFilter(provided, packages, rules); err != nil {
		return nil, err
	}
	effective := vetaudit.EffectiveFilter(provided, packages, rules)

	p := &auditPlan{
		mode:         mode,
		dir:          dir,
		baselinePath: resolveAuditPath(dir, o.BaselinePath),
		reportPath:   resolveAuditPath(dir, o.ReportPath),
		jsonPath:     resolveAuditPath(dir, o.JSONPath),
		failOn:       failOn,
		provided:     provided,
		effective:    effective,
		packageSet:   sliceToSet(effective.Packages),
	}

	if mode == vetaudit.ModeCompare {
		switch _, err := os.Stat(p.baselinePath); {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("audit baseline %s does not exist; run with --audit-update to create it",
				auditDisplayPath(dir, p.baselinePath))
		default:
			return nil, fmt.Errorf("stat audit baseline: %w", err)
		}
	}

	return p, nil
}

func resolveAuditPath(dir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

func sliceToSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

// runAudit compares the collected diagnostics with the baseline (or
// builds a replacement baseline in update mode), renders reports and
// publishes every artifact with atomic writes. It never mutates the
// baseline in compare mode.
func runAudit(
	p *auditPlan,
	configPath string,
	conf *config.Config,
	ruleDefs map[string]config.Rule,
	packageNames []string,
	collector *auditCollector,
	stdout, stderr io.Writer,
) error {
	current := slices.Clone(collector.findings)
	vetaudit.SortDiagnostics(current)

	var existing *vetaudit.Baseline
	var existingBytes []byte
	switch b, data, err := vetaudit.LoadBaseline(p.baselinePath); {
	case err == nil:
		existing, existingBytes = b, data
	case errors.Is(err, fs.ErrNotExist):
		// Allowed only in update mode; compare mode requires the file and
		// prepareAudit already verified it exists.
		if p.mode != vetaudit.ModeUpdate {
			return fmt.Errorf("audit baseline %s does not exist; run with --audit-update to create it",
				auditDisplayPath(p.dir, p.baselinePath))
		}
	default:
		return fmt.Errorf("load audit baseline: %w", err)
	}

	var oldDiagnostics []vetaudit.Diagnostic
	if existing != nil {
		oldDiagnostics = existing.Diagnostics
	}
	changes := vetaudit.Classify(oldDiagnostics, current)
	filtered := vetaudit.ApplyFilter(changes, p.effective)

	report := &vetaudit.Report{
		Version:      vetaudit.BaselineVersion,
		Mode:         p.mode,
		BaselinePath: auditDisplayPath(p.dir, p.baselinePath),
		FailOn:       p.failOn,
		Filters: vetaudit.FilterView{
			Packages: nonEmptyStrings(p.provided.Packages),
			Rules:    nonEmptyStrings(p.provided.Rules),
			Changes:  nonEmptyChanges(p.provided.Changes),
		},
		Summary: vetaudit.Summarize(filtered),
		Changes: filtered,
	}

	writes := map[string][]byte{}
	if p.mode == vetaudit.ModeUpdate {
		baseline, err := buildBaseline(p, configPath, conf, ruleDefs, packageNames, current)
		if err != nil {
			return err
		}
		baselineBytes, err := vetaudit.MarshalBaseline(baseline)
		if err != nil {
			return err
		}
		writes[p.baselinePath] = baselineBytes
		report.BaselineDigest = vetaudit.Digest(baselineBytes)
	} else {
		report.BaselineDigest = vetaudit.Digest(existingBytes)
	}

	textReport := vetaudit.RenderText(report)
	if p.reportPath != "" {
		writes[p.reportPath] = []byte(textReport)
	}
	if p.jsonPath != "" {
		jsonReport, err := vetaudit.MarshalReport(report)
		if err != nil {
			return err
		}
		writes[p.jsonPath] = jsonReport
	}

	// The gate is evaluated over the filtered changes so every filter
	// combination has a self-consistent report and exit status.
	var gateFailures []vetaudit.GateFailure
	if p.mode == vetaudit.ModeCompare {
		gateFailures = vetaudit.EvaluateGate(filtered, p.failOn)
	}

	// All content is finalized before any file is touched; publishing is
	// atomic per file and stages everything first, so no partial state is
	// ever committed.
	if err := vetaudit.AtomicWriteFiles(writes); err != nil {
		return fmt.Errorf("audit: write artifacts: %w", err)
	}

	out := stdout
	if out == nil {
		out = os.Stdout
	}
	fmt.Fprint(out, textReport)

	if len(gateFailures) > 0 {
		fmt.Fprintf(stderr, "audit gate failed: %d change(s) at or above severity %s\n",
			len(gateFailures), p.failOn)
		for _, failure := range gateFailures {
			if failure.Change.Current != nil {
				fmt.Fprintf(stderr, "  %s (%s)\n",
					vetaudit.FormatDiagnostic(*failure.Change.Current), failure.Reason)
			}
		}
		return ErrFailedChecks
	}
	return nil
}

func nonEmptyStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonEmptyChanges(values []vetaudit.ChangeType) []vetaudit.ChangeType {
	if values == nil {
		return []vetaudit.ChangeType{}
	}
	return values
}

// buildBaseline constructs the deterministic baseline for the audited
// package and rule scope, recording configuration and rule identity
// alongside the diagnostics.
func buildBaseline(
	p *auditPlan,
	configPath string,
	conf *config.Config,
	ruleDefs map[string]config.Rule,
	packageNames []string,
	diagnostics []vetaudit.Diagnostic,
) (*vetaudit.Baseline, error) {
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}

	baseline := &vetaudit.Baseline{
		Version: vetaudit.BaselineVersion,
		Config: vetaudit.ConfigFingerprint{
			Path:        filepath.Base(configPath),
			Digest:      vetaudit.Digest(configBytes),
			SqlcVersion: info.Version,
		},
		Rules:       map[string]vetaudit.RuleIdentity{},
		Diagnostics: diagnostics,
	}

	var scopedRules []string
	for i, sql := range conf.SQL {
		name := packageNames[i]
		if !p.includesPackage(name) {
			continue
		}
		schemaFiles, err := fingerprintInputPaths(p.dir, sql.Schema)
		if err != nil {
			return nil, err
		}
		queryFiles, err := fingerprintInputPaths(p.dir, sql.Queries)
		if err != nil {
			return nil, err
		}
		appliedRules := make([]string, 0, len(sql.Rules))
		for _, r := range sql.Rules {
			if slices.Contains(p.effective.Rules, r) {
				appliedRules = append(appliedRules, r)
			}
		}
		sort.Strings(appliedRules)
		baseline.Packages = append(baseline.Packages, vetaudit.PackageFingerprint{
			Name:    name,
			Engine:  string(sql.Engine),
			Schema:  schemaFiles,
			Queries: queryFiles,
			Rules:   appliedRules,
		})
		scopedRules = append(scopedRules, appliedRules...)
	}
	// Explicitly selected rules are part of the audited rule set even
	// when no selected package applies them.
	if len(p.provided.Rules) > 0 {
		scopedRules = append(scopedRules, p.provided.Rules...)
	}
	sort.Strings(scopedRules)
	scopedRules = slices.Compact(scopedRules)

	// Record the identity of every rule in the audited set, whether or
	// not it produced a diagnostic.
	for _, name := range scopedRules {
		def, ok := ruleDefs[name]
		if !ok {
			continue
		}
		severity, err := vetaudit.NormalizeSeverity(def.Severity)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", name, err)
		}
		baseline.Rules[name] = vetaudit.RuleIdentity{
			Rule:     def.Rule,
			Message:  def.Msg,
			Severity: severity,
		}
	}

	return baseline, nil
}

func fingerprintInputPaths(dir string, paths config.Paths) ([]vetaudit.FileFingerprint, error) {
	joined := make([]string, 0, len(paths))
	for _, p := range paths {
		joined = append(joined, filepath.Join(dir, p))
	}
	files, err := sqlpath.Glob(joined)
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	files = slices.Compact(files)
	out := make([]vetaudit.FileFingerprint, 0, len(files))
	for _, f := range files {
		digest, err := vetaudit.DigestFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, vetaudit.FileFingerprint{
			Path:   auditDisplayPath(dir, f),
			Digest: digest,
		})
	}
	return out, nil
}

// auditDisplayPath renders a path relative to the config directory using
// slash separators, keeping baselines and reports machine-independent and
// deterministic.
func auditDisplayPath(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(path)
}
