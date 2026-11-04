package vetaudit

// BaselineVersion is the on-disk format version of baseline and report
// files. It is bumped when the serialized shape changes incompatibly.
const BaselineVersion = 1

// Position identifies where a diagnostic was observed. It is part of the
// diagnostic payload, not its identity: a diagnostic that keeps the same
// package, query and rule but moves position is classified as moved.
type Position struct {
	Filename string `json:"filename"`
	Line     int    `json:"line,omitempty"`
}

// QueryRef references a query within a package. Query names are unique
// within a package, so the name is the stable identity; the filename is
// retained for human-readable reports.
type QueryRef struct {
	Filename string `json:"filename"`
	Name     string `json:"name"`
}

// Diagnostic is a single tripped rule for a package and query.
type Diagnostic struct {
	Package  string   `json:"package"`
	Query    QueryRef `json:"query"`
	Rule     string   `json:"rule"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
	Position Position `json:"position"`
}

// RuleIdentity records the definition of a rule captured in a baseline so
// that audits can prove which rule configuration produced the stored
// diagnostics.
type RuleIdentity struct {
	// Rule is the CEL expression of custom rules. It is empty for the
	// built-in sqlc/db-prepare rule.
	Rule     string   `json:"rule"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

// FileFingerprint records a vetted input file and a digest of its
// contents.
type FileFingerprint struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// PackageFingerprint records the configuration identity of a package at
// the time the baseline was produced.
type PackageFingerprint struct {
	Name    string            `json:"name"`
	Engine  string            `json:"engine"`
	Schema  []FileFingerprint `json:"schema"`
	Queries []FileFingerprint `json:"queries"`
	Rules   []string          `json:"rules"`
}

// ConfigFingerprint records the sqlc configuration and tool identity for
// a baseline.
type ConfigFingerprint struct {
	Path        string `json:"path"`
	Digest      string `json:"digest"`
	SqlcVersion string `json:"sqlc_version,omitempty"`
}

// Baseline is the deterministic, auditable snapshot persisted to disk.
type Baseline struct {
	Version     int                     `json:"version"`
	Config      ConfigFingerprint       `json:"config"`
	Packages    []PackageFingerprint    `json:"packages"`
	Rules       map[string]RuleIdentity `json:"rules"`
	Diagnostics []Diagnostic            `json:"diagnostics"`
}

// ChangeType classifies a single baseline/current diagnostic pair.
type ChangeType string

const (
	// ChangeNew is a diagnostic present in the current results but absent
	// from the baseline.
	ChangeNew ChangeType = "new"
	// ChangeResolved is a baseline diagnostic that no longer trips.
	ChangeResolved ChangeType = "resolved"
	// ChangeUnchanged is a diagnostic identical in position, message and
	// severity.
	ChangeUnchanged ChangeType = "unchanged"
	// ChangeMoved is a diagnostic whose position changed while message and
	// severity stayed the same.
	ChangeMoved ChangeType = "moved"
	// ChangeMessage is a diagnostic whose message changed while position
	// and severity stayed the same.
	ChangeMessage ChangeType = "message"
	// ChangeSeverity is a diagnostic whose severity changed while position
	// and message stayed the same.
	ChangeSeverity ChangeType = "severity"
)

// ChangeTypes returns every change type in canonical order.
func ChangeTypes() []ChangeType {
	return []ChangeType{
		ChangeNew,
		ChangeResolved,
		ChangeUnchanged,
		ChangeMoved,
		ChangeMessage,
		ChangeSeverity,
	}
}

// Change pairs the baseline and current representation of a single
// diagnostic identity. Exactly one side may be nil for new and resolved
// changes; both are set for every other type.
type Change struct {
	Type     ChangeType  `json:"type"`
	Package  string      `json:"package"`
	Query    QueryRef    `json:"query"`
	Rule     string      `json:"rule"`
	Baseline *Diagnostic `json:"baseline,omitempty"`
	Current  *Diagnostic `json:"current,omitempty"`
}

// Summary holds the number of changes of each type.
type Summary struct {
	New       int `json:"new"`
	Resolved  int `json:"resolved"`
	Unchanged int `json:"unchanged"`
	Moved     int `json:"moved"`
	Message   int `json:"message"`
	Severity  int `json:"severity"`
}

// Filter restricts the changes included in a report and considered by the
// failure gate. Empty package/rule slices mean "all".
type Filter struct {
	Packages []string
	Rules    []string
	Changes  []ChangeType
}

// Mode selects whether an audit run compares against the baseline or
// replaces it.
type Mode string

const (
	// ModeCompare never modifies the baseline.
	ModeCompare Mode = "compare"
	// ModeUpdate replaces the baseline with the current results.
	ModeUpdate Mode = "update"
)

// Report is the JSON-serializable result of an audit run.
type Report struct {
	Version        int        `json:"version"`
	Mode           Mode       `json:"mode"`
	BaselinePath   string     `json:"baseline_path"`
	BaselineDigest string     `json:"baseline_digest,omitempty"`
	FailOn         Severity   `json:"fail_on"`
	Filters        FilterView `json:"filters"`
	Summary        Summary    `json:"summary"`
	Changes        []Change   `json:"changes"`
}

// FilterView is the JSON representation of the effective filter. Empty
// slices are emitted as null-free empty lists.
type FilterView struct {
	Packages []string     `json:"packages"`
	Rules    []string     `json:"rules"`
	Changes  []ChangeType `json:"changes"`
}
