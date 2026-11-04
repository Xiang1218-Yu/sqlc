// Package vetaudit implements the explicitly enabled, auditable quality
// gate for sqlc vet. It produces deterministic diagnostic baselines,
// classifies differences between a baseline and the current vet results,
// renders text and JSON reports, and persists baselines and reports with
// atomic writes.
package vetaudit

import "fmt"

// Severity is the severity level assigned to a rule and its diagnostics.
type Severity string

const (
	// SeverityInfo is the lowest severity level.
	SeverityInfo Severity = "info"
	// SeverityWarning indicates a problem that should be reviewed.
	SeverityWarning Severity = "warning"
	// SeverityError indicates a problem that fails a default audit gate.
	SeverityError Severity = "error"
)

// DefaultSeverity is assigned to rules that do not declare a severity.
const DefaultSeverity = SeverityError

// NormalizeSeverity returns the canonical severity for a configuration
// value. An empty value resolves to DefaultSeverity. Unknown values are
// rejected so that invalid configuration never reaches a baseline.
func NormalizeSeverity(value string) (Severity, error) {
	switch Severity(value) {
	case "":
		return DefaultSeverity, nil
	case SeverityInfo, SeverityWarning, SeverityError:
		return Severity(value), nil
	default:
		return "", fmt.Errorf("invalid severity %q: must be one of %q, %q, %q",
			value, SeverityInfo, SeverityWarning, SeverityError)
	}
}

// Rank orders severities for threshold comparisons.
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityWarning:
		return 1
	case SeverityError:
		return 2
	default:
		// Unknown severities can only appear in hand-edited, untrusted
		// baselines; treat them as the most severe level rather than
		// silently dropping them below the gate.
		return len(severityOrder)
	}
}

// AtLeast reports whether s is at least as severe as the threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s.Rank() >= threshold.Rank()
}

var severityOrder = []Severity{SeverityInfo, SeverityWarning, SeverityError}
