package cmd

import (
	"io"

	"github.com/sqlc-dev/sqlc/internal/config"
)

type Options struct {
	Env    Env
	Stderr io.Writer
	Stdout io.Writer
	// TODO: Move these to a command-specific struct
	Tags    []string
	Against string

	// Audit enables and configures the explicitly opted-in sqlc vet
	// audit flow. It is nil for normal vet runs and for every other
	// command.
	Audit *AuditOptions

	// Testing only
	MutateConfig func(*config.Config)
}

// AuditOptions configures the sqlc vet audit flow. The flow is enabled
// only when a non-empty BaselinePath is supplied.
type AuditOptions struct {
	// BaselinePath is the path to the diagnostic baseline file.
	BaselinePath string
	// Update replaces the baseline instead of comparing against it.
	Update bool
	// ReportPath and JSONPath receive text and JSON reports when set.
	ReportPath string
	JSONPath   string
	// Packages, Rules and Changes scope and filter the audit.
	Packages []string
	Rules    []string
	Changes  []string
	// FailOn sets the severity threshold for the failure gate.
	FailOn string
}

func (o *Options) ReadConfig(dir, filename string) (string, *config.Config, error) {
	path, conf, err := readConfig(o.Stderr, dir, filename)
	if err != nil {
		return path, conf, err
	}
	if o.MutateConfig != nil {
		o.MutateConfig(conf)
	}
	return path, conf, nil
}
