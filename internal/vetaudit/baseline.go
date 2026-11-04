package vetaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// MarshalBaseline serializes a baseline deterministically. Diagnostics
// and package fingerprints are sorted by the caller; encoding/json emits
// map keys (rules) in sorted key order and the document carries no
// timestamps or other volatile data, so identical inputs always produce
// identical bytes.
func MarshalBaseline(b *Baseline) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("cannot marshal a nil baseline")
	}
	if b.Version != BaselineVersion {
		return nil, fmt.Errorf("unsupported baseline version: %d", b.Version)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBaseline parses a baseline and rejects unknown versions.
func UnmarshalBaseline(data []byte) (*Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse audit baseline: %w", err)
	}
	if b.Version != BaselineVersion {
		return nil, fmt.Errorf("unsupported audit baseline version: %d (expected %d)",
			b.Version, BaselineVersion)
	}
	if b.Rules == nil {
		b.Rules = map[string]RuleIdentity{}
	}
	if b.Diagnostics == nil {
		b.Diagnostics = []Diagnostic{}
	}
	return &b, nil
}

// LoadBaseline reads and parses a baseline file.
func LoadBaseline(path string) (*Baseline, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	b, err := UnmarshalBaseline(data)
	if err != nil {
		return nil, nil, err
	}
	return b, data, nil
}

// MarshalReport serializes a report deterministically.
func MarshalReport(r *Report) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("cannot marshal a nil report")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Digest returns the SHA-256 hex digest of the supplied content.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DigestFile returns the SHA-256 hex digest of a file's contents.
func DigestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
