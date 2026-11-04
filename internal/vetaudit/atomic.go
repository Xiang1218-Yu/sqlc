package vetaudit

import (
	"fmt"
	"os"
	"path/filepath"
)

// stagedFile is a fully written, not yet published artifact.
type stagedFile struct {
	target string
	tmp    string
}

// AtomicWriteFile writes data to path atomically: content is written to a
// temporary file in the destination directory and then renamed into
// place, so concurrent or interrupted runs never observe a partial file.
// Parent directories are created first.
func AtomicWriteFile(path string, data []byte) error {
	staged, err := stageFile(path, data)
	if err != nil {
		return err
	}
	return staged.commit()
}

// AtomicWriteFiles publishes several files atomically with respect to
// each destination file: every file is fully staged before any file is
// renamed, so a staging failure leaves every existing file untouched.
// Renames themselves are atomic; the commit order is deterministic, so an
// interrupted run followed by a re-run converges on identical content.
func AtomicWriteFiles(files map[string][]byte) error {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	// Deterministic staging and commit order.
	sortStrings(paths)

	staged := make([]stagedFile, 0, len(paths))
	committed := make([]stagedFile, 0, len(paths))
	rollback := func() {
		for _, s := range staged {
			_ = os.Remove(s.tmp)
		}
	}

	for _, path := range paths {
		s, err := stageFile(path, files[path])
		if err != nil {
			rollback()
			return err
		}
		staged = append(staged, s)
	}
	for _, s := range staged {
		if err := s.commit(); err != nil {
			// Already committed files are complete and valid; remove the
			// remaining temp files and surface the failure so the caller
			// does not report success.
			rollback()
			return err
		}
		committed = append(committed, s)
	}
	return nil
}

func stageFile(path string, data []byte) (stagedFile, error) {
	if path == "" {
		return stagedFile{}, fmt.Errorf("cannot write to an empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return stagedFile{}, fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".sqlc-audit-*")
	if err != nil {
		return stagedFile{}, fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return stagedFile{}, fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return stagedFile{}, fmt.Errorf("flush %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return stagedFile{}, fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		_ = os.Remove(tmpName)
		return stagedFile{}, fmt.Errorf("chmod %s: %w", path, err)
	}
	return stagedFile{target: path, tmp: tmpName}, nil
}

func (s stagedFile) commit() error {
	if err := os.Rename(s.tmp, s.target); err != nil {
		_ = os.Remove(s.tmp)
		return fmt.Errorf("replace %s: %w", s.target, err)
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
