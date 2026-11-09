package durable

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateFile(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "file")
	if err := CreateFile(name, []byte("first"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := CreateFile(name, []byte("second"), 0o400); !errors.Is(err, fs.ErrExist) {
		t.Errorf("CreateFile over existing file: got %v, want ErrExist", err)
	}

	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Errorf("file contains %q, want %q", data, "first")
	}
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Errorf("file mode is %v, want 0400", fi.Mode().Perm())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("directory has %d entries, want only the file", len(entries))
	}
}
