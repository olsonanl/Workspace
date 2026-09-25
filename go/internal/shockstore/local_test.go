package shockstore

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// writeShockFile creates <root>/<id[0:2]>/<id[2:4]>/<id[4:6]>/<id>/<id>.data
// with the given content, mirroring Shock's real on-disk layout.
func writeShockFile(t *testing.T, root, id, content string) string {
	t.Helper()
	dir := filepath.Join(root, id[0:2], id[2:4], id[4:6], id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, id+".data")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func shockNodeURL(id string) string {
	return "https://p3.theseed.org/services/shock_api/node/" + id
}

func TestOpenLocalHappyPath(t *testing.T) {
	root := t.TempDir()
	const id = "2f83bd7d-5a60-4f5a-a565-0b5bd619a29b"
	const content = "hello from shock"
	writeShockFile(t, root, id, content)

	f, err := OpenLocal(root, shockNodeURL(id), int64(len(content)))
	if err != nil {
		t.Fatalf("OpenLocal: %v", err)
	}
	defer f.Close()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != content {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestOpenLocalSizeMismatch(t *testing.T) {
	root := t.TempDir()
	const id = "2f83bd7d-5a60-4f5a-a565-0b5bd619a29b"
	writeShockFile(t, root, id, "short")

	_, err := OpenLocal(root, shockNodeURL(id), 99999)
	if !errors.Is(err, ErrIntegrity) {
		t.Errorf("err = %v, want ErrIntegrity", err)
	}
}

func TestOpenLocalMissingFile(t *testing.T) {
	root := t.TempDir()
	const id = "2f83bd7d-5a60-4f5a-a565-0b5bd619a29b"
	// Nothing written under root -- the sharded path doesn't exist.

	_, err := OpenLocal(root, shockNodeURL(id), 10)
	if !errors.Is(err, ErrIntegrity) {
		t.Errorf("err = %v, want ErrIntegrity (missing file is folded into integrity, not a soft miss)", err)
	}
}

func TestOpenLocalUnsupportedURL(t *testing.T) {
	root := t.TempDir()

	for _, url := range []string{
		"",
		"https://p3.theseed.org/download/somefile",
		"https://p3.theseed.org/services/shock_api/node/abc/", // trailing slash breaks the anchor
	} {
		_, err := OpenLocal(root, url, 10)
		if !errors.Is(err, ErrUnsupportedURL) {
			t.Errorf("url %q: err = %v, want ErrUnsupportedURL", url, err)
		}
	}
}
