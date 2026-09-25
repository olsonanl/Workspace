package dlservice

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/BV-BRC/Workspace/go/internal/dlstore"
)

// writeShockFile creates <root>/<id[0:2]>/<id[2:4]>/<id[4:6]>/<id>/<id>.data,
// mirroring Shock's real on-disk layout (and shockstore.ShardedPath, which
// this deliberately does not import, so the test doesn't just restate the
// production formula back at itself).
func writeShockFile(t *testing.T, root, id, content string) {
	t.Helper()
	dir := filepath.Join(root, id[0:2], id[2:4], id[4:6], id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".data"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const testShockID = "2f83bd7d-5a60-4f5a-a565-0b5bd619a29b"

func shockNodeURL(base, id string) string {
	return base + "/services/shock_api/node/" + id
}

// fakeShock serves the same query contract as real Shock: "?download" for a
// whole-object fetch, "?download&seek=B&length=L" for a range, both status
// 200 and 206 accepted by the client. It also records the last query string
// seen, so a test can assert the HTTP path was (or wasn't) used.
type fakeShock struct {
	srv        *httptest.Server
	content    string
	lastQuery  string
	statusCode int // 0 defaults to 200
}

func newFakeShock(content string) *fakeShock {
	fs := &fakeShock{content: content}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.lastQuery = r.URL.RawQuery
		status := fs.statusCode
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(fs.content))
	}))
	return fs
}

func (fs *fakeShock) Close() { fs.srv.Close() }

func TestShockDownloadOverHTTP(t *testing.T) {
	const body = "shock http payload"
	shock := newFakeShock(body)
	defer shock.Close()

	fs := &fakeStore{byKey: map[string]*dlstore.Download{
		"k": {
			DownloadKey: "k",
			Name:        "f.bin",
			Size:        int64(len(body)),
			ShockNode:   shock.srv.URL, // not configured to resolve locally
			UserToken:   "sometoken",
		},
	}}
	s := &Server{Store: fs, Log: quietLogger()}

	w := get(s.Handler(), "GET", "/download/k/f.bin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != body {
		t.Errorf("body = %q, want %q", w.Body.String(), body)
	}
	if shock.lastQuery != "download" {
		t.Errorf("shock query = %q, want %q (no seek/length for a non-range request)", shock.lastQuery, "download")
	}
}

// The same Range-header behavior local files get must hold for the HTTP
// Shock backend too -- this is the regression test that the byteSource
// unification actually works.
func TestShockDownloadOverHTTPRanges(t *testing.T) {
	const body = "0123456789"
	shock := newFakeShock(body)
	defer shock.Close()

	fs := &fakeStore{byKey: map[string]*dlstore.Download{
		"k": {DownloadKey: "k", Name: "f.bin", Size: int64(len(body)), ShockNode: shock.srv.URL},
	}}
	s := &Server{Store: fs, Log: quietLogger()}

	hdr := http.Header{"Range": {"bytes=2-4"}}
	w := get(s.Handler(), "GET", "/download/k/f.bin", hdr)
	if w.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", w.Code)
	}
	if got, want := w.Header().Get("Content-Range"), "bytes 2-4/10"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if got, want := shock.lastQuery, "download&seek=2&length=3"; got != want {
		t.Errorf("shock query = %q, want %q", got, want)
	}
}

func TestShockDownloadDirectFilesystem(t *testing.T) {
	const body = "read straight off disk"
	root := t.TempDir()
	writeShockFile(t, root, testShockID, body)

	// An HTTP client that fails any request proves the direct-filesystem path
	// is what actually served this, not a silent fallback to HTTP.
	failClient := &http.Client{Transport: failingRoundTripper{}}

	fs := &fakeStore{byKey: map[string]*dlstore.Download{
		"k": {
			DownloadKey: "k",
			Name:        "f.bin",
			Size:        int64(len(body)),
			ShockNode:   shockNodeURL("https://p3.theseed.org", testShockID),
		},
	}}
	s := &Server{Store: fs, Log: quietLogger(), ShockDataDir: root, ShockHTTPClient: failClient}

	w := get(s.Handler(), "GET", "/download/k/f.bin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != body {
		t.Errorf("body = %q, want %q", w.Body.String(), body)
	}
}

// A record whose recorded size disagrees with the on-disk file must be a
// hard 500, never a silent fallback to HTTP -- see shockstore's package doc
// and the plan this implements.
func TestShockDownloadIntegrityMismatchIsHardError(t *testing.T) {
	root := t.TempDir()
	writeShockFile(t, root, testShockID, "short")

	shock := newFakeShock("should never be served")
	defer shock.Close()

	fs := &fakeStore{byKey: map[string]*dlstore.Download{
		"k": {
			DownloadKey: "k",
			Name:        "f.bin",
			Size:        99999, // disagrees with the 5-byte file on disk
			ShockNode:   shockNodeURL(shock.srv.URL, testShockID),
		},
	}}
	s := &Server{Store: fs, Log: quietLogger(), ShockDataDir: root}

	w := get(s.Handler(), "GET", "/download/k/f.bin", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (integrity mismatch must not fall back to HTTP)", w.Code)
	}
	if shock.lastQuery != "" {
		t.Errorf("shock was queried (query=%q) but a mismatch must fail hard, not fall back", shock.lastQuery)
	}
}

func TestShockDownloadMissingFileIsHardError(t *testing.T) {
	root := t.TempDir() // nothing written

	fs := &fakeStore{byKey: map[string]*dlstore.Download{
		"k": {
			DownloadKey: "k",
			Name:        "f.bin",
			Size:        10,
			ShockNode:   shockNodeURL("https://p3.theseed.org", testShockID),
		},
	}}
	s := &Server{Store: fs, Log: quietLogger(), ShockDataDir: root}

	w := get(s.Handler(), "GET", "/download/k/f.bin", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// A shock URL that doesn't resolve to a local node id is a structural
// fallback to HTTP, not an error -- unlike a size mismatch.
func TestShockDownloadUnresolvableURLFallsBackToHTTP(t *testing.T) {
	root := t.TempDir()
	const body = "served over http because the url didn't parse"
	shock := newFakeShock(body)
	defer shock.Close()

	fs := &fakeStore{byKey: map[string]*dlstore.Download{
		"k": {
			DownloadKey: "k",
			Name:        "f.bin",
			Size:        int64(len(body)),
			ShockNode:   shock.srv.URL, // no "/node/<id>" suffix at all
		},
	}}
	s := &Server{Store: fs, Log: quietLogger(), ShockDataDir: root}

	w := get(s.Handler(), "GET", "/download/k/f.bin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (served via HTTP fallback)", w.Code)
	}
	if w.Body.String() != body {
		t.Errorf("body = %q, want %q", w.Body.String(), body)
	}
}

// A direct-filesystem Shock read must close the file it opens. Regression
// test for a leak in the original phase-2 code: seekerSource wrapped the
// *os.File in io.NopCloser, and sendFile only ever closed the fh it opened
// itself in the FilePath branch -- so every Shock download served off local
// disk held its fd open until process exit.
func TestShockDirectFilesystemDoesNotLeakFileDescriptors(t *testing.T) {
	const body = "no leaks here"
	root := t.TempDir()
	writeShockFile(t, root, testShockID, body)

	fs := &fakeStore{byKey: map[string]*dlstore.Download{
		"k": {
			DownloadKey: "k",
			Name:        "f.bin",
			Size:        int64(len(body)),
			ShockNode:   shockNodeURL("https://p3.theseed.org", testShockID),
		},
	}}
	s := &Server{Store: fs, Log: quietLogger(), ShockDataDir: root}

	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("cannot read /proc/self/fd on this platform: %v", err)
		}
		return len(entries)
	}

	before := countFDs()
	const n = 25
	for i := 0; i < n; i++ {
		w := get(s.Handler(), "GET", "/download/k/f.bin", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("iteration %d: status = %d, want 200", i, w.Code)
		}
	}
	after := countFDs()

	if after > before {
		t.Errorf("open fd count grew from %d to %d after %d direct-filesystem Shock downloads; want no growth", before, after, n)
	}
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("test: HTTP path must not be used")
}
