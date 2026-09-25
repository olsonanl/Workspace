package dlservice

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BV-BRC/Workspace/go/internal/dlstore"
	"github.com/BV-BRC/Workspace/go/internal/serviceauth"
	"github.com/BV-BRC/Workspace/go/internal/wsresolve"
)

// testServiceAuth returns a *serviceauth.TokenSource backed by a fake login
// endpoint, for tests exercising the Shock ACL grant path.
func testServiceAuth(t *testing.T) *serviceauth.TokenSource {
	t.Helper()
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"test-service-token"}`)
	}))
	t.Cleanup(login.Close)
	return &serviceauth.TokenSource{User: "wsuser", Password: "wspass", URL: login.URL}
}

const viewTestUser = "u@patricbrc.org"

// newViewTestServer builds a server with a live, unexpired session for
// viewTestUser and no workspace/object fixtures yet -- callers populate
// fs.workspaces/byUUID/objects for their scenario.
func newViewTestServer(t *testing.T) (*Server, *fakeStore) {
	t.Helper()
	fs := &fakeStore{
		byKey:      map[string]*dlstore.Download{},
		bySig:      map[string]*dlstore.Download{},
		sessions:   map[string]*dlstore.AuthCookie{},
		workspaces: map[string]*wsresolve.Workspace{},
		byUUID:     map[string]*wsresolve.Workspace{},
		objects:    map[string]*dlstore.Object{},
	}
	fs.sessions["sess"] = &dlstore.AuthCookie{
		SessionToken:   "sess",
		AuthToken:      "un=" + viewTestUser + "|expiry=9999999999|sig=deadbeef",
		ExpirationTime: time.Now().Add(time.Hour).Unix(),
	}
	s := &Server{Store: fs, Log: quietLogger()}
	return s, fs
}

func viewRequest(h http.Handler, target string) *httptest.ResponseRecorder {
	hdr := http.Header{}
	hdr.Set("Cookie", SessionCookieName+"=sess")
	return get(h, "GET", target, hdr)
}

func TestViewHappyPathLocalFile(t *testing.T) {
	dir := t.TempDir()
	content := "hello from /view"
	// Mirrors WorkspaceImpl.pm:1814: <db-path>/<owner>/<ws-name>/<path>/<name>.
	fullPath := filepath.Join(dir, viewTestUser, "home", "sub", "x.txt")
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	s, fs := newViewTestServer(t)
	s.DBPath = dir
	fs.workspaces[viewTestUser+"/home"] = &wsresolve.Workspace{
		UUID: "ws-1", Owner: viewTestUser, Name: "home", GlobalPermission: wsresolve.PermNone,
	}
	fs.objects["ws-1|sub|x.txt"] = &dlstore.Object{Name: "x.txt", Path: "sub", Size: int64(len(content))}

	w := viewRequest(s.Handler(), "/view/"+viewTestUser+"/home/sub/x.txt")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%q", w.Code, w.Body.String())
	}
	if w.Body.String() != content {
		t.Errorf("body = %q, want %q", w.Body.String(), content)
	}
	// /view always serves inline, unlike /download's attachment disposition.
	if got := w.Header().Get("Content-Disposition"); got != "inline" {
		t.Errorf("Content-Disposition = %q, want %q", got, "inline")
	}
}

func TestViewHappyPathShockBacked(t *testing.T) {
	const body = "shock-backed view content"
	shock := newFakeShock(body)
	defer shock.Close()

	s, fs := newViewTestServer(t)
	fs.workspaces[viewTestUser+"/home"] = &wsresolve.Workspace{
		UUID: "ws-1", Owner: viewTestUser, Name: "home", GlobalPermission: wsresolve.PermNone,
	}
	fs.objects["ws-1||x.bin"] = &dlstore.Object{
		Name: "x.bin", Size: int64(len(body)), Shock: 1, ShockNode: shock.srv.URL,
	}

	w := viewRequest(s.Handler(), "/view/"+viewTestUser+"/home/x.bin")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%q", w.Code, w.Body.String())
	}
	if w.Body.String() != body {
		t.Errorf("body = %q, want %q", w.Body.String(), body)
	}
}

// The ACL grant is /view's own behavior and must fire exactly when the
// Shock-over-HTTP backend is actually used -- never for the direct-filesystem
// fast path, which needs no Shock authentication at all.
func TestViewGrantsShockACLOnlyOverHTTP(t *testing.T) {
	const body = "acl gated content"

	t.Run("HTTP backend: ACL PUT fires", func(t *testing.T) {
		var sawPUT bool
		shock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				sawPUT = true
				if got, want := r.URL.Path, "/acl/read"; got != want {
					t.Errorf("ACL PUT path = %q, want %q", got, want)
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		}))
		defer shock.Close()

		s, fs := newViewTestServer(t)
		s.ServiceAuth = testServiceAuth(t)
		fs.workspaces[viewTestUser+"/home"] = &wsresolve.Workspace{
			UUID: "ws-1", Owner: viewTestUser, Name: "home", GlobalPermission: wsresolve.PermNone,
		}
		fs.objects["ws-1||x.bin"] = &dlstore.Object{
			Name: "x.bin", Size: int64(len(body)), Shock: 1, ShockNode: shock.URL,
		}

		w := viewRequest(s.Handler(), "/view/"+viewTestUser+"/home/x.bin")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if !sawPUT {
			t.Error("no ACL PUT was sent for a Shock-over-HTTP /view read")
		}
	})

	t.Run("direct filesystem backend: no ACL PUT", func(t *testing.T) {
		root := t.TempDir()
		writeShockFile(t, root, testShockID, body)

		// If an ACL grant were attempted it would try to reach this URL and
		// fail loudly via failingRoundTripper -- proving the direct-FS path
		// issues no Shock traffic of any kind, ACL included.
		s, fs := newViewTestServer(t)
		s.ShockDataDir = root
		s.ShockHTTPClient = &http.Client{Transport: failingRoundTripper{}}
		s.ServiceAuth = testServiceAuth(t)
		fs.workspaces[viewTestUser+"/home"] = &wsresolve.Workspace{
			UUID: "ws-1", Owner: viewTestUser, Name: "home", GlobalPermission: wsresolve.PermNone,
		}
		fs.objects["ws-1||x.bin"] = &dlstore.Object{
			Name: "x.bin", Size: int64(len(body)), Shock: 1,
			ShockNode: shockNodeURL("https://p3.theseed.org", testShockID),
		}

		w := viewRequest(s.Handler(), "/view/"+viewTestUser+"/home/x.bin")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%q", w.Code, w.Body.String())
		}
		if w.Body.String() != body {
			t.Errorf("body = %q, want %q", w.Body.String(), body)
		}
	})
}

func TestViewPermissionDenied(t *testing.T) {
	s, fs := newViewTestServer(t)
	fs.workspaces["someoneelse@patricbrc.org/private"] = &wsresolve.Workspace{
		UUID: "ws-2", Owner: "someoneelse@patricbrc.org", Name: "private", GlobalPermission: wsresolve.PermNone,
	}
	fs.objects["ws-2||x.txt"] = &dlstore.Object{Name: "x.txt", Size: 1}

	w := viewRequest(s.Handler(), "/view/someoneelse@patricbrc.org/private/x.txt")
	if w.Code != http.StatusNotFound || w.Body.String() != bodyInvalidPath {
		t.Errorf("status=%d body=%q, want 404 %q (permission denied looks identical to not-found)", w.Code, w.Body.String(), bodyInvalidPath)
	}
}

func TestViewObjectIsFolder(t *testing.T) {
	s, fs := newViewTestServer(t)
	fs.workspaces[viewTestUser+"/home"] = &wsresolve.Workspace{
		UUID: "ws-1", Owner: viewTestUser, Name: "home", GlobalPermission: wsresolve.PermNone,
	}
	fs.objects["ws-1||adir"] = &dlstore.Object{Name: "adir", Folder: 1}

	w := viewRequest(s.Handler(), "/view/"+viewTestUser+"/home/adir")
	if w.Code != http.StatusNotFound || w.Body.String() != bodyInvalidPath {
		t.Errorf("status=%d body=%q, want 404 %q", w.Code, w.Body.String(), bodyInvalidPath)
	}
}

func TestViewObjectNotFound(t *testing.T) {
	s, fs := newViewTestServer(t)
	fs.workspaces[viewTestUser+"/home"] = &wsresolve.Workspace{
		UUID: "ws-1", Owner: viewTestUser, Name: "home", GlobalPermission: wsresolve.PermNone,
	}
	// No matching object in fs.objects.

	w := viewRequest(s.Handler(), "/view/"+viewTestUser+"/home/nope.txt")
	if w.Code != http.StatusNotFound || w.Body.String() != bodyInvalidPath {
		t.Errorf("status=%d body=%q, want 404 %q", w.Code, w.Body.String(), bodyInvalidPath)
	}
}

func TestViewUnknownWorkspace(t *testing.T) {
	s, _ := newViewTestServer(t)
	// No workspace fixture at all.
	w := viewRequest(s.Handler(), "/view/"+viewTestUser+"/nosuchworkspace/x.txt")
	if w.Code != http.StatusNotFound || w.Body.String() != bodyInvalidPath {
		t.Errorf("status=%d body=%q, want 404 %q", w.Code, w.Body.String(), bodyInvalidPath)
	}
}

func TestViewMalformedPathIs404(t *testing.T) {
	s, _ := newViewTestServer(t)
	// A single segment matches none of wsresolve.ParseWSPath's shapes.
	w := viewRequest(s.Handler(), "/view/onlyonesegment")
	if w.Code != http.StatusNotFound || w.Body.String() != bodyInvalidPath {
		t.Errorf("status=%d body=%q, want 404 %q", w.Code, w.Body.String(), bodyInvalidPath)
	}
}

// A workspace granting the caller an explicit permission above global (but
// still not owner) must be honored -- exercises the non-owner grant branch of
// wsresolve.EffectivePermission end to end through the HTTP handler.
func TestViewGrantedPermission(t *testing.T) {
	s, fs := newViewTestServer(t)
	fs.workspaces["owner@patricbrc.org/shared"] = &wsresolve.Workspace{
		UUID: "ws-3", Owner: "owner@patricbrc.org", Name: "shared",
		GlobalPermission: wsresolve.PermNone,
		Permissions:      map[string]wsresolve.Perm{viewTestUser: wsresolve.PermRead},
	}
	fs.objects["ws-3||x.txt"] = &dlstore.Object{Name: "x.txt", Size: 3}

	dir := t.TempDir()
	fullPath := filepath.Join(dir, "owner@patricbrc.org", "shared", "x.txt")
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte("hey"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.DBPath = dir

	w := viewRequest(s.Handler(), "/view/owner@patricbrc.org/shared/x.txt")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (explicit grant should allow read)", w.Code)
	}
}
