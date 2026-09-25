package serviceauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeLogin serves the same shape login_rast expects and records what
// credentials and how many requests it saw.
type fakeLogin struct {
	srv       *httptest.Server
	hits      int
	lastUser  string
	lastPass  string
	token     string
	failCount int // fail this many requests with 401 before succeeding
}

func newFakeLogin(token string) *fakeLogin {
	fl := &fakeLogin{token: token}
	fl.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl.hits++
		u, p, _ := r.BasicAuth()
		fl.lastUser, fl.lastPass = u, p
		if fl.failCount > 0 {
			fl.failCount--
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `{"access_token":%q}`, fl.token)
	}))
	return fl
}

func (fl *fakeLogin) Close() { fl.srv.Close() }

func TestTokenLogsInAndSendsBasicAuth(t *testing.T) {
	fl := newFakeLogin("tok123")
	defer fl.Close()

	ts := &TokenSource{User: "wsuser", Password: "wspass", URL: fl.srv.URL}
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "tok123" {
		t.Errorf("Token = %q, want %q", got, "tok123")
	}
	if fl.lastUser != "wsuser" || fl.lastPass != "wspass" {
		t.Errorf("BasicAuth = %q/%q, want wsuser/wspass", fl.lastUser, fl.lastPass)
	}
}

func TestTokenIsCached(t *testing.T) {
	fl := newFakeLogin("tok123")
	defer fl.Close()

	ts := &TokenSource{User: "u", Password: "p", URL: fl.srv.URL}
	for i := 0; i < 3; i++ {
		if _, err := ts.Token(context.Background()); err != nil {
			t.Fatalf("Token %d: %v", i, err)
		}
	}
	if fl.hits != 1 {
		t.Errorf("login endpoint hit %d times, want 1 (should be cached)", fl.hits)
	}
}

func TestTokenReLogsInAfterExpiry(t *testing.T) {
	fl := newFakeLogin("tok123")
	defer fl.Close()

	ts := &TokenSource{User: "u", Password: "p", URL: fl.srv.URL, CacheTTL: 10 * time.Millisecond}
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if fl.hits != 2 {
		t.Errorf("login endpoint hit %d times, want 2 (cache should have expired)", fl.hits)
	}
}

func TestInvalidateForcesRelogin(t *testing.T) {
	fl := newFakeLogin("tok123")
	defer fl.Close()

	ts := &TokenSource{User: "u", Password: "p", URL: fl.srv.URL}
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	ts.Invalidate()
	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if fl.hits != 2 {
		t.Errorf("login endpoint hit %d times, want 2 (Invalidate should force a fresh login)", fl.hits)
	}
}

func TestTokenLoginFailure(t *testing.T) {
	fl := newFakeLogin("tok123")
	fl.failCount = 999
	defer fl.Close()

	ts := &TokenSource{User: "u", Password: "wrong", URL: fl.srv.URL}
	if _, err := ts.Token(context.Background()); err == nil {
		t.Error("Token() = nil error, want an error on a 401 login response")
	}
}
