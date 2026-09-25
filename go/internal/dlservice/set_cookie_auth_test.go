package dlservice

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // matching the production algorithm under test
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/BV-BRC/Workspace/go/internal/p3auth"
)

// signedTestToken builds a token p3auth.Validator will accept, and a
// *p3auth.Validator trusting the signer that produced it -- enough to drive
// /set-cookie-auth's happy path without a live signer.
func signedTestToken(t *testing.T) (token string, v *p3auth.Validator, closeSigner func()) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"valid":true,"pubkey":%q}`, pemText)
	}))

	signedData := "un=bob@patricbrc.org|expiry=" + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + "|SigningSubject=" + signer.URL
	sum := sha1.Sum([]byte(signedData)) //nolint:gosec // matching the production algorithm under test
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	token = signedData + "|sig=" + hex.EncodeToString(sig)

	v = &p3auth.Validator{TrustedSigners: map[string]bool{signer.URL: true}}
	return token, v, signer.Close
}

func TestSetCookieAuthNoValidatorConfiguredIsForbidden(t *testing.T) {
	h, _ := newTestServer(t, "x")
	hdr := http.Header{"Authorization": {"un=bob|sig=whatever"}}

	w := get(h, "POST", "/set-cookie-auth", hdr)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when no Validator is configured", w.Code)
	}
	if got, want := w.Body.String(), "Authentication failed"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if got := w.Header().Get("Content-Type"); got != "" {
		t.Errorf("Content-Type = %q, want none", got)
	}
}

func TestSetCookieAuthBadTokenIsForbidden(t *testing.T) {
	srv := &Server{Store: &fakeStore{}, Log: quietLogger(), Validator: &p3auth.Validator{}}
	hdr := http.Header{"Authorization": {"not-a-real-token|sig=deadbeef"}}

	w := get(srv.Handler(), "POST", "/set-cookie-auth", hdr)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a token that fails validation", w.Code)
	}
	if got, want := w.Body.String(), "Authentication failed"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestSetCookieAuthValidTokenSetsCookie(t *testing.T) {
	token, v, closeSigner := signedTestToken(t)
	defer closeSigner()

	fs := &fakeStore{}
	srv := &Server{Store: fs, Log: quietLogger(), Validator: v, DownloadLifetime: 30 * time.Minute}

	w := get(srv.Handler(), "POST", "/set-cookie-auth", http.Header{"Authorization": {token}})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%q", w.Code, w.Body.String())
	}
	if got, want := w.Body.String(), "Cookie set\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}

	resp := w.Result()
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteNoneMode || cookie.Path != "/" {
		t.Errorf("cookie attributes = %+v, want HttpOnly+Secure+SameSite=None+Path=/", cookie)
	}
	if cookie.MaxAge != 30*60 {
		t.Errorf("MaxAge = %d, want %d (DownloadLifetime)", cookie.MaxAge, 30*60)
	}
	if len(fs.insertedSessions) != 1 {
		t.Fatalf("InsertSession called %d times, want 1", len(fs.insertedSessions))
	}
	inserted := fs.insertedSessions[0]
	if inserted.AuthToken != token {
		t.Errorf("stored auth_token = %q, want the original bearer token %q", inserted.AuthToken, token)
	}
	if cookie.Value != inserted.SessionToken {
		t.Errorf("cookie value %q does not match the session token that was stored (%q)", cookie.Value, inserted.SessionToken)
	}
}

func TestSetCookieAuthAcceptsAnyMethod(t *testing.T) {
	token, v, closeSigner := signedTestToken(t)
	defer closeSigner()

	for _, method := range []string{"GET", "POST", "PUT"} {
		srv := &Server{Store: &fakeStore{}, Log: quietLogger(), Validator: v}
		w := get(srv.Handler(), method, "/set-cookie-auth", http.Header{"Authorization": {token}})
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", method, w.Code)
		}
	}
}
