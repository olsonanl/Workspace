// Package serviceauth ports the Workspace download service's use of a
// service-account login: P3AuthLogin::login_rast
// (modules/p3_auth/lib/P3AuthLogin.pm) and its caller-side cache, _wsauth
// (Bio/P3/Workspace/WorkspaceImpl.pm:164-176). The only consumer today is
// /view's Shock read-ACL grant, which must run "using the workspace owner
// token" rather than the requesting user's own (WorkspaceImpl.pm:1821) --
// but the mechanism (a cached, retriable service-account bearer token) is
// independent of that one call site, hence its own package.
package serviceauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// DefaultLoginURL is P3AuthConstants.pm's globus_token_url, byte for byte:
// http, not https. This is not a mistake to "fix" here -- it is what the
// deployed endpoint actually is, and switching to https without confirming
// the endpoint serves it would trade a known-working call for an untested
// one. It does mean the Basic-auth credentials in the request this package
// sends are sent in the clear, exactly as Perl already does.
const DefaultLoginURL = "http://rast.nmpdr.org/goauth/token?grant_type=client_credentials"

// DefaultTimeout matches P3AuthLogin.pm's $ua_timeout (10 seconds).
const DefaultTimeout = 10 * time.Second

// DefaultCacheTTL bounds how long a fetched token is reused before this
// package proactively re-logs-in.
//
// This is a Go-side addition with no Perl equivalent: login_rast returns
// only an opaque access_token with no expiry claim, and _wsauth
// (WorkspaceImpl.pm:164-176) caches whatever it gets on $self FOREVER, with
// no refresh and no invalidation on a failed use -- so in Perl's long-lived
// Twiggy process, an expired service token silently and permanently breaks
// every Shock-backed /view until the process restarts (the ACL-grant PUT's
// response is discarded unchecked at :1823, so nothing ever notices). This
// package cannot know the real rotation period any more than Perl could, so
// DefaultCacheTTL is a conservative guess; TokenSource.Invalidate is the
// actual fix, letting a caller force one fresh login after a 401 rather than
// silently failing forever.
const DefaultCacheTTL = 30 * time.Minute

// TokenSource fetches and caches a service-account bearer token. The zero
// value is not usable -- User and Password are required.
type TokenSource struct {
	User, Password string

	// URL defaults to DefaultLoginURL.
	URL string
	// HTTPClient defaults to a client with DefaultTimeout.
	HTTPClient *http.Client
	// CacheTTL defaults to DefaultCacheTTL.
	CacheTTL time.Duration

	mu        sync.Mutex
	cached    string
	fetchedAt time.Time
}

func (t *TokenSource) url() string {
	if t.URL != "" {
		return t.URL
	}
	return DefaultLoginURL
}

func (t *TokenSource) httpClient() *http.Client {
	if t.HTTPClient != nil {
		return t.HTTPClient
	}
	return &http.Client{Timeout: DefaultTimeout}
}

func (t *TokenSource) cacheTTL() time.Duration {
	if t.CacheTTL > 0 {
		return t.CacheTTL
	}
	return DefaultCacheTTL
}

// Token returns a cached token if one is fresh, otherwise logs in and caches
// the result.
func (t *TokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.cached != "" && time.Since(t.fetchedAt) < t.cacheTTL() {
		return t.cached, nil
	}

	tok, err := t.login(ctx)
	if err != nil {
		return "", err
	}
	t.cached = tok
	t.fetchedAt = time.Now()
	return tok, nil
}

// Invalidate discards the cached token, forcing the next Token call to log
// in again. Callers should use this after a request authenticated with the
// cached token comes back 401 -- Perl has no equivalent (see DefaultCacheTTL's
// doc comment), which is precisely the gap this exists to close.
func (t *TokenSource) Invalidate() {
	t.mu.Lock()
	t.cached = ""
	t.mu.Unlock()
}

// login ports P3AuthLogin::login_rast exactly: GET the login URL with HTTP
// Basic credentials, expect JSON {"access_token": "..."}.
func (t *TokenSource) login(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.url(), nil)
	if err != nil {
		return "", fmt.Errorf("serviceauth: building login request: %w", err)
	}
	req.SetBasicAuth(t.User, t.Password)

	resp, err := t.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("serviceauth: login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("serviceauth: login failed: %s", resp.Status)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("serviceauth: decoding login response: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("serviceauth: login response had no access_token")
	}
	return body.AccessToken, nil
}
