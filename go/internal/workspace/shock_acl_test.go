package workspace

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnsureShockReadACLRequestShape(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := EnsureShockReadACL(context.Background(), srv.Client(), srv.URL, "svctoken", "bob@patricbrc.org")
	if err != nil {
		t.Fatalf("EnsureShockReadACL: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/acl/read" {
		t.Errorf("path = %q, want /acl/read", gotPath)
	}
	// Built like Perl's raw string interpolation, not url.Values -- "@" must
	// appear literally, not percent-encoded.
	if gotQuery != "users=bob@patricbrc.org" {
		t.Errorf("query = %q, want %q (unescaped, matching Perl)", gotQuery, "users=bob@patricbrc.org")
	}
	if gotAuth != "OAuth svctoken" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "OAuth svctoken")
	}
}

func TestEnsureShockReadACLFailureReturnsACLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad service token"))
	}))
	defer srv.Close()

	err := EnsureShockReadACL(context.Background(), srv.Client(), srv.URL, "badtoken", "bob@patricbrc.org")
	if err == nil {
		t.Fatal("EnsureShockReadACL() = nil, want an error for a 401 response")
	}
	var aclErr *ACLError
	if !errors.As(err, &aclErr) {
		t.Fatalf("error is %T, want *ACLError", err)
	}
	if aclErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want 401", aclErr.StatusCode)
	}
}

func TestEnsureShockReadACLAcceptsAny2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := EnsureShockReadACL(context.Background(), srv.Client(), srv.URL, "tok", "bob"); err != nil {
		t.Errorf("EnsureShockReadACL: %v, want nil for a 204 response", err)
	}
}
