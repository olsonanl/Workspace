package workspace

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestShockOpenRangeRequestShape(t *testing.T) {
	var gotQuery, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "body")
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name             string
		start, length    int64
		token, wantQuery string
	}{
		{"no range -> plain download", 0, -1, "tok", "download"},
		{"ranged -> seek and length", 5, 10, "tok", "download&seek=5&length=10"},
		{"no token -> no auth header", 0, -1, "", "download"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, err := ShockOpenRange(context.Background(), srv.Client(), srv.URL, tc.token, tc.start, tc.length)
			if err != nil {
				t.Fatalf("ShockOpenRange: %v", err)
			}
			defer rc.Close()
			if gotQuery != tc.wantQuery {
				t.Errorf("query = %q, want %q", gotQuery, tc.wantQuery)
			}
			if tc.token != "" && gotAuth != "OAuth "+tc.token {
				t.Errorf("Authorization = %q, want %q", gotAuth, "OAuth "+tc.token)
			}
			if tc.token == "" && gotAuth != "" {
				t.Errorf("Authorization = %q, want empty", gotAuth)
			}
		})
	}
}

func TestShockOpenRangeAcceptsPartialContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPartialContent)
		io.WriteString(w, "partial")
	}))
	defer srv.Close()

	rc, err := ShockOpenRange(context.Background(), srv.Client(), srv.URL, "", 0, 7)
	if err != nil {
		t.Fatalf("ShockOpenRange: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "partial" {
		t.Errorf("body = %q, want %q", got, "partial")
	}
}

func TestShockOpenRangeErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "gone")
	}))
	defer srv.Close()

	_, err := ShockOpenRange(context.Background(), srv.Client(), srv.URL, "", 0, -1)
	if err == nil {
		t.Fatal("expected an error for a non-200/206 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v, want it to mention the status", err)
	}
}

// TestShockOpenRangeCancellation proves a canceled context aborts the
// request rather than blocking until the (slow) server responds -- the
// property that fixes the Perl service's disconnect-handling bug.
func TestShockOpenRangeCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hang until the test cleans up
	}))
	// srv.Close() blocks until in-flight handlers return, so block must be
	// closed first -- a plain "defer close(block); defer srv.Close()" would
	// deadlock, since defers run LIFO (srv.Close() would run before
	// close(block)).
	defer func() {
		close(block)
		srv.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() {
		_, err := ShockOpenRange(ctx, srv.Client(), srv.URL, "", 0, -1)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from the canceled request")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ShockOpenRange did not return promptly after context cancellation")
	}
}
