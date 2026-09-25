// Package dlservice implements the HTTP surface of the Workspace download
// service, a port of the Perl handlers in
// Bio/P3/Workspace/WorkspaceImpl.pm:1460-2040 (mounted by
// lib/WorkspaceDownload.psgi).
//
// The Perl service runs under Twiggy, a single-process event loop, and does
// synchronous Mongo and HTTP calls inside it. One slow call stalls every
// concurrent download -- measured at ~91% of wall-clock time. Go's per-request
// goroutines remove that coupling; blocking work here costs only its own
// request.
//
// Response details (status codes, body text, even header-name casing) are
// reproduced deliberately so this can be swapped in behind nginx without
// clients noticing. Where the Perl behavior is an outright bug, the deviation
// is called out in a comment and gated behind a Server field.
package dlservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BV-BRC/Workspace/go/internal/dlstore"
	"github.com/BV-BRC/Workspace/go/internal/shockstore"
	"github.com/BV-BRC/Workspace/go/internal/workspace"
)

// Error bodies, byte-for-byte as the Perl handlers emit them. All four are
// distinct and all are served as text/plain with a trailing newline.
const (
	bodyInvalidPath    = "Invalid path\n"    // bad URL shape, no record, lookup failed, open failed
	bodyNotFound       = "Not found\n"       // archive record with empty/non-array objects
	bodyNotAFile       = "Not a file\n"      // local path resolved to a directory
	bodyInvalidSession = "Invalid session\n" // /view with a missing/unknown/expired cookie
)

// SessionCookieName is set by /set-cookie-auth and read by /view
// (WorkspaceImpl.pm:1561, :1620).
const SessionCookieName = "bvbrc_ws_view_session"

// archivePathRE mirrors WorkspaceImpl.pm:1572. Note the character class is
// [a-z0-9], not hex -- it accepts g-z even though the value is always an
// HMAC-SHA1 hex digest.
var archivePathRE = regexp.MustCompile(`^/archive/([a-z0-9]{40})$`)

// filePathRE mirrors WorkspaceImpl.pm:1579: exactly two non-empty,
// slash-free segments.
var filePathRE = regexp.MustCompile(`^/([^/]+)/([^/]+)$`)

// Store is the subset of dlstore the handlers use, narrowed so tests can
// substitute a fake without a live Mongo.
type Store interface {
	FindByDownloadKey(ctx context.Context, key string) (*dlstore.Download, error)
	FindBySignature(ctx context.Context, sig string) (*dlstore.Download, error)
	FindSession(ctx context.Context, sessionToken string) (*dlstore.AuthCookie, error)
	InsertSession(ctx context.Context, a *dlstore.AuthCookie) error
}

// Server holds the handler dependencies and the compatibility switches.
type Server struct {
	Store Store
	Log   *slog.Logger

	// EnforceDownloadExpiry checks expiration_time on /download and /archive.
	//
	// The Perl code does NOT do this (WorkspaceImpl.pm:1836 queries on
	// download_key alone), leaving expiry to the 120s sweep -- so a key stays
	// live for up to two minutes past its nominal expiry. Default false for
	// bug-compatibility; set true to close the window.
	EnforceDownloadExpiry bool

	// StrictRangeErrors answers 416 for a range starting at or past EOF.
	//
	// The Perl code emits a 206 with a negative Content-Length instead. Default
	// false reproduces Perl; true is correct HTTP.
	StrictRangeErrors bool

	// ShockDataDir, when non-empty, enables reading Shock-backed objects
	// directly from the filesystem instead of through the Shock HTTP API --
	// see go/internal/shockstore. This is a deployment-wide switch (the
	// service either has access to Shock's data volume or it doesn't), not a
	// per-record fallback: a record whose file disagrees with its recorded
	// size is a hard error (500), never silently retried over HTTP. Empty
	// (the default) always uses the HTTP path.
	ShockDataDir string

	// ShockHTTPClient is used for Shock-over-HTTP reads, either because
	// ShockDataDir is unset or because a record's shock URL doesn't resolve
	// to a local node id. Defaults to http.DefaultClient when nil.
	ShockHTTPClient *http.Client
}

func (s *Server) shockHTTPClient() *http.Client {
	if s.ShockHTTPClient != nil {
		return s.ShockHTTPClient
	}
	return http.DefaultClient
}

// Handler builds the routed, CORS-wrapped handler.
//
// The Perl mount table (WorkspaceDownload.psgi:17-22) is:
//
//	/download          -> file or archive, prefix stripped
//	/view              -> workspace path, prefix stripped
//	/set-cookie-auth   -> any method, any sub-path
//	/                  -> same as /download, prefix NOT stripped (legacy URLs)
//
// All four URL forms are live: get_download_url mints /download/{key}/{name}
// and get_archive_url mints /archive/{sig}, while older links used /{key}/{name}.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/set-cookie-auth", s.handleSetCookieAuth)
	mux.HandleFunc("/set-cookie-auth/", s.handleSetCookieAuth)

	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		s.routeDownload(w, r, strings.TrimPrefix(r.URL.Path, "/download"))
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		s.routeDownload(w, r, strings.TrimPrefix(r.URL.Path, "/download"))
	})

	mux.HandleFunc("/view", func(w http.ResponseWriter, r *http.Request) {
		s.handleView(w, r, strings.TrimPrefix(r.URL.Path, "/view"))
	})
	mux.HandleFunc("/view/", func(w http.ResponseWriter, r *http.Request) {
		s.handleView(w, r, strings.TrimPrefix(r.URL.Path, "/view"))
	})

	// The "/" mount is the legacy fallback; the path is NOT stripped.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.routeDownload(w, r, r.URL.Path)
	})

	// accessLog is innermost so its timings cover only request handling, and
	// CORS preflights (answered by the middleware without calling the app) are
	// not logged as requests.
	return corsMiddleware(accessLog(s.Log, mux))
}

// routeDownload implements _download_request / _download_request_orig, which
// are byte-identical apart from their mount point (WorkspaceImpl.pm:1566, :1592).
func (s *Server) routeDownload(w http.ResponseWriter, r *http.Request, path string) {
	if m := archivePathRE.FindStringSubmatch(path); m != nil {
		s.handleArchive(w, r, m[1])
		return
	}
	m := filePathRE.FindStringSubmatch(path)
	if m == nil {
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}
	dlid, name := m[1], m[2]

	// Perl checks `if (!($name && $dlid))`, so a segment that is literally "0"
	// counts as missing and 404s.
	if dlid == "" || dlid == "0" || name == "" || name == "0" {
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}

	// `name` is parsed and then never used: the served filename always comes
	// from the Mongo record (WorkspaceImpl.pm:1584 passes it, :1843 ignores it).
	s.handleDownloadFile(w, r, dlid)
}

// handleDownloadFile implements _handle_dl_file_request (WorkspaceImpl.pm:1830).
func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request, dlid string) {
	rec, err := s.Store.FindByDownloadKey(r.Context(), dlid)
	if errors.Is(err, dlstore.ErrNotFound) {
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}
	if err != nil {
		// A Mongo failure is NOT "invalid path". Perl cannot tell these apart;
		// conflating them would hide an outage behind a 404.
		s.Log.Error("download key lookup failed", "err", err)
		writePlain(w, http.StatusInternalServerError, "Internal error\n")
		return
	}

	if s.EnforceDownloadExpiry && rec.Expired(time.Now()) {
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}

	s.sendFile(w, r, rec, rec.UserToken, false)
}

// handleArchive implements _handle_archive_request (WorkspaceImpl.pm:1664).
// The zip streaming itself lands in a later change; the lookup and its two
// distinct 404s are in place now.
func (s *Server) handleArchive(w http.ResponseWriter, r *http.Request, sig string) {
	rec, err := s.Store.FindBySignature(r.Context(), sig)
	if errors.Is(err, dlstore.ErrNotFound) {
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}
	if err != nil {
		s.Log.Error("archive signature lookup failed", "err", err)
		writePlain(w, http.StatusInternalServerError, "Internal error\n")
		return
	}
	// Note the different body here -- Perl returns "Not found\n", not
	// "Invalid path\n", when the record exists but carries no objects.
	if len(rec.Objects) == 0 {
		writePlain(w, http.StatusNotFound, bodyNotFound)
		return
	}
	if s.EnforceDownloadExpiry && rec.Expired(time.Now()) {
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}

	s.Log.Warn("archive route not yet implemented in Go", "objects", len(rec.Objects))
	writePlain(w, http.StatusNotImplemented, "Archive support not yet implemented\n")
}

// handleView implements _view_request (WorkspaceImpl.pm:1614). The workspace
// resolution it needs lands in a later change; session handling is in place now.
func (s *Server) handleView(w http.ResponseWriter, r *http.Request, wsPath string) {
	c, err := r.Cookie(SessionCookieName)
	// Perl truthiness again: an empty value or "0" counts as no cookie.
	if err != nil || c.Value == "" || c.Value == "0" {
		writePlain(w, http.StatusServiceUnavailable, bodyInvalidSession)
		return
	}

	sess, err := s.Store.FindSession(r.Context(), c.Value)
	if errors.Is(err, dlstore.ErrNotFound) {
		// Perl warns to STDERR here; the session token is a bearer secret, so
		// it is deliberately not logged.
		s.Log.Warn("no session found for presented cookie")
		writePlain(w, http.StatusServiceUnavailable, bodyInvalidSession)
		return
	}
	if err != nil {
		s.Log.Error("session lookup failed", "err", err)
		writePlain(w, http.StatusInternalServerError, "Internal error\n")
		return
	}
	if sess.Expired(time.Now()) {
		s.Log.Warn("session token has expired")
		writePlain(w, http.StatusServiceUnavailable, bodyInvalidSession)
		return
	}

	s.Log.Warn("view route not yet implemented in Go", "ws_path_len", len(wsPath))
	writePlain(w, http.StatusNotImplemented, "View support not yet implemented\n")
}

// handleSetCookieAuth implements _set_auth_request (WorkspaceImpl.pm:1515).
// Token validation lands in a later change.
func (s *Server) handleSetCookieAuth(w http.ResponseWriter, r *http.Request) {
	// Perl never checks the method; GET, POST and PUT all behave the same.
	token := r.Header.Get("Authorization")
	if token == "" || token == "0" {
		// Note: Perl sends NO Content-Type on this branch.
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "Authentication required")
		return
	}

	s.Log.Warn("set-cookie-auth not yet implemented in Go")
	writePlain(w, http.StatusNotImplemented, "Auth support not yet implemented\n")
}

// byteSource abstracts a backend that can serve a specific byte range of an
// object of known size, so streamRanged doesn't care whether it's talking to
// a local workspace file, a directly-opened Shock file, or Shock over HTTP.
type byteSource interface {
	// openRange returns a reader for [start, start+length), or from start to
	// EOF when length < 0. ctx cancellation must abort any in-flight I/O
	// (in particular the upstream Shock fetch), not merely stop being read
	// from -- see workspace.ShockOpenRange's doc comment for why this matters.
	openRange(ctx context.Context, start, length int64) (io.ReadCloser, error)
}

// seekerSource adapts a local, already-open *os.File to byteSource. Used for
// both genuine local workspace files and Shock nodes resolved to a local path
// by shockstore.OpenLocal -- once opened, the two are indistinguishable.
type seekerSource struct{ f *os.File }

func (s seekerSource) openRange(_ context.Context, start, length int64) (io.ReadCloser, error) {
	if _, err := s.f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	if length < 0 {
		return io.NopCloser(s.f), nil
	}
	return io.NopCloser(io.LimitReader(s.f, length)), nil
}

// httpShockSource adapts workspace.ShockOpenRange to byteSource.
type httpShockSource struct {
	hc       *http.Client
	shockURL string
	token    string
}

func (s httpShockSource) openRange(ctx context.Context, start, length int64) (io.ReadCloser, error) {
	return workspace.ShockOpenRange(ctx, s.hc, s.shockURL, s.token, start, length)
}

// sendFile implements _send_ws_file (WorkspaceImpl.pm:1846) for both the
// local-file and Shock backends.
func (s *Server) sendFile(w http.ResponseWriter, r *http.Request, rec *dlstore.Download, token string, inline bool) {
	var src byteSource
	size := rec.Size

	switch {
	case rec.ShockNode != "":
		var ok bool
		src, ok = s.resolveShockSource(w, rec, token)
		if !ok {
			return // resolveShockSource already wrote the response
		}

	case rec.FilePath != "":
		fh, err := os.Open(rec.FilePath)
		if err != nil {
			// Perl logs the path and errno, then 404s (:1965-1968).
			s.Log.Warn("could not open workspace file", "path", rec.FilePath, "err", err)
			writePlain(w, http.StatusNotFound, bodyInvalidPath)
			return
		}
		defer fh.Close()

		st, err := fh.Stat()
		if err != nil {
			s.Log.Warn("could not stat workspace file", "path", rec.FilePath, "err", err)
			writePlain(w, http.StatusNotFound, bodyInvalidPath)
			return
		}
		if st.IsDir() {
			writePlain(w, http.StatusNotFound, bodyNotAFile)
			return
		}
		src = seekerSource{fh}

	default:
		// Reachable when an archive record is fetched through /download/{key}:
		// Perl finds the doc, then open(undef) fails and it 404s.
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}

	// Perl trusts the Mongo `size` field rather than stat(), and reports it in
	// Content-Range. Keep that so Content-Range matches byte-for-byte even when
	// the record is stale.
	setDispositionHeaders(w, rec.Name, inline)
	s.streamRanged(w, r, src, size)
}

// resolveShockSource picks the Shock backend for rec and returns a byteSource
// ready to stream. ok is false when it has already written an error response
// itself (a filesystem integrity failure): the caller must not do anything
// further with the ResponseWriter.
func (s *Server) resolveShockSource(w http.ResponseWriter, rec *dlstore.Download, token string) (byteSource, bool) {
	if s.ShockDataDir != "" {
		f, err := shockstore.OpenLocal(s.ShockDataDir, rec.ShockNode, rec.Size)
		switch {
		case err == nil:
			return seekerSource{f}, true

		case errors.Is(err, shockstore.ErrIntegrity):
			// Per this deployment's guarantee that a sized Mongo record means
			// the backing file is complete, this must never happen -- treat it
			// as a hard failure rather than silently falling back to HTTP,
			// which would hide real corruption behind a working response.
			s.Log.Error("shock file integrity check failed", "node", rec.ShockNode, "err", err)
			writePlain(w, http.StatusInternalServerError, "Internal error\n")
			return nil, false

		case errors.Is(err, shockstore.ErrUnsupportedURL):
			// Structural, not corruption: this record's URL just doesn't look
			// like a local node reference. Fall through to HTTP below.
			s.Log.Debug("shock url not resolvable to a local path; using HTTP", "node", rec.ShockNode)

		default:
			// Should be unreachable -- shockstore.OpenLocal only returns the
			// two sentinel errors above -- but don't silently swallow a third
			// kind of failure if one is ever added.
			s.Log.Error("unexpected error resolving shock file locally", "node", rec.ShockNode, "err", err)
			writePlain(w, http.StatusInternalServerError, "Internal error\n")
			return nil, false
		}
	}

	return httpShockSource{s.shockHTTPClient(), rec.ShockNode, token}, true
}

// streamRanged writes the status line, range headers and body for src.
func (s *Server) streamRanged(w http.ResponseWriter, r *http.Request, src byteSource, size int64) {
	ctx := r.Context()
	rng, ok, satisfiable := parseRange(r.Header.Get("Range"), size)

	if ok && !satisfiable {
		if s.StrictRangeErrors {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			writePlain(w, http.StatusRequestedRangeNotSatisfiable, "Requested range not satisfiable\n")
			return
		}
		// Bug-compatible path: Perl clamps end to size-1 and emits a 206 whose
		// Content-Length is negative. Reproduce the headers, then send nothing.
		h := w.Header()
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.start, size-1, size))
		h.Set("Content-Length", strconv.FormatInt(size-1-rng.start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		return
	}

	if !ok {
		// Perl sets no Content-Length on the non-range path; the response is
		// chunked. Go would normally add one, so suppress it to match.
		body, err := src.openRange(ctx, 0, -1)
		if err != nil {
			s.Log.Error("opening backend for streaming failed", "err", err)
			writePlain(w, http.StatusInternalServerError, "Internal error\n")
			return
		}
		defer body.Close()
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, body); err != nil {
			s.Log.Warn("aborted while streaming body", "err", err)
		}
		return
	}

	body, err := src.openRange(ctx, rng.start, rng.length())
	if err != nil {
		s.Log.Error("opening backend for ranged streaming failed", "err", err)
		writePlain(w, http.StatusInternalServerError, "Internal error\n")
		return
	}
	defer body.Close()

	h := w.Header()
	h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.start, rng.end, size))
	h.Set("Content-Length", strconv.FormatInt(rng.length(), 10))
	w.WriteHeader(http.StatusPartialContent)

	if _, err := io.Copy(w, body); err != nil {
		s.Log.Warn("aborted while streaming ranged body", "err", err)
	}
}

// setDispositionHeaders reproduces WorkspaceImpl.pm:1851-1873, including the
// inconsistent header-name casing: the inline branch uses "Content-Type" while
// the attachment branch uses "Content-type". Go canonicalizes header names on
// Set, so the casing is normalized here -- it is observable over HTTP/1.1 but
// not over HTTP/2, and clients do not care. Everything else matches.
func setDispositionHeaders(w http.ResponseWriter, name string, inline bool) {
	h := w.Header()
	if inline {
		h.Set("Content-Disposition", "inline")
		h.Set("Content-Type", mimeTypeFor(name))
		return
	}
	// Perl interpolates the name unescaped, so a name containing a quote or
	// CRLF injects headers. Go's net/http rejects CR/LF in header values, and
	// quoting the name closes the rest. This is a deliberate fix.
	h.Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
	h.Set("Content-Type", "application/octet-stream")
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
