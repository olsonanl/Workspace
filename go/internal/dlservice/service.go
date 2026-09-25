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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BV-BRC/Workspace/go/internal/dlstore"
	"github.com/BV-BRC/Workspace/go/internal/p3auth"
	"github.com/BV-BRC/Workspace/go/internal/serviceauth"
	"github.com/BV-BRC/Workspace/go/internal/shockstore"
	"github.com/BV-BRC/Workspace/go/internal/workspace"
	"github.com/BV-BRC/Workspace/go/internal/wsresolve"
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

	// FindWorkspace, FindWorkspaceByUUID and FindObject back /view's
	// resolution path -- see handleView and internal/dlstore's
	// FindObject doc comment for what is deliberately NOT reproduced from
	// Perl's equivalent (_query_database's write side effects on what is a
	// read path).
	FindWorkspace(ctx context.Context, owner, name string) (*wsresolve.Workspace, error)
	FindWorkspaceByUUID(ctx context.Context, uuid string) (*wsresolve.Workspace, error)
	FindObject(ctx context.Context, workspaceUUID, path, name string) (*dlstore.Object, error)
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

	// Validator checks inbound token signatures for /set-cookie-auth
	// (WorkspaceImpl.pm:1527-1534). Required for that route to do anything
	// but answer 401/501; leave nil for a /download-only deployment.
	Validator *p3auth.Validator

	// DownloadLifetime backs both /set-cookie-auth's session cookie's
	// Max-Age and the stored auth_cookie's expiration_time
	// (WorkspaceImpl.pm:1539-1561). Zero means wsconfig.DefaultDownloadLifetime
	// (1 hour), matching Perl's own fallback there.
	DownloadLifetime time.Duration

	// ServiceAuth, when set, lets /view grant a Shock read ACL to the
	// requesting user under a service account, exactly as
	// _lookup_ws_file_details does before serving a Shock-backed object
	// (WorkspaceImpl.pm:1817-1823) -- but ONLY for the Shock-over-HTTP
	// backend; the direct-filesystem fast path needs no Shock auth at all
	// and never triggers this. Nil disables ACL granting; the read is still
	// attempted, matching what happens in Perl when the grant silently fails
	// (its PUT's response is never checked).
	ServiceAuth *serviceauth.TokenSource

	// DBPath is the local-filesystem root for non-Shock workspace objects
	// (wsconfig.Config.DBPath, already normalized with the "/P3WSDB" suffix
	// Perl's constructor appends). /view needs this to build a local
	// object's file path itself (WorkspaceImpl.pm:1814) -- unlike
	// /download and /archive, whose records already carry a precomputed
	// file_path written by the RPC service.
	DBPath string
}

func (s *Server) shockHTTPClient() *http.Client {
	if s.ShockHTTPClient != nil {
		return s.ShockHTTPClient
	}
	return http.DefaultClient
}

// downloadLifetimeDuration mirrors WorkspaceImpl.pm:1539-1544's fallback: a
// zero/unset lifetime defaults to one hour.
func (s *Server) downloadLifetimeDuration() time.Duration {
	if s.DownloadLifetime > 0 {
		return s.DownloadLifetime
	}
	return time.Hour
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

	s.sendFile(w, r, rec, rec.UserToken, false, "")
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

// handleView implements _view_request (WorkspaceImpl.pm:1614).
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

	// Perl reads the caller's user id straight off the session's stored
	// token without a second signature check (WorkspaceImpl.pm:1641) -- the
	// token was already validated once, at /set-cookie-auth time. Using
	// ParseUnverified here (rather than Validator.Validate) is that same
	// choice, made explicit; see its doc comment for why it's safe only in
	// this position.
	claims, err := p3auth.ParseUnverified(sess.AuthToken)
	if err != nil {
		s.Log.Warn("session's stored token is malformed", "err", err)
		writePlain(w, http.StatusServiceUnavailable, bodyInvalidSession)
		return
	}
	currentUser := claims.UserID()

	rec, err := s.resolveView(r.Context(), wsPath, currentUser)
	if errors.Is(err, errViewResolution) {
		// Every resolution failure -- bad path shape, unknown workspace,
		// permission denied, object missing, object is a folder -- collapses
		// to the same body, matching Perl's blanket eval/$@
		// (WorkspaceImpl.pm:1655-1659). The distinction lives only in this
		// log line.
		s.Log.Warn("view resolution failed", "err", err)
		writePlain(w, http.StatusNotFound, bodyInvalidPath)
		return
	}
	if err != nil {
		s.Log.Error("view resolution failed", "err", err)
		writePlain(w, http.StatusInternalServerError, "Internal error\n")
		return
	}

	// _view_request always serves inline and always uses the session's own
	// token, never a service token, for the actual read (WorkspaceImpl.pm:1661:
	// $self->_send_ws_file($req, $doc, $token, 1) where $token is the
	// session's auth_token). aclGrantUser (currentUser) is separate: it's
	// who Shock is told to let read the node, granted under the service
	// account -- see resolveShockSource.
	s.sendFile(w, r, rec, sess.AuthToken, true, currentUser)
}

// errViewResolution is wrapped by every failure inside resolveView that
// should become a 404, so handleView can collapse them all to the same body
// while still logging which one actually happened.
var errViewResolution = errors.New("dlservice: view resolution failed")

// resolveView implements _lookup_ws_file_details (WorkspaceImpl.pm:1778-1828):
// parse wsPath, look up its workspace, check the caller has at least read
// permission, look up the object, and reject a folder. On success it
// synthesizes a *dlstore.Download exactly as _lookup_ws_file_details builds
// its $doc (:1807-1826), so the existing sendFile/streamRanged machinery --
// already shared with /download on the Perl side -- needs no changes to
// serve it.
func (s *Server) resolveView(ctx context.Context, wsPath, currentUser string) (*dlstore.Download, error) {
	parsed, err := wsresolve.ParseWSPath(wsPath)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing path: %v", errViewResolution, err)
	}

	var ws *wsresolve.Workspace
	var path, name string

	switch parsed.Kind {
	case wsresolve.KindUserWorkspace:
		ws, err = s.Store.FindWorkspace(ctx, parsed.User, parsed.Workspace)
		path, name = parsed.Path, parsed.Name

	case wsresolve.KindWorkspaceUUID:
		ws, err = s.Store.FindWorkspaceByUUID(ctx, parsed.WorkspaceUUID)
		path, name = parsed.Path, parsed.Name

	default:
		// KindObjectUUID: unreachable from the /view route in practice --
		// wsPath always has a leading "/" once the mount prefix is stripped,
		// and that shape never matches a bare UUID (see
		// wsresolve.KindObjectUUID's doc comment) -- but handled rather than
		// silently mis-resolving if that ever changes.
		return nil, fmt.Errorf("%w: a bare object uuid is not resolvable via /view", errViewResolution)
	}

	if errors.Is(err, dlstore.ErrNotFound) {
		return nil, fmt.Errorf("%w: workspace not found", errViewResolution)
	}
	if err != nil {
		return nil, fmt.Errorf("dlservice: looking up workspace: %w", err)
	}

	if !wsresolve.EffectivePermission(ws, currentUser).AtLeast(wsresolve.PermRead) {
		return nil, fmt.Errorf("%w: permission denied", errViewResolution)
	}

	obj, err := s.Store.FindObject(ctx, ws.UUID, path, name)
	if errors.Is(err, dlstore.ErrNotFound) {
		return nil, fmt.Errorf("%w: object not found", errViewResolution)
	}
	if err != nil {
		return nil, fmt.Errorf("dlservice: looking up object: %w", err)
	}
	if obj.IsFolder() {
		return nil, fmt.Errorf("%w: object is a folder, not a file", errViewResolution)
	}

	doc := &dlstore.Download{
		WorkspacePath: wsPath,
		Name:          obj.Name,
		Size:          obj.Size,
	}
	if obj.IsShock() {
		doc.ShockNode = obj.ShockNode
	} else {
		// Mirrors WorkspaceImpl.pm:1814: <db-path>/<owner>/<ws-name>/<path>/<name>.
		// s.DBPath already has "/P3WSDB" appended and doubled slashes
		// collapsed (wsconfig.normalizeDBPath). An object at the workspace
		// root has Path=="", which would produce a doubled slash mid-path in
		// Perl's string concatenation; filepath.Join normalizes that away
		// here, so don't expect this to string-match a Perl log line
		// byte-for-byte.
		doc.FilePath = filepath.Join(s.DBPath, ws.Owner, ws.Name, obj.Path, obj.Name)
	}
	return doc, nil
}

// handleSetCookieAuth implements _set_auth_request (WorkspaceImpl.pm:1515).
func (s *Server) handleSetCookieAuth(w http.ResponseWriter, r *http.Request) {
	// Perl never checks the method; GET, POST and PUT all behave the same.
	token := r.Header.Get("Authorization")
	if token == "" || token == "0" {
		// Note: Perl sends NO Content-Type on this branch.
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "Authentication required")
		return
	}

	if s.Validator == nil {
		// No validator configured: fail the same way an invalid token would
		// rather than silently accepting every request, per the package doc's
		// warning that nothing may authenticate a request without one.
		s.Log.Error("set-cookie-auth called with no Validator configured")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "Authentication failed")
		return
	}

	if err := s.Validator.Validate(token); err != nil {
		// Perl warns the reason to STDERR and returns a fixed body regardless
		// of which check failed (:1530-1534) -- do the same; the reason is
		// for our logs, never the client.
		s.Log.Warn("token validation failed", "err", err)
		// Note: Perl sends NO Content-Type on this branch either.
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "Authentication failed")
		return
	}

	sessionToken, err := newSessionToken()
	if err != nil {
		s.Log.Error("generating session token failed", "err", err)
		writePlain(w, http.StatusInternalServerError, "Internal error\n")
		return
	}

	lifetime := s.downloadLifetimeDuration()
	expires := time.Now().Add(lifetime)

	if err := s.Store.InsertSession(r.Context(), &dlstore.AuthCookie{
		SessionToken:   sessionToken,
		ExpirationTime: expires.Unix(),
		AuthToken:      token,
	}); err != nil {
		s.Log.Error("inserting session failed", "err", err)
		writePlain(w, http.StatusInternalServerError, "Internal error\n")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(lifetime.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	writePlain(w, http.StatusOK, "Cookie set\n")
}

// newSessionToken generates a URL-safe random session token. Perl mints one
// from Data::UUID->create_b64(), then strips the "=" padding and remaps "+"
// and "/" to "-" and "_" (WorkspaceImpl.pm:1547-1551) -- i.e. it hand-rolls
// base64.RawURLEncoding over what is, in entropy terms, a 128-bit UUID.
// base64.RawURLEncoding of 16 CSPRNG bytes produces a token in the same
// alphabet and of the same length, from a proper randomness source rather
// than a UUID generator's.
func newSessionToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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
//
// seekerSource owns f and implements io.Closer so sendFile can release it
// uniformly regardless of which backend produced it -- see the comment there.
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

func (s seekerSource) Close() error { return s.f.Close() }

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
//
// aclGrantUser, when non-empty, is the user id to grant Shock read access to
// (via a service-account token) before streaming a Shock-over-HTTP response
// -- see resolveShockSource. This is /view's own behavior
// (_lookup_ws_file_details, WorkspaceImpl.pm:1810-1826) and must stay empty
// for /download and /archive, which never do this in Perl: pass "" from
// those callers.
func (s *Server) sendFile(w http.ResponseWriter, r *http.Request, rec *dlstore.Download, token string, inline bool, aclGrantUser string) {
	var src byteSource
	size := rec.Size

	switch {
	case rec.ShockNode != "":
		var ok bool
		src, ok = s.resolveShockSource(w, r, rec, token, aclGrantUser)
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

		st, err := fh.Stat()
		if err != nil {
			fh.Close()
			s.Log.Warn("could not stat workspace file", "path", rec.FilePath, "err", err)
			writePlain(w, http.StatusNotFound, bodyInvalidPath)
			return
		}
		if st.IsDir() {
			fh.Close()
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

	// Every branch above that reaches here has handed us an open resource
	// (a local file, or a Shock file opened by shockstore.OpenLocal via
	// resolveShockSource) wrapped in seekerSource, which implements io.Closer.
	// httpShockSource opens nothing until streamRanged calls openRange, and
	// that reader is closed there instead -- so this covers exactly the
	// backends that need it, once, regardless of which one produced src.
	if c, ok := src.(io.Closer); ok {
		defer c.Close()
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
//
// aclGrantUser is threaded through from sendFile: when non-empty AND the
// direct-filesystem fast path is not used (either ShockDataDir is unset, or
// this record's URL doesn't resolve to a local node id), this grants that
// user read access to the Shock node before returning the HTTP backend --
// see ensureShockACL. The direct-filesystem path never needs this: reading
// straight off disk involves no Shock authentication at all.
func (s *Server) resolveShockSource(w http.ResponseWriter, r *http.Request, rec *dlstore.Download, token, aclGrantUser string) (byteSource, bool) {
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

	if aclGrantUser != "" {
		if err := s.ensureShockACL(r.Context(), rec.ShockNode, aclGrantUser); err != nil {
			// Perl discards this PUT's response entirely (:1823), so a failed
			// grant today is invisible until Shock 403s the actual read.
			// Log it, but proceed exactly as Perl does -- the read is
			// attempted regardless of whether the grant succeeded.
			s.Log.Warn("failed to grant shock read acl; the read may still fail",
				"node", rec.ShockNode, "user", aclGrantUser, "err", err)
		}
	}

	return httpShockSource{s.shockHTTPClient(), rec.ShockNode, token}, true
}

// ensureShockACL grants aclGrantUser read access to shockNodeURL using
// s.ServiceAuth's token, retrying once with a fresh token if the grant comes
// back 401. Perl's equivalent (_wsauth, WorkspaceImpl.pm:164-176) caches its
// service token forever with no such retry, so an expired token there
// silently breaks every grant until the process restarts -- see
// serviceauth's package doc.
func (s *Server) ensureShockACL(ctx context.Context, shockNodeURL, user string) error {
	if s.ServiceAuth == nil {
		return errors.New("no service-account credentials configured")
	}

	tok, err := s.ServiceAuth.Token(ctx)
	if err != nil {
		return fmt.Errorf("fetching service token: %w", err)
	}

	err = workspace.EnsureShockReadACL(ctx, s.shockHTTPClient(), shockNodeURL, tok, user)
	var aclErr *workspace.ACLError
	if errors.As(err, &aclErr) && aclErr.StatusCode == http.StatusUnauthorized {
		s.ServiceAuth.Invalidate()
		tok, tokErr := s.ServiceAuth.Token(ctx)
		if tokErr != nil {
			return fmt.Errorf("re-fetching service token after 401: %w", tokErr)
		}
		err = workspace.EnsureShockReadACL(ctx, s.shockHTTPClient(), shockNodeURL, tok, user)
	}
	return err
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
