// Command ws-download-difftest diffs the Go ws-download service against the
// live Perl WorkspaceDownload service for identical requests, to answer the
// one question unit tests can't: do the two agree byte-for-byte against real
// Mongo, real Shock, and a real token signer?
//
// This is phase 4 of the port (see ../ws-download/PORT_STATUS.md and
// PORT_PLAN.md). Phases 1-3 built /download, /view, and /set-cookie-auth
// against unit tests and the Perl *source*; this tool is the first check
// against the Perl *service* itself. /archive is not implemented yet
// (phase 5), so it is out of scope here.
//
// Usage:
//
//	ws-download-difftest \
//	    --perl-url https://p3.theseed.org/services/WorkspaceDownload \
//	    --go-url   http://localhost:7229 \
//	    --object   /you@patricbrc.org/home/some-local-file.txt \
//	    --object   /you@patricbrc.org/home/some-shock-file.bam
//
// Give at least one --object you own; ideally one backed by a local file and
// one backed by Shock, so both storage backends get exercised. A token is
// required (for minting real download keys via the RPC service, and for
// /set-cookie-auth): pass --token, set P3_TOKEN, or have ~/.patric_token in
// place (same lookup as p3-login leaves behind; see internal/auth.LoadToken).
//
// SAFETY. Every read this tool makes is against whatever real data --perl-url
// and --rpc-url point at -- there is no sandbox mode, because the whole point
// is to compare against the real service. The only writes are exactly what
// already happens every time anyone uses /set-cookie-auth or /view for real:
// one auth_cookie session row per /set-cookie-auth call, and one (idempotent)
// Shock read-ACL grant per /view call served over HTTP. All test traffic uses
// your own token and objects; never point --object or --foreign-object at
// data you don't own or have explicit permission to read. Point --go-url at a
// private, non-nginx-routed port (see PORT_STATUS.md's cutover notes) -- this
// tool assumes it is never talking to a Go instance that is itself already
// serving real production traffic.
package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/BV-BRC/Workspace/go/internal/auth"
	"github.com/BV-BRC/Workspace/go/internal/workspace"
)

// maxBodyBytes caps how much of any single response body this tool will read
// into memory for a sha256 comparison. A test object should be modest in
// size; this is a backstop, not a feature.
const maxBodyBytes = 200 << 20 // 200 MiB

// debugBodyPreview mirrors the ≤2 KiB body preview convention documented for
// P3_DEBUG_HTTP in the top-level CLAUDE.md, so a failure dump looks familiar.
const debugBodyPreview = 2 << 10

func main() {
	var (
		perlURL = pflag.String("perl-url", "https://p3.theseed.org/services/WorkspaceDownload", "base URL of the live Perl download service")
		goURL   = pflag.String("go-url", "", "base URL of the Go ws-download instance under test (required; point it at a private, non-nginx-routed port)")
		rpcURL  = pflag.String("rpc-url", workspace.DefaultURL, "base URL of the Workspace RPC service, for minting real download keys")
		token   = pflag.String("token", "", "BV-BRC auth token (default: $P3_TOKEN, then ~/.patric_token, then ~/.bvbrc_token)")
		objects = pflag.StringArray("object", nil, "full workspace path to a real object you own, to exercise /download and /view against (repeatable; give at least one local-file-backed and one Shock-backed)")
		foreign = pflag.String("foreign-object", "", "optional: a real object path you do NOT have read access to, for the /view permission-denied case")
		verbose = pflag.Bool("verbose", false, "on a mismatch, print both responses (redacted; see P3_DEBUG_HTTP's convention)")
		timeout = pflag.Duration("timeout", 60*time.Second, "per-request timeout")
	)
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ws-download-difftest - diff the Go port against the live Perl service\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  ws-download-difftest --go-url <url> --object <ws-path> [options]\n\n")
		fmt.Fprintf(os.Stderr, "SAFETY: reads real production data and writes real session/ACL rows.\n")
		fmt.Fprintf(os.Stderr, "        Use only your own objects. See the package doc for detail.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
	}
	pflag.Parse()

	if *goURL == "" || len(*objects) == 0 {
		pflag.Usage()
		os.Exit(1)
	}

	tok, err := loadToken(*token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{Timeout: *timeout}
	ws := workspace.NewClient(*rpcURL, tok)
	ws.HTTPClient = client

	cfg := &config{
		perlURL: strings.TrimRight(*perlURL, "/"),
		goURL:   strings.TrimRight(*goURL, "/"),
		token:   tok,
		verbose: *verbose,
	}

	t := &tally{}
	for _, obj := range *objects {
		fmt.Printf("\n=== object: %s ===\n", obj)
		runObjectCases(t, cfg, client, ws, obj)
	}

	fmt.Printf("\n=== /set-cookie-auth ===\n")
	perlCookie, goCookie := runSetCookieAuthCases(t, cfg, client, tok)

	if len(*objects) > 0 {
		fmt.Printf("\n=== /view (session-gated cases) ===\n")
		runViewSessionCases(t, cfg, client, (*objects)[0], perlCookie, goCookie)
	}

	if *foreign != "" {
		fmt.Printf("\n=== /view permission denied ===\n")
		runViewForeignCase(t, cfg, client, *foreign, perlCookie, goCookie)
	} else {
		fmt.Printf("\n(skipping /view permission-denied case: no --foreign-object given)\n")
	}

	fmt.Printf("\n=== CORS preflight ===\n")
	runCORSCases(t, cfg, client)

	fmt.Printf("\n%d/%d cases passed\n", t.passed, t.total)
	if t.passed != t.total {
		fmt.Printf("failed: %s\n", strings.Join(t.failures, ", "))
		os.Exit(1)
	}
}

func loadToken(flagVal string) (*auth.Token, error) {
	if flagVal != "" {
		return &auth.Token{TokenString: flagVal}, nil
	}
	if env := os.Getenv("P3_TOKEN"); env != "" {
		return &auth.Token{TokenString: env}, nil
	}
	return auth.LoadToken()
}

type config struct {
	perlURL, goURL string
	token          *auth.Token
	verbose        bool
}

// ---- request/response plumbing --------------------------------------------

type sideResp struct {
	label   string
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
	err     error
}

func fetch(client *http.Client, label, method, rawURL string, hdr http.Header) sideResp {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return sideResp{label: label, err: fmt.Errorf("building request: %w", err)}
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return sideResp{label: label, err: fmt.Errorf("%s %s: %w", method, rawURL, err)}
	}
	defer resp.Body.Close()
	cookies := resp.Cookies()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return sideResp{label: label, status: resp.StatusCode, header: resp.Header, err: fmt.Errorf("reading body: %w", err)}
	}
	return sideResp{label: label, status: resp.StatusCode, header: resp.Header, body: body, cookies: cookies}
}

// joinURL appends a raw (unescaped) workspace-style path onto a base URL,
// letting url.URL handle escaping on Stringify -- workspace paths routinely
// contain "@" and spaces, and must reach the server undisturbed the way a
// browser's own URL bar would send them.
func joinURL(base, rawPath string) string {
	u, err := url.Parse(base)
	if err != nil {
		// base URLs come from flags the operator controls; fail loudly rather
		// than silently producing a broken request.
		panic(fmt.Sprintf("invalid base URL %q: %v", base, err))
	}
	u.Path = strings.TrimRight(u.Path, "/") + rawPath
	return u.String()
}

// ---- pass/fail bookkeeping --------------------------------------------------

type tally struct {
	total, passed int
	failures      []string
}

func (t *tally) record(name string, ok bool, detail string) {
	t.total++
	status := "PASS"
	if ok {
		t.passed++
	} else {
		status = "FAIL"
		t.failures = append(t.failures, name)
	}
	fmt.Printf("  [%s] %s\n", status, name)
	if !ok && detail != "" {
		fmt.Printf("         %s\n", detail)
	}
}

type compareOpts struct {
	// headers whose VALUE must match exactly between the two sides. Go's
	// http.Response parser canonicalizes header names on both sides (e.g.
	// "Content-type" and "Content-Type" both become "Content-Type"), so the
	// documented header-casing deviation between the two services needs no
	// special handling here -- comparing via Header.Get already looks past it.
	headers []string
	// headers that must be present on both sides or absent on both, without
	// comparing values -- for anything the two sides mint independently
	// (Date, Set-Cookie, and similar per-response/per-session values).
	presenceOnly []string
	compareBody  bool
}

func compare(cfg *config, t *tally, name string, perl, gor sideResp, opts compareOpts) {
	if perl.err != nil || gor.err != nil {
		t.record(name, false, fmt.Sprintf("perl err=%v go err=%v", perl.err, gor.err))
		return
	}

	var mismatches []string
	if perl.status != gor.status {
		mismatches = append(mismatches, fmt.Sprintf("status perl=%d go=%d", perl.status, gor.status))
	}
	for _, h := range opts.headers {
		pv, gv := perl.header.Get(h), gor.header.Get(h)
		if pv != gv {
			mismatches = append(mismatches, fmt.Sprintf("header %s perl=%q go=%q", h, pv, gv))
		}
	}
	for _, h := range opts.presenceOnly {
		pv, gv := perl.header.Get(h) != "", gor.header.Get(h) != ""
		if pv != gv {
			mismatches = append(mismatches, fmt.Sprintf("header %s presence perl=%v go=%v", h, pv, gv))
		}
	}
	if opts.compareBody {
		ps, gs := sha256.Sum256(perl.body), sha256.Sum256(gor.body)
		if ps != gs {
			mismatches = append(mismatches, fmt.Sprintf("body sha256 perl=%x (%d bytes) go=%x (%d bytes)",
				ps, len(perl.body), gs, len(gor.body)))
		}
	}

	ok := len(mismatches) == 0
	t.record(name, ok, strings.Join(mismatches, "; "))
	if !ok && cfg.verbose {
		dumpResponse("perl", perl)
		dumpResponse("go", gor)
	}
}

// dumpResponse prints a redacted response, matching the P3_DEBUG_HTTP
// convention documented in the top-level CLAUDE.md: never print
// Authorization/Cookie/Set-Cookie values, and cap the body preview at 2 KiB.
func dumpResponse(label string, r sideResp) {
	fmt.Printf("  --- %s: status=%d ---\n", label, r.status)
	for k, vs := range r.header {
		for _, v := range vs {
			if isSensitiveHeader(k) {
				v = fmt.Sprintf("<redacted, %d bytes>", len(v))
			}
			fmt.Printf("    %s: %s\n", k, v)
		}
	}
	body := r.body
	truncated := false
	if len(body) > debugBodyPreview {
		body = body[:debugBodyPreview]
		truncated = true
	}
	fmt.Printf("    body (%d bytes%s): %q\n", len(r.body), map[bool]string{true: ", truncated"}[truncated], body)
}

func isSensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "cookie", "set-cookie", "proxy-authorization", "x-auth-token":
		return true
	}
	return false
}

// ---- /download and /view for a single object -------------------------------

func runObjectCases(t *tally, cfg *config, client *http.Client, ws *workspace.Client, objPath string) {
	urls, err := ws.GetDownloadURL([]string{objPath})
	if err != nil || len(urls) == 0 {
		t.record(objPath+": get_download_url", false, fmt.Sprintf("%v", err))
		return
	}
	minted := urls[0]
	suffix := strings.TrimPrefix(minted, cfg.perlURL)
	if suffix == minted {
		t.record(objPath+": get_download_url", false,
			fmt.Sprintf("minted URL %q does not start with --perl-url %q; check --perl-url matches deploy.cfg's download-url-base", minted, cfg.perlURL))
		return
	}

	perlDL := cfg.perlURL + suffix
	goDL := cfg.goURL + suffix

	// Valid key, full body.
	perlResp := fetch(client, "perl", "GET", perlDL, nil)
	goResp := fetch(client, "go", "GET", goDL, nil)
	compare(cfg, t, objPath+": /download valid key", perlResp, goResp, compareOpts{
		headers:     []string{"Content-Disposition", "Content-Type"},
		compareBody: true,
	})

	// Bogus key: same name, garbage key, straight against the base URL rather
	// than the minted one.
	bogusPath := strings.Replace(suffix, extractKey(suffix), "0000000000000000000000000000000000000000", 1)
	compare(cfg, t, objPath+": /download bogus key",
		fetch(client, "perl", "GET", cfg.perlURL+bogusPath, nil),
		fetch(client, "go", "GET", cfg.goURL+bogusPath, nil),
		compareOpts{compareBody: true})

	// Range cases, sized off the valid response's real Content-Length.
	if perlResp.err == nil && goResp.err == nil {
		runRangeCases(t, cfg, client, objPath, perlDL, goDL, perlResp.header.Get("Content-Length"))
	}

	// /view happy path (uses the workspace path directly, not the minted URL).
	viewSuffix := "/view" + objPath
	compare(cfg, t, objPath+": /view happy path",
		fetch(client, "perl", "GET", joinURL(cfg.perlURL, viewSuffix), nil),
		fetch(client, "go", "GET", joinURL(cfg.goURL, viewSuffix), nil),
		compareOpts{headers: []string{"Content-Disposition", "Content-Type"}, compareBody: true})

	// /view on the object's parent directory -- always a folder.
	folderSuffix := "/view" + path.Dir(objPath)
	compare(cfg, t, objPath+": /view on containing folder",
		fetch(client, "perl", "GET", joinURL(cfg.perlURL, folderSuffix), nil),
		fetch(client, "go", "GET", joinURL(cfg.goURL, folderSuffix), nil),
		compareOpts{compareBody: true})
}

// extractKey pulls the download key out of a "/download/<key>/<name>" suffix
// -- get_download_url (WorkspaceImpl.pm:3198) always mints exactly this
// shape, so the key is always the second path segment. Used to build a
// bogus-key variant without hardcoding the route shape twice.
func extractKey(suffix string) string {
	parts := strings.Split(strings.TrimPrefix(suffix, "/"), "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func runRangeCases(t *tally, cfg *config, client *http.Client, objPath, perlDL, goDL, contentLength string) {
	size, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil || size < 5 {
		fmt.Printf("  (skipping Range cases for %s: Content-Length=%q too small or unparseable)\n", objPath, contentLength)
		return
	}

	cases := []struct {
		name  string
		value string
	}{
		{"bytes=0-0", "bytes=0-0"},
		{"bounded", fmt.Sprintf("bytes=1-%d", min64(3, size-1))},
		{"open-ended", fmt.Sprintf("bytes=%d-", size/2)},
		{"past-EOF", fmt.Sprintf("bytes=%d-", size+1000)},
	}
	for _, c := range cases {
		hdr := http.Header{"Range": {c.value}}
		compare(cfg, t, fmt.Sprintf("%s: /download Range %s (%s)", objPath, c.name, c.value),
			fetch(client, "perl", "GET", perlDL, hdr),
			fetch(client, "go", "GET", goDL, hdr),
			compareOpts{headers: []string{"Content-Range", "Content-Length"}, compareBody: true})
	}
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// ---- /set-cookie-auth -------------------------------------------------------

func runSetCookieAuthCases(t *tally, cfg *config, client *http.Client, tok *auth.Token) (perlCookie, goCookie *http.Cookie) {
	hdr := http.Header{"Authorization": {tok.TokenString}}
	perlResp := fetch(client, "perl", "POST", cfg.perlURL+"/set-cookie-auth", hdr)
	goResp := fetch(client, "go", "POST", cfg.goURL+"/set-cookie-auth", hdr)
	compare(cfg, t, "/set-cookie-auth valid token", perlResp, goResp, compareOpts{
		presenceOnly: []string{"Set-Cookie"},
	})
	perlCookie = firstSessionCookie(perlResp.cookies)
	goCookie = firstSessionCookie(goResp.cookies)

	// This is the run that answers PORT_STATUS.md's open question: what does
	// Perl's malformed-PSGI 403 path actually put on the wire for a token that
	// fails validation?
	badHdr := http.Header{"Authorization": {corruptSignature(tok.TokenString)}}
	compare(cfg, t, "/set-cookie-auth corrupted signature",
		fetch(client, "perl", "POST", cfg.perlURL+"/set-cookie-auth", badHdr),
		fetch(client, "go", "POST", cfg.goURL+"/set-cookie-auth", badHdr),
		compareOpts{})

	compare(cfg, t, "/set-cookie-auth no Authorization header",
		fetch(client, "perl", "POST", cfg.perlURL+"/set-cookie-auth", nil),
		fetch(client, "go", "POST", cfg.goURL+"/set-cookie-auth", nil),
		compareOpts{})

	return perlCookie, goCookie
}

func firstSessionCookie(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if c.Name == "bvbrc_ws_view_session" {
			return c
		}
	}
	return nil
}

// corruptSignature flips the last hex digit of a token's "sig=" value, so the
// signed data is unchanged but the signature no longer verifies -- a
// minimal, deliberate corruption rather than a syntactically bogus token.
func corruptSignature(tok string) string {
	idx := strings.LastIndex(tok, "sig=")
	if idx < 0 || idx+4 >= len(tok) {
		return tok + "|sig=0"
	}
	sigStart := idx + 4
	b := []byte(tok)
	if b[sigStart] == '0' {
		b[sigStart] = '1'
	} else {
		b[sigStart] = '0'
	}
	return string(b)
}

// ---- /view session-gated cases ----------------------------------------------

func runViewSessionCases(t *tally, cfg *config, client *http.Client, objPath string, perlCookie, goCookie *http.Cookie) {
	viewSuffix := "/view" + objPath

	if perlCookie != nil && goCookie != nil {
		compare(cfg, t, "/view with own session",
			fetch(client, "perl", "GET", joinURL(cfg.perlURL, viewSuffix), http.Header{"Cookie": {perlCookie.String()}}),
			fetch(client, "go", "GET", joinURL(cfg.goURL, viewSuffix), http.Header{"Cookie": {goCookie.String()}}),
			compareOpts{headers: []string{"Content-Type"}, compareBody: true})
	} else {
		fmt.Printf("  (skipping /view-with-session case: /set-cookie-auth did not return a session on both sides)\n")
	}

	badCookie := "bvbrc_ws_view_session=0000000000000000000000000000000000000000000000000000000000000000"
	compare(cfg, t, "/view with bad/unknown session",
		fetch(client, "perl", "GET", joinURL(cfg.perlURL, viewSuffix), http.Header{"Cookie": {badCookie}}),
		fetch(client, "go", "GET", joinURL(cfg.goURL, viewSuffix), http.Header{"Cookie": {badCookie}}),
		compareOpts{})
}

func runViewForeignCase(t *tally, cfg *config, client *http.Client, foreignPath string, perlCookie, goCookie *http.Cookie) {
	if perlCookie == nil || goCookie == nil {
		fmt.Printf("  (skipping: no session available on both sides)\n")
		return
	}
	viewSuffix := "/view" + foreignPath
	compare(cfg, t, "/view permission denied",
		fetch(client, "perl", "GET", joinURL(cfg.perlURL, viewSuffix), http.Header{"Cookie": {perlCookie.String()}}),
		fetch(client, "go", "GET", joinURL(cfg.goURL, viewSuffix), http.Header{"Cookie": {goCookie.String()}}),
		compareOpts{})
}

// ---- CORS preflight ----------------------------------------------------------

func runCORSCases(t *tally, cfg *config, client *http.Client) {
	hdr := http.Header{
		"Origin":                        {"https://example.org"},
		"Access-Control-Request-Method": {"GET"},
	}
	for _, route := range []string{"/download", "/view"} {
		compare(cfg, t, "CORS preflight "+route,
			fetch(client, "perl", "OPTIONS", cfg.perlURL+route, hdr),
			fetch(client, "go", "OPTIONS", cfg.goURL+route, hdr),
			compareOpts{headers: []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Credentials",
				"Access-Control-Expose-Headers",
				"Vary",
			}})
	}
}
