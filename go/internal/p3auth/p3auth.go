// Package p3auth ports the token-signature verification in
// p3_auth/lib/P3TokenValidator.pm, which is what /set-cookie-auth must run
// before it will hand out a session cookie
// (Bio/P3/Workspace/WorkspaceImpl.pm:1527-1534). Nothing in this tree did
// this before: internal/auth.Token.parseToken splits and reads a claim, but
// performs no signature or expiry check at all and must never be trusted to
// authenticate an inbound request.
//
// Two deliberate deviations from Perl, both load-bearing enough to call out
// here rather than just at the call site:
//
//   - Pubkeys are cached process-wide (Validator.cache, guarded by a mutex),
//     not per-Validator. Perl constructs a fresh P3TokenValidator for every
//     request (WorkspaceImpl.pm:1528), so its own 86400s cache never actually
//     hits and every /set-cookie-auth does a live HTTPS GET to the signer.
//     This is a latency improvement only -- the verification logic and its
//     failure modes are unchanged.
//   - Verification uses SHA-1 (rsa.VerifyPKCS1v15 with crypto.SHA1), matching
//     Crypt::OpenSSL::RSA's use_sha1_hash() (P3TokenValidator.pm:101). This
//     is required for interoperability with tokens already signed by the
//     existing infrastructure -- it is not a weakness introduced here, and
//     must not be "upgraded" without changing the signer side of the whole
//     BV-BRC auth system first.
package p3auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // required for compatibility -- see package doc
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// trustedSigners mirrors P3AuthConstants.pm's trust_token_signers constant
// (modules/p3_auth/lib/P3AuthConstants.pm:5) exactly -- FIVE entries. Two
// existing descriptions of this port, PORT_STATUS.md and PORT_PLAN.md
// (both predating this file), list only four and omit
// "https://user.beta.patricbrc.org/public_key". That was a documentation bug
// in this repo, not a discrepancy in the deployed Perl service -- copying
// the docs instead of the Perl source here would silently reject every
// beta-environment token. Comparison against SigningSubject is by exact
// string match, matching Perl's `$self->{token_signers}->{$signer}` hash
// lookup.
var trustedSigners = map[string]bool{
	"https://rast.nmpdr.org/goauth/keys":             true,
	"https://user.alpha.patricbrc.org/public_key":    true,
	"https://nexus.api.globusonline.org/goauth/keys": true,
	"https://user.patricbrc.org/public_key":          true,
	"https://user.beta.patricbrc.org/public_key":     true,
}

// DefaultCacheLifetime mirrors P3TokenValidator.pm:20 ($self->{cache_lifetime}
// = 86400).
const DefaultCacheLifetime = 86400 * time.Second

// DefaultHTTPTimeout mirrors P3TokenValidator::new's P3ClientUA::new_ua(timeout
// => 10) (P3TokenValidator.pm:15).
const DefaultHTTPTimeout = 10 * time.Second

// Claims is the parsed set of "|"-separated "k=v" pairs from a BV-BRC token
// string, with no verification performed. See ParseUnverified.
type Claims struct {
	Values map[string]string
}

// UserID returns the "un=" claim, the token's user id.
func (c Claims) UserID() string { return c.Values["un"] }

// parseSignedData recovers the exact bytes the signature in a token covers:
// everything before the LAST "|sig=" delimiter. Ports the first line of
// P3TokenValidator::validate (:32): `my($sig_data) = $token_str =~
// /^(.*)\|sig=/;` -- Perl's greedy .* backtracks to the rightmost "|sig=" in
// the string, which strings.LastIndex reproduces directly. ok is false when
// there is no such delimiter at all.
func parseSignedData(token string) (signedData string, ok bool) {
	idx := strings.LastIndex(token, "|sig=")
	if idx < 0 {
		return "", false
	}
	return token[:idx], true
}

// parseClaimValues splits token into its "|"-separated "k=v" pairs. Ports
// the second half of P3TokenValidator::validate (:39): `my %vars = map {
// split /=/ } split /\|/, $token->token();`. Perl's unlimited `split /=/`
// mangles a value containing "=" by flattening it into the surrounding
// hash-pair sequence and shifting every later key/value out of alignment;
// this uses strings.Cut (split on the FIRST "=" only) instead, which is
// strictly safer and unobservable for every claim this token format
// actually carries (none of un/sig/expiry/SigningSubject ever contains
// "="). A part with no "=" at all is silently skipped, matching Perl's
// `split /=/` on such a part producing a single-element list that leaves
// its "value" as the next part's key -- a corruption case that likewise
// never arises in a well-formed token.
func parseClaimValues(token string) map[string]string {
	values := make(map[string]string)
	for _, part := range strings.Split(token, "|") {
		k, v, found := strings.Cut(part, "=")
		if found {
			values[k] = v
		}
	}
	return values
}

// ParseUnverified parses token's claims WITHOUT checking its signature or
// expiry.
//
// This function performs NO verification. It must NEVER be used to
// authenticate an inbound request -- calling it and trusting the result is
// exactly the mistake internal/auth.Token.parseToken's doc comment warns
// against. It exists for /view, which only needs the user id embedded in a
// token that was already run through Validator.Validate once, at
// /set-cookie-auth time, and is now merely being read back out of a stored
// session record (Bio/P3/Workspace/WorkspaceImpl.pm:1641 does the same thing
// in Perl: it constructs a P3AuthToken from the session's stored auth_token
// and reads user_id straight off it, with no second call into
// P3TokenValidator).
//
// The only error this returns is a malformed token (no "|sig=" delimiter);
// it still does not mean the signature is valid.
func ParseUnverified(token string) (Claims, error) {
	if _, ok := parseSignedData(token); !ok {
		return Claims{}, errors.New("p3auth: malformed token (no |sig= delimiter)")
	}
	return Claims{Values: parseClaimValues(token)}, nil
}

// cachedKey is one entry in Validator's process-wide pubkey cache.
type cachedKey struct {
	key     *rsa.PublicKey
	expires time.Time
}

// Validator ports P3TokenValidator (P3TokenValidator.pm). The zero value is
// ready to use; all fields are optional overrides for testing.
type Validator struct {
	// HTTPClient is used to fetch signer pubkeys. Defaults to a client with
	// DefaultHTTPTimeout.
	HTTPClient *http.Client

	// CacheLifetime is how long a fetched pubkey is trusted before being
	// re-fetched. Defaults to DefaultCacheLifetime.
	CacheLifetime time.Duration

	// TrustedSigners overrides the default trusted-signer set, keyed by
	// exact SigningSubject URL. Nil means the package default (all five
	// production signers).
	TrustedSigners map[string]bool

	mu    sync.Mutex
	cache map[string]cachedKey
}

func (v *Validator) httpClient() *http.Client {
	if v.HTTPClient != nil {
		return v.HTTPClient
	}
	return &http.Client{Timeout: DefaultHTTPTimeout}
}

func (v *Validator) cacheLifetime() time.Duration {
	if v.CacheLifetime > 0 {
		return v.CacheLifetime
	}
	return DefaultCacheLifetime
}

func (v *Validator) trustedSigners() map[string]bool {
	if v.TrustedSigners != nil {
		return v.TrustedSigners
	}
	return trustedSigners
}

// getPubkey fetches (or returns the cached) RSA public key for signer,
// mirroring P3TokenValidator::get_pubkey (:69-106): GET the signer URL,
// expect JSON {"valid": bool, "pubkey": "<PEM>"}, parse and cache the key.
func (v *Validator) getPubkey(signer string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	if ent, ok := v.cache[signer]; ok && time.Now().Before(ent.expires) {
		v.mu.Unlock()
		return ent.key, nil
	}
	v.mu.Unlock()

	req, err := http.NewRequest(http.MethodGet, signer, nil)
	if err != nil {
		return nil, fmt.Errorf("p3auth: building request for %s: %w", signer, err)
	}
	resp, err := v.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("p3auth: fetching pubkey from %s: %w", signer, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("p3auth: %s returned status %s", signer, resp.Status)
	}

	var body struct {
		Valid  bool   `json:"valid"`
		Pubkey string `json:"pubkey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("p3auth: decoding response from %s: %w", signer, err)
	}
	if !body.Valid || body.Pubkey == "" {
		return nil, fmt.Errorf("p3auth: %s did not return a valid pubkey", signer)
	}

	pub, err := parseRSAPublicKeyPEM(body.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("p3auth: parsing pubkey from %s: %w", signer, err)
	}

	v.mu.Lock()
	if v.cache == nil {
		v.cache = make(map[string]cachedKey)
	}
	v.cache[signer] = cachedKey{key: pub, expires: time.Now().Add(v.cacheLifetime())}
	v.mu.Unlock()

	return pub, nil
}

// parseRSAPublicKeyPEM accepts both PEM forms Crypt::OpenSSL::RSA->
// new_public_key takes: PKCS#1 ("RSA PUBLIC KEY") and the more common PKIX/
// SubjectPublicKeyInfo ("PUBLIC KEY").
func parseRSAPublicKeyPEM(pemText string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("could not decode PEM block")
	}
	if block.Type == "RSA PUBLIC KEY" {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not RSA", pub)
	}
	return rsaPub, nil
}

// expiryOf returns the numeric "expiry" claim, or 0 if it is absent or not a
// valid integer. Perl's `time >= $vars{expiry}` numeric-coerces a missing
// (undef) or non-numeric expiry to 0, so the comparison always fails closed
// (now >= 0 is always true -> "Token expired"); returning 0 here reproduces
// that without relying on Go doing the same implicit coercion Perl does.
func expiryOf(values map[string]string) int64 {
	e, err := strconv.ParseInt(values["expiry"], 10, 64)
	if err != nil {
		return 0
	}
	return e
}

// Validate ports P3TokenValidator::validate (P3TokenValidator.pm:26-67).
// A nil error means the token's signature verified, has not expired, and was
// signed by a trusted signer. Every failure path returns a distinct,
// human-readable error, mirroring Perl's four rejection reasons (missing
// signature data, expired, unknown signer, retrieval/verification failure) --
// callers should log the error but must not expose it to the client (Perl's
// own /set-cookie-auth handler doesn't: it warns to STDERR and returns a
// fixed "Authentication failed" body regardless of which check failed).
func (v *Validator) Validate(token string) error {
	claims, err := ParseUnverified(token)
	if err != nil {
		return err
	}
	signedData, _ := parseSignedData(token) // ParseUnverified already confirmed ok

	if time.Now().Unix() >= expiryOf(claims.Values) {
		return errors.New("p3auth: token expired")
	}

	signer := claims.Values["SigningSubject"]
	if !v.trustedSigners()[signer] {
		return fmt.Errorf("p3auth: token signed by unknown signer %q", signer)
	}

	pub, err := v.getPubkey(signer)
	if err != nil {
		return fmt.Errorf("p3auth: could not retrieve signer pubkey for %s: %w", signer, err)
	}

	sigBytes, err := hex.DecodeString(claims.Values["sig"])
	if err != nil {
		return errors.New("p3auth: token signature is not valid hex")
	}

	sum := sha1.Sum([]byte(signedData)) //nolint:gosec // required for compatibility -- see package doc
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, sum[:], sigBytes); err != nil {
		return errors.New("p3auth: token signature did not verify")
	}

	return nil
}
