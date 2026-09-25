package p3auth

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
	"strings"
	"testing"
	"time"
)

const testSigner = "https://signer.example.test/public_key"

// testKeyPair generates an RSA key and returns it PEM-encoded in the given
// form ("PUBLIC KEY" for PKIX, "RSA PUBLIC KEY" for PKCS#1), plus a function
// to sign arbitrary data with it the same way the real signer does
// (SHA-1 + PKCS1v15).
func testKeyPair(t *testing.T, pemType string) (priv *rsa.PrivateKey, pemText string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	var der []byte
	switch pemType {
	case "RSA PUBLIC KEY":
		der = x509.MarshalPKCS1PublicKey(&key.PublicKey)
	case "PUBLIC KEY":
		var err error
		der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("marshaling public key: %v", err)
		}
	default:
		t.Fatalf("unknown pem type %q", pemType)
	}
	block := &pem.Block{Type: pemType, Bytes: der}
	return key, string(pem.EncodeToMemory(block))
}

func sign(t *testing.T, priv *rsa.PrivateKey, data string) string {
	t.Helper()
	sum := sha1.Sum([]byte(data)) //nolint:gosec // matching the production algorithm under test
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, sum[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return hex.EncodeToString(sig)
}

// buildToken assembles a token in the same shape validate() expects:
// "|"-separated k=v pairs ending in "|sig=<hex>", with the signature
// covering everything before "|sig=".
func buildToken(t *testing.T, priv *rsa.PrivateKey, extra ...string) string {
	t.Helper()
	fields := append([]string{}, extra...)
	signedData := strings.Join(fields, "|")
	sig := sign(t, priv, signedData)
	return signedData + "|sig=" + sig
}

// fakeSigner serves {"valid":true,"pubkey":"<PEM>"} and counts how many times
// it was hit, so tests can assert the process-wide cache actually avoids a
// refetch.
type fakeSigner struct {
	srv      *httptest.Server
	hits     int
	pemText  string
	validKey bool
}

func newFakeSigner(pemText string) *fakeSigner {
	fs := &fakeSigner{pemText: pemText, validKey: true}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.hits++
		fmt.Fprintf(w, `{"valid":%v,"pubkey":%q}`, fs.validKey, fs.pemText)
	}))
	return fs
}

func (fs *fakeSigner) Close() { fs.srv.Close() }

func validatorFor(fs *fakeSigner) *Validator {
	return &Validator{TrustedSigners: map[string]bool{fs.srv.URL: true}}
}

func futureExpiry() string {
	return strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
}

func pastExpiry() string {
	return strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
}

func TestValidateAcceptsAValidToken(t *testing.T) {
	for _, pemType := range []string{"PUBLIC KEY", "RSA PUBLIC KEY"} {
		t.Run(pemType, func(t *testing.T) {
			priv, pemText := testKeyPair(t, pemType)
			fs := newFakeSigner(pemText)
			defer fs.Close()

			token := buildToken(t, priv, "un=bob@patricbrc.org", "expiry="+futureExpiry(), "SigningSubject="+fs.srv.URL)

			v := validatorFor(fs)
			if err := v.Validate(token); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestValidateCachesThePubkey(t *testing.T) {
	priv, pemText := testKeyPair(t, "PUBLIC KEY")
	fs := newFakeSigner(pemText)
	defer fs.Close()

	v := validatorFor(fs)
	for i := 0; i < 2; i++ {
		token := buildToken(t, priv, "un=bob@patricbrc.org", "expiry="+futureExpiry(), "SigningSubject="+fs.srv.URL)
		if err := v.Validate(token); err != nil {
			t.Fatalf("validation %d: %v", i, err)
		}
	}
	if fs.hits != 1 {
		t.Errorf("signer was fetched %d times, want 1 (the pubkey should be cached across validations)", fs.hits)
	}
}

func TestValidateRejectsExpiredToken(t *testing.T) {
	priv, pemText := testKeyPair(t, "PUBLIC KEY")
	fs := newFakeSigner(pemText)
	defer fs.Close()

	token := buildToken(t, priv, "un=bob@patricbrc.org", "expiry="+pastExpiry(), "SigningSubject="+fs.srv.URL)
	if err := validatorFor(fs).Validate(token); err == nil {
		t.Error("Validate() = nil, want an error for an expired token")
	}
}

func TestValidateRejectsMissingExpiry(t *testing.T) {
	priv, pemText := testKeyPair(t, "PUBLIC KEY")
	fs := newFakeSigner(pemText)
	defer fs.Close()

	// No "expiry=" field at all -- must fail closed (Perl: undef coerces to
	// 0, so `time >= 0` is always true).
	token := buildToken(t, priv, "un=bob@patricbrc.org", "SigningSubject="+fs.srv.URL)
	if err := validatorFor(fs).Validate(token); err == nil {
		t.Error("Validate() = nil, want an error when expiry is missing (must fail closed)")
	}
}

func TestValidateRejectsUnknownSigner(t *testing.T) {
	priv, pemText := testKeyPair(t, "PUBLIC KEY")
	fs := newFakeSigner(pemText)
	defer fs.Close()

	token := buildToken(t, priv, "un=bob@patricbrc.org", "expiry="+futureExpiry(), "SigningSubject=https://not-trusted.example/keys")
	if err := validatorFor(fs).Validate(token); err == nil {
		t.Error("Validate() = nil, want an error for an untrusted signer")
	}
}

func TestValidateRejectsTamperedSignature(t *testing.T) {
	priv, pemText := testKeyPair(t, "PUBLIC KEY")
	fs := newFakeSigner(pemText)
	defer fs.Close()

	token := buildToken(t, priv, "un=bob@patricbrc.org", "expiry="+futureExpiry(), "SigningSubject="+fs.srv.URL)
	// Flip the claimed user without re-signing.
	tampered := strings.Replace(token, "un=bob@patricbrc.org", "un=eve@patricbrc.org", 1)

	if err := validatorFor(fs).Validate(tampered); err == nil {
		t.Error("Validate() = nil, want an error for a tampered token")
	}
}

func TestValidateRejectsMissingSigDelimiter(t *testing.T) {
	v := &Validator{}
	if err := v.Validate("un=bob@patricbrc.org|expiry=9999999999"); err == nil {
		t.Error("Validate() = nil, want an error when there is no |sig= at all")
	}
}

func TestValidateRejectsSignerReportingInvalid(t *testing.T) {
	priv, pemText := testKeyPair(t, "PUBLIC KEY")
	fs := newFakeSigner(pemText)
	fs.validKey = false
	defer fs.Close()

	token := buildToken(t, priv, "un=bob@patricbrc.org", "expiry="+futureExpiry(), "SigningSubject="+fs.srv.URL)
	if err := validatorFor(fs).Validate(token); err == nil {
		t.Error("Validate() = nil, want an error when the signer reports valid:false")
	}
}

func TestParseUnverifiedReturnsUserID(t *testing.T) {
	claims, err := ParseUnverified("un=bob@patricbrc.org|expiry=123|SigningSubject=https://x/keys|sig=deadbeef")
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if got := claims.UserID(); got != "bob@patricbrc.org" {
		t.Errorf("UserID() = %q, want %q", got, "bob@patricbrc.org")
	}
}

// ParseUnverified performs no verification at all -- an unsigned, garbage
// signature, or wrong-signer token still parses successfully as long as the
// "|sig=" delimiter is present. This is the point: it exists for reading an
// already-authenticated session's stored token, not for authenticating a
// fresh request.
func TestParseUnverifiedDoesNotCheckAnything(t *testing.T) {
	claims, err := ParseUnverified("un=anyone|expiry=1|SigningSubject=nonsense|sig=not-even-hex")
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if claims.UserID() != "anyone" {
		t.Errorf("UserID() = %q, want %q", claims.UserID(), "anyone")
	}
}

func TestParseUnverifiedRejectsMissingSigDelimiter(t *testing.T) {
	if _, err := ParseUnverified("un=bob|expiry=1"); err == nil {
		t.Error("ParseUnverified() = nil error, want an error for a token with no |sig=")
	}
}

// Greedy match: if a value happens to contain the literal substring "|sig=",
// the LAST occurrence is what delimits the signed data, matching Perl's
// greedy regex.
func TestParseSignedDataUsesLastDelimiter(t *testing.T) {
	token := "note=contains|sig=embedded|real|sig=abc123"
	got, ok := parseSignedData(token)
	if !ok {
		t.Fatal("parseSignedData: ok = false, want true")
	}
	want := "note=contains|sig=embedded|real"
	if got != want {
		t.Errorf("parseSignedData(%q) = %q, want %q", token, got, want)
	}
}
