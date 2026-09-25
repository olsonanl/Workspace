package wsresolve

import "testing"

func TestEscapeUsernameForMongo(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"olson@patricbrc.org", "olson@patricbrc%2Eorg"},
		{"bob$dollar@x.y", "bob%24dollar@x%2Ey"},
		{"noescape@needed", "noescape@needed"},
		{"", ""},
	} {
		if got := EscapeUsernameForMongo(tc.in); got != tc.want {
			t.Errorf("EscapeUsernameForMongo(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnescapeUsernameForMongo(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"olson@patricbrc%2Eorg", "olson@patricbrc.org"},
		{"bob%24dollar@x%2Ey", "bob$dollar@x.y"},
		{"noescape@needed", "noescape@needed"},
		// EscapeUsernameForMongo always emits uppercase hex, but the store
		// unescapes data written over the service's history -- accept
		// lowercase hex too.
		{"olson@patricbrc%2eorg", "olson@patricbrc.org"},
	} {
		if got := UnescapeUsernameForMongo(tc.in); got != tc.want {
			t.Errorf("UnescapeUsernameForMongo(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEscapeUnescapeRoundTrip(t *testing.T) {
	for _, name := range []string{
		"olson@patricbrc.org",
		"a.b.c@d.e.org",
		"bob$@x.org",
		"plainuser",
	} {
		got := UnescapeUsernameForMongo(EscapeUsernameForMongo(name))
		if got != name {
			t.Errorf("round trip for %q produced %q", name, got)
		}
	}
}

// The escape/unescape pair is NOT a true inverse in Perl -- unescape is a
// blanket percent-decoder, escape touches only "." and "$". This package
// deliberately does not reproduce that asymmetry (see escape.go's doc
// comments): a literal "%" followed by two hex digits in a username passes
// through EscapeUsernameForMongo unchanged and is only decoded by
// UnescapeUsernameForMongo if it happens to spell "%2E" or "%24". Document
// the chosen (safer) behavior with a concrete case.
func TestUnescapeDoesNotDecodeArbitraryPercentEscapes(t *testing.T) {
	in := "100%25done@x.org" // contains a pre-existing "%25" (a literal '%')
	got := UnescapeUsernameForMongo(in)
	want := "100%25done@x.org" // unchanged: "%25" is not "%2E" or "%24"
	if got != want {
		t.Errorf("UnescapeUsernameForMongo(%q) = %q, want %q (only %%2E/%%24 are decoded)", in, got, want)
	}
}
