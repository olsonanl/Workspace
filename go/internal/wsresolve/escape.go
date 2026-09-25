package wsresolve

import "strings"

// EscapeUsernameForMongo ports _escape_username_for_mongo
// (WorkspaceImpl.pm:454-459): uri_escape($name, '.\$'). MongoDB (in
// particular the server version this deployment runs, 3.4) forbids "." and
// "$" in field names, and every BV-BRC username has a "." in its domain
// (e.g. "olson@patricbrc.org"), so the `workspaces.permissions` map --
// itself a Mongo document keyed by username -- stores keys with those two
// characters percent-escaped: "olson@patricbrc%2Eorg". "@" is legal in a
// Mongo field name and is deliberately left alone.
//
// This is intentionally a strict two-character substitution, not a call
// into net/url or an equivalent general percent-encoder: see
// UnescapeUsernameForMongo for why a general decoder is not this function's
// true inverse, and would silently corrupt a username containing a literal
// "%" followed by two hex digits.
func EscapeUsernameForMongo(name string) string {
	name = strings.ReplaceAll(name, "$", "%24")
	name = strings.ReplaceAll(name, ".", "%2E")
	return name
}

// UnescapeUsernameForMongo ports _unescape_username_for_mongo
// (WorkspaceImpl.pm:461-466). In Perl this is uri_unescape($name) -- a
// BLANKET percent-decoder, not the inverse of the two-character escape
// above. _get_db_ws (:253) calls it on every key of every workspace's
// `permissions` map on every read, which is why every in-memory Workspace
// value in this package must carry plain usernames: EffectivePermission's
// map lookup is only correct because the caller (the store) has already
// unescaped the keys it read from Mongo.
//
// Implemented here as the exact matching two-character reversal ("%2E"->".",
// "%24"->"$", case-insensitive hex, since EscapeUsernameForMongo always
// produces uppercase but real historical data is not guaranteed to) rather
// than a general percent-decoder. This is a deliberate, documented departure
// from Perl's uri_unescape: the escape/unescape pair in Perl is not a true
// round trip (escape touches only "." and "$"; unescape decodes every
// "%XX"), and a real BV-BRC username never contains a literal "%", so the
// strict form and the Perl form agree on every value this ever actually
// sees while being an honest inverse of the escape above.
func UnescapeUsernameForMongo(name string) string {
	name = replaceFold(name, "%2E", ".")
	name = replaceFold(name, "%24", "$")
	return name
}

// replaceFold replaces every case-insensitive occurrence of old with new.
func replaceFold(s, old, new string) string {
	var b strings.Builder
	for {
		i := strings.Index(strings.ToUpper(s), strings.ToUpper(old))
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		b.WriteString(new)
		s = s[i+len(old):]
	}
	return b.String()
}
