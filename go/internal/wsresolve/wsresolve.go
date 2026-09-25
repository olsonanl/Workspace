// Package wsresolve is a pure, dependency-free port of the Workspace path
// parsing and permission logic in Bio/P3/Workspace/WorkspaceImpl.pm --
// specifically _parse_ws_path (:469), _get_ws_permission (:405) and
// _check_ws_permissions (:431). It has no Mongo dependency and does no I/O:
// callers (today, go/internal/dlservice's /view handler; eventually a full
// Go port of the Workspace RPC service) own resolving the UUID forms and the
// object lookup against whatever store they use.
//
// Everything here is ported deliberately, warts included. Where Perl's
// behavior looks like a bug, the comment says so and cites the Perl line
// rather than "fixing" it -- a fix here would silently diverge from the
// service this is meant to be interchangeable with.
package wsresolve

import (
	"errors"
	"regexp"
)

// Perm is one of the six single-letter Workspace permission levels
// (WorkspaceImpl.pm:414-421, :437-444). Note "p" (published) and "r" (read)
// carry the same numeric weight -- they are different letters for different
// reasons (global default vs. an explicit per-user grant) but grant the same
// access.
type Perm string

const (
	PermNone      Perm = "n"
	PermPublished Perm = "p"
	PermRead      Perm = "r"
	PermWrite     Perm = "w"
	PermAdmin     Perm = "a"
	PermOwner     Perm = "o"
)

// permWeight mirrors the numeric ladder both _get_ws_permission and
// _check_ws_permissions build locally in Perl: n=0, p=1, r=1, w=2, a=3, o=4.
var permWeight = map[Perm]int{
	PermNone:      0,
	PermPublished: 1,
	PermRead:      1,
	PermWrite:     2,
	PermAdmin:     3,
	PermOwner:     4,
}

// AtLeast reports whether p grants at least min's level of access, per the
// numeric ladder in permWeight. Unlike Perl's _check_ws_permissions, an
// unrecognized Perm value cannot occur here (the type is closed to the six
// constants above), so there is no equivalent of Perl's fail-open behavior
// on a typo'd permission string ($values->{$minperm} being undef, and N <
// undef being false).
func (p Perm) AtLeast(min Perm) bool {
	return permWeight[p] >= permWeight[min]
}

// Workspace is the subset of a `workspaces` Mongo document that permission
// checking needs. Permissions must be keyed by plain, unescaped usernames --
// see UnescapeUsernameForMongo and the store that owns decoding the on-disk
// document into this shape.
type Workspace struct {
	UUID             string
	Owner            string
	Name             string
	GlobalPermission Perm
	Permissions      map[string]Perm
}

// EffectivePermission ports _get_ws_permission (WorkspaceImpl.pm:405-428).
//
// The order of checks is preserved exactly and is significant: a published
// workspace's global permission short-circuits BEFORE the owner check, so
// the owner of their own published workspace gets PermPublished (weight 1),
// not PermOwner (weight 4). This is documented upstream as a wart, not
// fixed here: WorkspaceImpl.pm's set_permissions (:4156) works around it
// with its own explicit owner test rather than calling _check_ws_permissions
// at all. It is harmless for a read check (PermPublished and PermRead carry
// the same weight) but would silently break a write check built the same
// way -- do not "correct" this ordering if this function is ever used for
// one.
//
// A nil ws (workspace not found) returns PermNone, matching the net effect
// of Perl's undef-safe-by-accident path through the same comparisons (see
// the Perl source for the play-by-play); the caller should already have
// turned "workspace not found" into an error before it gets here.
func EffectivePermission(ws *Workspace, currentUser string) Perm {
	if ws == nil {
		return PermNone
	}
	if ws.GlobalPermission == PermPublished {
		return PermPublished
	}
	if ws.Owner == currentUser {
		return PermOwner
	}
	if grant, ok := ws.Permissions[currentUser]; ok {
		if permWeight[grant] > permWeight[ws.GlobalPermission] {
			return grant
		}
	}
	return ws.GlobalPermission
}

// uuidPattern is WorkspaceImpl.pm's UUID regex, byte-for-byte
// (WorkspaceImpl.pm:479 and the three /_uuid/ patterns at :485,:489,:493):
// standard 8-4-4-4-12 hex, case-insensitive.
const uuidPattern = `[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}`

var (
	slashesRE = regexp.MustCompile(`/+`)

	objectUUIDRE = regexp.MustCompile(`^` + uuidPattern + `$`)

	wsUUIDOnlyRE = regexp.MustCompile(`^/_uuid/(` + uuidPattern + `)/*$`)
	wsUUIDNameRE = regexp.MustCompile(`^/_uuid/(` + uuidPattern + `)/([^/]+)/*$`)
	wsUUIDPathRE = regexp.MustCompile(`^/_uuid/(` + uuidPattern + `)/(.+)/([^/]+)/*$`)

	userWsOnlyRE = regexp.MustCompile(`^/([^/]+)/([^/]+)/*$`)
	userWsNameRE = regexp.MustCompile(`^/([^/]+)/([^/]+)/([^/]+)/*$`)
	userWsPathRE = regexp.MustCompile(`^/([^/]+)/([^/]+)/(.+)/([^/]+)/*$`)
)

// Kind discriminates which of _parse_ws_path's three accepted input classes
// matched.
type Kind int

const (
	// KindUserWorkspace: input was /<user>/<ws>[/<path>/]<name>. User and
	// Workspace are ready to use directly; no DB lookup is needed to
	// interpret the parse itself (looking up the *workspace record* for
	// that user/name pair is still the caller's job).
	KindUserWorkspace Kind = iota

	// KindWorkspaceUUID: input was /_uuid/<ws-uuid>[/...]. Perl resolves
	// this via _wscache("_uuid", $uuid) (WorkspaceImpl.pm:486,490,494) --
	// this package has no store dependency, so the caller must look up
	// WorkspaceUUID itself (e.g. Store.FindWorkspaceByUUID) before it has an
	// owner/name to work with.
	KindWorkspaceUUID

	// KindObjectUUID: input was a bare object UUID with no other structure
	// (WorkspaceImpl.pm:479-482). The caller resolves ObjectUUID directly
	// against the objects collection; there is no separate path/name to
	// combine, since the object's own workspace/path/name come back from
	// that lookup. Unreachable from the /view route specifically (its input
	// always has a leading "/" once the mount prefix is stripped), but part
	// of the port for callers that pass a bare UUID directly.
	KindObjectUUID
)

// Result is the parse of one workspace path, discriminated by Kind. Fields
// not documented as valid for the result's Kind are zero.
type Result struct {
	Kind Kind

	User, Workspace string // KindUserWorkspace
	WorkspaceUUID   string // KindWorkspaceUUID
	ObjectUUID      string // KindObjectUUID

	// Path and Name are valid for KindUserWorkspace and KindWorkspaceUUID.
	// Both are "" when absent from the input -- Perl never distinguishes
	// "absent" from "present but empty", and neither does this.
	Path, Name string
}

// ErrNoMatch is returned when input matches none of _parse_ws_path's
// accepted shapes. Perl falls off the end of the function in this case and
// returns an empty list, which the caller (_lookup_ws_file_details:1786-1788)
// catches one line later and dies on; the HTTP layer turns that into a 404.
// Callers here should do the same.
var ErrNoMatch = errors.New("wsresolve: path does not match any accepted shape")

// ParseWSPath ports _parse_ws_path (WorkspaceImpl.pm:469-507).
//
// Behaviors worth calling out because they are easy to get wrong porting
// from the regex cascade:
//
//   - A trailing slash does NOT mark a directory: "/bob/home/dir/" parses to
//     Name="dir", Path="" -- the trailing "/*" in every pattern is consumed
//     and discarded, not treated as structure.
//   - The path-capturing patterns use a greedy (.+), so "/bob/home/a/b/c"
//     parses to Path="a/b", Name="c": everything between the workspace name
//     and the final segment.
//   - Runs of "/" are collapsed to one before matching (Perl does this twice,
//     redundantly; once is enough since nothing after the first pass can
//     reintroduce a run).
//   - An input with no leading "/" (and that isn't a bare object UUID)
//     matches nothing: ErrNoMatch.
func ParseWSPath(input string) (Result, error) {
	input = slashesRE.ReplaceAllString(input, "/")

	if objectUUIDRE.MatchString(input) {
		return Result{Kind: KindObjectUUID, ObjectUUID: input}, nil
	}

	if m := wsUUIDOnlyRE.FindStringSubmatch(input); m != nil {
		return Result{Kind: KindWorkspaceUUID, WorkspaceUUID: m[1]}, nil
	}
	if m := wsUUIDNameRE.FindStringSubmatch(input); m != nil {
		return Result{Kind: KindWorkspaceUUID, WorkspaceUUID: m[1], Name: m[2]}, nil
	}
	if m := wsUUIDPathRE.FindStringSubmatch(input); m != nil {
		return Result{Kind: KindWorkspaceUUID, WorkspaceUUID: m[1], Path: m[2], Name: m[3]}, nil
	}

	if m := userWsOnlyRE.FindStringSubmatch(input); m != nil {
		return Result{Kind: KindUserWorkspace, User: m[1], Workspace: m[2]}, nil
	}
	if m := userWsNameRE.FindStringSubmatch(input); m != nil {
		return Result{Kind: KindUserWorkspace, User: m[1], Workspace: m[2], Name: m[3]}, nil
	}
	if m := userWsPathRE.FindStringSubmatch(input); m != nil {
		return Result{Kind: KindUserWorkspace, User: m[1], Workspace: m[2], Path: m[3], Name: m[4]}, nil
	}

	return Result{}, ErrNoMatch
}
