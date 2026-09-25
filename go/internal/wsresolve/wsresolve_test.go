package wsresolve

import "testing"

const testUUID = "2f83bd7d-5a60-4f5a-a565-0b5bd619a29b"

func TestParseWSPathUserWorkspaceForms(t *testing.T) {
	for _, tc := range []struct {
		name, input        string
		wantUser, wantWS   string
		wantPath, wantName string
	}{
		{"workspace root", "/bob/home", "bob", "home", "", ""},
		{"trailing slash, still root", "/bob/home/", "bob", "home", "", ""},
		{"collapsed slash runs", "/bob/home///", "bob", "home", "", ""},
		{"one file", "/bob/home/f.txt", "bob", "home", "", "f.txt"},
		{"trailing slash does NOT mark a directory", "/bob/home/dir/", "bob", "home", "", "dir"},
		{"greedy path, multiple segments", "/bob/home/a/b/c", "bob", "home", "a/b", "c"},
		{"path is a single segment", "/bob/home/a/b/", "bob", "home", "a", "b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseWSPath(tc.input)
			if err != nil {
				t.Fatalf("ParseWSPath(%q): %v", tc.input, err)
			}
			if got.Kind != KindUserWorkspace {
				t.Fatalf("Kind = %v, want KindUserWorkspace", got.Kind)
			}
			if got.User != tc.wantUser || got.Workspace != tc.wantWS || got.Path != tc.wantPath || got.Name != tc.wantName {
				t.Errorf("ParseWSPath(%q) = %+v, want User=%q Workspace=%q Path=%q Name=%q",
					tc.input, got, tc.wantUser, tc.wantWS, tc.wantPath, tc.wantName)
			}
		})
	}
}

func TestParseWSPathNoMatch(t *testing.T) {
	for _, input := range []string{
		"/bob",    // only one segment
		"",        // empty
		"foo",     // no leading slash
		"foo/bar", // no leading slash
		"/",       // nothing after the slash
	} {
		t.Run(input, func(t *testing.T) {
			_, err := ParseWSPath(input)
			if err != ErrNoMatch {
				t.Errorf("ParseWSPath(%q) err = %v, want ErrNoMatch", input, err)
			}
		})
	}
}

func TestParseWSPathWorkspaceUUIDForms(t *testing.T) {
	for _, tc := range []struct {
		name, input        string
		wantPath, wantName string
	}{
		{"uuid only", "/_uuid/" + testUUID, "", ""},
		{"uuid only, trailing slash", "/_uuid/" + testUUID + "/", "", ""},
		{"uuid plus name", "/_uuid/" + testUUID + "/name.txt", "", "name.txt"},
		{"uuid plus path and name", "/_uuid/" + testUUID + "/a/b/name.txt", "a/b", "name.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseWSPath(tc.input)
			if err != nil {
				t.Fatalf("ParseWSPath(%q): %v", tc.input, err)
			}
			if got.Kind != KindWorkspaceUUID {
				t.Fatalf("Kind = %v, want KindWorkspaceUUID", got.Kind)
			}
			if got.WorkspaceUUID != testUUID {
				t.Errorf("WorkspaceUUID = %q, want %q", got.WorkspaceUUID, testUUID)
			}
			if got.Path != tc.wantPath || got.Name != tc.wantName {
				t.Errorf("ParseWSPath(%q) Path=%q Name=%q, want Path=%q Name=%q",
					tc.input, got.Path, got.Name, tc.wantPath, tc.wantName)
			}
		})
	}
}

func TestParseWSPathBareObjectUUID(t *testing.T) {
	got, err := ParseWSPath(testUUID)
	if err != nil {
		t.Fatalf("ParseWSPath(%q): %v", testUUID, err)
	}
	if got.Kind != KindObjectUUID || got.ObjectUUID != testUUID {
		t.Errorf("ParseWSPath(%q) = %+v, want KindObjectUUID with ObjectUUID=%q", testUUID, got, testUUID)
	}
}

func TestParseWSPathUppercaseUUID(t *testing.T) {
	upper := "2F83BD7D-5A60-4F5A-A565-0B5BD619A29B"
	got, err := ParseWSPath(upper)
	if err != nil || got.Kind != KindObjectUUID {
		t.Errorf("ParseWSPath(%q) = %+v, err=%v, want KindObjectUUID (regex is case-insensitive)", upper, got, err)
	}
}

func TestEffectivePermission(t *testing.T) {
	for _, tc := range []struct {
		name string
		ws   *Workspace
		user string
		want Perm
	}{
		{
			"nil workspace",
			nil, "bob", PermNone,
		},
		{
			"published workspace short-circuits before the owner check",
			&Workspace{Owner: "bob", GlobalPermission: PermPublished}, "bob", PermPublished,
		},
		{
			"owner of a non-published workspace",
			&Workspace{Owner: "bob", GlobalPermission: PermNone}, "bob", PermOwner,
		},
		{
			"non-owner, no grant, falls back to global",
			&Workspace{Owner: "bob", GlobalPermission: PermRead}, "alice", PermRead,
		},
		{
			"non-owner, grant exceeds global",
			&Workspace{Owner: "bob", GlobalPermission: PermNone, Permissions: map[string]Perm{"alice": PermWrite}},
			"alice", PermWrite,
		},
		{
			"non-owner, grant does not exceed global, global wins",
			&Workspace{Owner: "bob", GlobalPermission: PermWrite, Permissions: map[string]Perm{"alice": PermRead}},
			"alice", PermWrite,
		},
		{
			"non-owner, grant equals global weight, global wins (strict > in Perl)",
			&Workspace{Owner: "bob", GlobalPermission: PermRead, Permissions: map[string]Perm{"alice": PermPublished}},
			"alice", PermRead,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectivePermission(tc.ws, tc.user)
			if got != tc.want {
				t.Errorf("EffectivePermission(...) = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPermAtLeast(t *testing.T) {
	for _, tc := range []struct {
		p, min Perm
		want   bool
	}{
		{PermNone, PermRead, false},
		{PermPublished, PermRead, true}, // p and r carry the same weight
		{PermRead, PermPublished, true},
		{PermRead, PermRead, true},
		{PermRead, PermWrite, false},
		{PermOwner, PermAdmin, true},
		{PermWrite, PermOwner, false},
	} {
		if got := tc.p.AtLeast(tc.min); got != tc.want {
			t.Errorf("%q.AtLeast(%q) = %v, want %v", tc.p, tc.min, got, tc.want)
		}
	}
}
