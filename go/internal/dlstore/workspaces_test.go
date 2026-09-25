package dlstore

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/BV-BRC/Workspace/go/internal/wsresolve"
)

// Decoding must tolerate the real document shape _create_workspace writes
// (WorkspaceImpl.pm:1097-1104), including permission keys still
// Mongo-escaped.
func TestDecodeWorkspaceRecord(t *testing.T) {
	raw, err := bson.Marshal(bson.D{
		{Key: "uuid", Value: "2F83BD7D-5A60-4F5A-A565-0B5BD619A29B"},
		{Key: "name", Value: "home"},
		{Key: "owner", Value: "olson@patricbrc.org"},
		{Key: "creation_date", Value: "2026-09-25T12:00:00Z"}, // string, NOT a BSON date
		{Key: "global_permission", Value: "n"},
		{Key: "permissions", Value: bson.D{
			{Key: "alice@patricbrc%2Eorg", Value: "r"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var w Workspace
	if err := bson.Unmarshal(raw, &w); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if w.UUID != "2F83BD7D-5A60-4F5A-A565-0B5BD619A29B" || w.Owner != "olson@patricbrc.org" {
		t.Errorf("UUID/Owner = %q/%q", w.UUID, w.Owner)
	}
	if w.GlobalPermission != wsresolve.PermNone {
		t.Errorf("GlobalPermission = %q, want %q", w.GlobalPermission, wsresolve.PermNone)
	}
	// Permissions is decoded RAW here -- keys are still escaped. Unescaping
	// happens in toResolveWorkspace, tested separately below.
	if w.Permissions["alice@patricbrc%2Eorg"] != "r" {
		t.Errorf("raw Permissions map = %+v, want the escaped key to survive decode unchanged", w.Permissions)
	}
}

// toResolveWorkspace is what every FindWorkspace* caller actually receives:
// permission keys unescaped, mirroring _get_db_ws's unconditional unescape
// on every read (WorkspaceImpl.pm:243-256).
func TestToResolveWorkspaceUnescapesPermissionKeys(t *testing.T) {
	w := &Workspace{
		UUID:             "u",
		Name:             "home",
		Owner:            "olson@patricbrc.org",
		GlobalPermission: wsresolve.PermRead,
		Permissions: map[string]string{
			"alice@patricbrc%2Eorg": "w",
			"bob%24x@y%2Eorg":       "a",
		},
	}
	got := w.toResolveWorkspace()

	if got.Owner != w.Owner || got.GlobalPermission != w.GlobalPermission {
		t.Errorf("Owner/GlobalPermission not carried through: %+v", got)
	}
	if got.Permissions["alice@patricbrc.org"] != wsresolve.PermWrite {
		t.Errorf("Permissions[%q] = %q, want %q (unescaped key)", "alice@patricbrc.org", got.Permissions["alice@patricbrc.org"], wsresolve.PermWrite)
	}
	if got.Permissions["bob$x@y.org"] != wsresolve.PermAdmin {
		t.Errorf("Permissions[%q] = %q, want %q (unescaped key)", "bob$x@y.org", got.Permissions["bob$x@y.org"], wsresolve.PermAdmin)
	}
	// The escaped forms must NOT still be present -- a caller that
	// accidentally looked up the escaped key would silently deny access.
	if _, ok := got.Permissions["alice@patricbrc%2Eorg"]; ok {
		t.Error("escaped key survived into the resolved workspace's Permissions map")
	}
}

// Decoding must tolerate the real document shape _create_object writes
// (WorkspaceImpl.pm:1126-1202), for both a local file and a Shock-backed one.
func TestDecodeObjectRecordLocal(t *testing.T) {
	raw, err := bson.Marshal(bson.D{
		{Key: "uuid", Value: "obj-uuid"},
		{Key: "workspace_uuid", Value: "ws-uuid"},
		{Key: "name", Value: "x.txt"},
		{Key: "path", Value: "a/b"},
		{Key: "owner", Value: "olson@patricbrc.org"},
		{Key: "type", Value: "unspecified"},
		{Key: "folder", Value: int32(0)},
		{Key: "size", Value: int64(42)},
		{Key: "creation_date", Value: "2026-09-25T12:00:00Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var o Object
	if err := bson.Unmarshal(raw, &o); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if o.IsFolder() {
		t.Error("IsFolder() = true, want false for folder=0")
	}
	if o.IsShock() {
		t.Error("IsShock() = true, want false when the shock field is absent")
	}
	if o.Size != 42 || o.Path != "a/b" {
		t.Errorf("Size/Path = %d/%q", o.Size, o.Path)
	}
}

func TestDecodeObjectRecordFolder(t *testing.T) {
	raw, _ := bson.Marshal(bson.D{
		{Key: "uuid", Value: "obj-uuid"},
		{Key: "workspace_uuid", Value: "ws-uuid"},
		{Key: "name", Value: "adir"},
		{Key: "path", Value: ""},
		{Key: "folder", Value: int32(1)},
		{Key: "size", Value: int64(0)},
	})
	var o Object
	if err := bson.Unmarshal(raw, &o); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !o.IsFolder() {
		t.Error("IsFolder() = false, want true for folder=1")
	}
}

func TestDecodeObjectRecordShock(t *testing.T) {
	raw, _ := bson.Marshal(bson.D{
		{Key: "uuid", Value: "obj-uuid"},
		{Key: "workspace_uuid", Value: "ws-uuid"},
		{Key: "name", Value: "big.bin"},
		{Key: "path", Value: ""},
		{Key: "folder", Value: int32(0)},
		{Key: "size", Value: int64(999)},
		{Key: "shock", Value: int32(1)},
		{Key: "shocknode", Value: "https://shock/node/abc"},
	})
	var o Object
	if err := bson.Unmarshal(raw, &o); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !o.IsShock() {
		t.Error("IsShock() = false, want true when shock=1")
	}
	if o.ShockNode != "https://shock/node/abc" {
		t.Errorf("ShockNode = %q", o.ShockNode)
	}
}
