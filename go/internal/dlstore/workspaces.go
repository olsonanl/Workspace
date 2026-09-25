package dlstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/BV-BRC/Workspace/go/internal/wsresolve"
)

// Workspace mirrors a document in the `workspaces` collection exactly as
// stored on disk -- including Permissions' keys, which are still
// Mongo-escaped (wsresolve.EscapeUsernameForMongo), matching what
// _create_workspace writes (WorkspaceImpl.pm:1097-1104) and what
// set_permissions updates in place (:4188,:4193). Every lookup below
// (FindWorkspace, FindWorkspaceByUUID) decodes into this shape and then
// immediately unescapes the keys before returning -- callers never see this
// type directly, only its unescaped wsresolve.Workspace counterpart. This
// mirrors _get_db_ws, which does the same unescape unconditionally on every
// read (WorkspaceImpl.pm:243-256).
type Workspace struct {
	UUID             string            `bson:"uuid"`
	Name             string            `bson:"name"`
	Owner            string            `bson:"owner"`
	CreationDate     string            `bson:"creation_date"` // ISO-8601 string, NOT a BSON date
	GlobalPermission wsresolve.Perm    `bson:"global_permission"`
	Permissions      map[string]string `bson:"permissions"`
}

// toResolveWorkspace unescapes Permissions' keys and converts values to
// wsresolve.Perm, producing the shape wsresolve.EffectivePermission expects.
func (w *Workspace) toResolveWorkspace() *wsresolve.Workspace {
	perms := make(map[string]wsresolve.Perm, len(w.Permissions))
	for k, v := range w.Permissions {
		perms[wsresolve.UnescapeUsernameForMongo(k)] = wsresolve.Perm(v)
	}
	return &wsresolve.Workspace{
		UUID:             w.UUID,
		Owner:            w.Owner,
		Name:             w.Name,
		GlobalPermission: w.GlobalPermission,
		Permissions:      perms,
	}
}

// Object mirrors a document in the `objects` collection, as written by
// _create_object (WorkspaceImpl.pm:1126-1202).
type Object struct {
	UUID          string `bson:"uuid"`
	WorkspaceUUID string `bson:"workspace_uuid"`
	Name          string `bson:"name"`
	Path          string `bson:"path"`
	Owner         string `bson:"owner"`
	Type          string `bson:"type"`
	// Folder is an integer flag, not a bool -- WorkspaceImpl.pm:1799 tests
	// `== 1`, and IsFolder below does the same.
	Folder       int    `bson:"folder"`
	Size         int64  `bson:"size"`
	Shock        int    `bson:"shock,omitempty"`
	ShockNode    string `bson:"shocknode,omitempty"`
	CreationDate string `bson:"creation_date"` // ISO-8601 string, NOT a BSON date
}

// IsFolder mirrors the `$obj->{folder} == 1` test at WorkspaceImpl.pm:1799.
func (o *Object) IsFolder() bool { return o.Folder == 1 }

// IsShock mirrors `!defined($obj->{shock}) || $obj->{shock} == 0` at
// WorkspaceImpl.pm:1813 -- an ABSENT shock field means local storage, not
// "unknown"; IsShock therefore returns false rather than erroring when Shock
// is unset (Go's zero value for an omitted int field is already 0, so this
// falls out for free, but the intent is worth stating).
func (o *Object) IsShock() bool { return o.Shock == 1 }

// FindWorkspace looks up a workspace by (owner, name), mirroring
// _get_db_ws({owner=>owner, name=>name}) as called from
// _wscache(user, ws) (WorkspaceImpl.pm:221-259, :1215-1220).
func (s *Store) FindWorkspace(ctx context.Context, owner, name string) (*wsresolve.Workspace, error) {
	return s.findWorkspace(ctx, bson.D{{Key: "owner", Value: owner}, {Key: "name", Value: name}})
}

// FindWorkspaceByUUID looks up a workspace by its uuid, mirroring
// _wscache("_uuid", uuid) (WorkspaceImpl.pm:1213-1217) -- the resolution
// wsresolve.ParseWSPath's KindWorkspaceUUID result needs before the caller
// can do anything else with it.
func (s *Store) FindWorkspaceByUUID(ctx context.Context, uuid string) (*wsresolve.Workspace, error) {
	return s.findWorkspace(ctx, bson.D{{Key: "uuid", Value: uuid}})
}

func (s *Store) findWorkspace(ctx context.Context, filter bson.D) (*wsresolve.Workspace, error) {
	var w Workspace
	err := s.workspaces.FindOne(ctx, filter).Decode(&w)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("dlstore: querying workspaces: %w", err)
	}
	return w.toResolveWorkspace(), nil
}

// FindObject looks up an object by its (workspace_uuid, path, name) key,
// mirroring _get_db_object({workspace_uuid, path, name}) as called from
// _lookup_ws_file_details (WorkspaceImpl.pm:1793-1797) via _query_database
// (:655-697).
//
// Two of _query_database's behaviors are deliberately NOT reproduced here --
// this is a read path and must not carry write side effects:
//
//   - Perl deletes one of two documents that share a (workspace_uuid, path,
//     name) key (:679-690), so a GET can delete data. Here, if more than one
//     document matches, the one sorting first by uuid is returned and a
//     warning is logged; nothing is removed.
//   - Perl synchronously re-fetches a Shock node's size when
//     shock==1 && size==0 (_update_shock_node, :814-844): a live HTTP GET, a
//     Mongo write, and potentially a subprocess spawn, all triggered by a
//     read. Here such a record is returned as-is with a warning logged --
//     the direct-filesystem Shock path (shockstore.OpenLocal) can recover a
//     stale zero size straight from the file without touching Mongo at all.
func (s *Store) FindObject(ctx context.Context, workspaceUUID, path, name string) (*Object, error) {
	// Mirrors _query_database's path normalization (WorkspaceImpl.pm:657-660):
	// strip one leading and one trailing slash. wsresolve.ParseWSPath never
	// produces a leading/trailing slash on its own Path field, but this keeps
	// FindObject correct for any other caller that passes one.
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")

	filter := bson.D{
		{Key: "workspace_uuid", Value: workspaceUUID},
		{Key: "path", Value: path},
		{Key: "name", Value: name},
	}
	cur, err := s.objects.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "uuid", Value: 1}}))
	if err != nil {
		return nil, fmt.Errorf("dlstore: querying objects: %w", err)
	}
	defer cur.Close(ctx)

	var results []Object
	if err := cur.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("dlstore: decoding objects: %w", err)
	}
	if len(results) == 0 {
		return nil, ErrNotFound
	}
	if len(results) > 1 {
		s.log.Warn("duplicate object rows for one (workspace_uuid, path, name); using the lowest uuid and leaving the rest in place (Perl would delete one; this store never does)",
			"workspace_uuid", workspaceUUID, "path", path, "name", name, "count", len(results))
	}
	obj := results[0]
	if obj.IsShock() && obj.Size == 0 {
		s.log.Warn("shock object has a recorded size of 0; not refreshing it from Shock on this read-only path",
			"uuid", obj.UUID, "shock_node", obj.ShockNode)
	}
	return &obj, nil
}
