// Package shockstore resolves a Shock node reference to its backing file on
// disk, so a colocated reader can skip the Shock HTTP API entirely.
//
// This ports the one place the Perl codebase already does this --
// lib/Bio/P3/Workspace/WSFileMember.pm:44-191, used by the zip-archive
// builder -- rather than inventing a new scheme. It deliberately knows
// nothing about Mongo, HTTP, or the download service: any future component
// that needs a Shock node's bytes on a host that shares Shock's data volume
// (the archive builder today, a future full Go port of the Workspace service
// tomorrow) can use it directly.
//
// Unlike WSFileMember.pm, this package does NOT silently fall back to HTTP
// when the file disagrees with its expected size. That decision is
// deliberate: the deployment guarantees there is exactly one copy of the
// Shock data tree, and that a Mongo record carrying a size means the file is
// already complete on disk. A disagreement therefore means the invariant was
// violated -- real corruption or a real bug -- and papering over it by
// silently refetching over HTTP is exactly the kind of masked failure that
// turned a one-line bug into a multi-day investigation for this service (see
// go/cmd/ws-download/PORT_STATUS.md). Callers must treat ErrIntegrity as a
// hard failure.
package shockstore

import (
	"errors"
	"regexp"
)

// nodeIDRE mirrors WSFileMember.pm:76 exactly: `m,node/([a-f0-9-]+)$,i`.
var nodeIDRE = regexp.MustCompile(`(?i)node/([a-f0-9-]+)$`)

// NodeIDFromURL extracts the Shock node id from a stored shocknode URL, e.g.
// ".../shock_api/node/2f83bd7d-5a60-4f5a-a565-0b5bd619a29b" ->
// "2f83bd7d-5a60-4f5a-a565-0b5bd619a29b".
//
// A URL that doesn't match (a future non-Shock scheme, or simply malformed)
// is reported via ok=false, not an error -- callers should fall back to the
// HTTP path rather than treat it as corruption.
func NodeIDFromURL(shockURL string) (id string, ok bool) {
	m := nodeIDRE.FindStringSubmatch(shockURL)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ShardedPath reproduces WSFileMember.pm:186-191's _get_path: Shock's own
// on-disk sharding scheme, not something invented here.
//
//	<dataRoot>/<id[0:2]>/<id[2:4]>/<id[4:6]>/<id>/<id>.data
func ShardedPath(dataRoot, id string) string {
	return dataRoot + "/" + id[0:2] + "/" + id[2:4] + "/" + id[4:6] + "/" + id + "/" + id + ".data"
}

// ErrUnsupportedURL means shockURL doesn't look like a Shock node reference
// at all. Not an error condition in the failure sense -- callers should fall
// back to the HTTP path.
var ErrUnsupportedURL = errors.New("shockstore: url is not a recognized shock node reference")

// ErrIntegrity means the URL resolved to a node id, but the on-disk file is
// missing or its size disagrees with the caller's expected size. Per this
// package's documented invariant (see the package doc), this must never
// happen in practice; callers must surface it as a hard failure, never as a
// silent signal to retry over HTTP.
var ErrIntegrity = errors.New("shockstore: on-disk file missing or size mismatch")
