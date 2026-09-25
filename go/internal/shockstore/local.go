package shockstore

import (
	"fmt"
	"os"
)

// minIDLen is the shortest id ShardedPath can shard without slicing out of
// bounds. Real Shock ids are 36-character UUIDs; this only guards against a
// malformed URL that still happened to match nodeIDRE.
const minIDLen = 6

// OpenLocal resolves shockURL to its on-disk path under dataRoot, opens it,
// and verifies its size against expectedSize.
//
// On success, returns an open *os.File positioned at 0; the caller owns
// closing it.
//
// Returns ErrUnsupportedURL if shockURL doesn't resolve to a node id at all
// (callers should fall back to the HTTP path). Returns ErrIntegrity if the
// id resolved but the file is missing or its size disagrees with
// expectedSize -- deliberately not distinguished from each other, since
// either one means the "a sized record implies a complete file" invariant
// was violated (see the package doc).
func OpenLocal(dataRoot, shockURL string, expectedSize int64) (*os.File, error) {
	id, ok := NodeIDFromURL(shockURL)
	if !ok || len(id) < minIDLen {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedURL, shockURL)
	}

	path := ShardedPath(dataRoot, id)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: node %s: %v", ErrIntegrity, id, err)
	}

	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: node %s: stat: %v", ErrIntegrity, id, err)
	}
	if st.Size() != expectedSize {
		f.Close()
		return nil, fmt.Errorf("%w: node %s: on-disk size %d != recorded size %d",
			ErrIntegrity, id, st.Size(), expectedSize)
	}

	return f, nil
}
