package shockstore

import "testing"

func TestNodeIDFromURL(t *testing.T) {
	for _, tc := range []struct {
		name, url, wantID string
		wantOK            bool
	}{
		{
			"real shock url",
			"https://p3.theseed.org/services/shock_api/node/2f83bd7d-5a60-4f5a-a565-0b5bd619a29b",
			"2f83bd7d-5a60-4f5a-a565-0b5bd619a29b", true,
		},
		{
			"internal shock host",
			"http://10.1.16.5/node/abcdef01-1234-5678-9abc-def012345678",
			"abcdef01-1234-5678-9abc-def012345678", true,
		},
		{
			"uppercase hex",
			"http://shock/node/ABCDEF01-1234-5678-9ABC-DEF012345678",
			"ABCDEF01-1234-5678-9ABC-DEF012345678", true,
		},
		{"trailing slash breaks the end anchor", "http://shock/node/abcdef01/", "", false},
		{"query string breaks the end anchor", "http://shock/node/abcdef01?download", "", false},
		{"no node segment", "http://shock/download/abcdef01", "", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := NodeIDFromURL(tc.url)
			if ok != tc.wantOK || id != tc.wantID {
				t.Errorf("NodeIDFromURL(%q) = (%q, %v), want (%q, %v)", tc.url, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

func TestShardedPath(t *testing.T) {
	// Golden vectors computed by hand from the same substring formula as
	// WSFileMember.pm:186-191 (_get_path): id[0:2]/id[2:4]/id[4:6]/id/id.data.
	for _, tc := range []struct{ id, want string }{
		{
			"2f83bd7d-5a60-4f5a-a565-0b5bd619a29b",
			"/data/2f/83/bd/2f83bd7d-5a60-4f5a-a565-0b5bd619a29b/2f83bd7d-5a60-4f5a-a565-0b5bd619a29b.data",
		},
		{
			"00000000-0000-0000-0000-000000000000",
			"/data/00/00/00/00000000-0000-0000-0000-000000000000/00000000-0000-0000-0000-000000000000.data",
		},
	} {
		got := ShardedPath("/data", tc.id)
		if got != tc.want {
			t.Errorf("ShardedPath(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}
