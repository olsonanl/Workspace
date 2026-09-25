package workspace

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetDownloadURLRequestAndResponseShape(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.1","result":["https://p3.theseed.org/services/shock_api/node/abc?download&download_key=xyz"],"id":"1"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	urls, err := c.GetDownloadURL([]string{"/bob@patricbrc.org/home/x.txt"})
	if err != nil {
		t.Fatalf("GetDownloadURL: %v", err)
	}
	if len(urls) != 1 || urls[0] != "https://p3.theseed.org/services/shock_api/node/abc?download&download_key=xyz" {
		t.Errorf("urls = %v, want a single minted URL", urls)
	}

	var req jsonRPCRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("decoding request body: %v", err)
	}
	if req.Method != "Workspace.get_download_url" {
		t.Errorf("method = %q, want Workspace.get_download_url", req.Method)
	}
	if len(req.Params) != 1 {
		t.Fatalf("params length = %d, want 1", len(req.Params))
	}
	params, ok := req.Params[0].(map[string]interface{})
	if !ok {
		t.Fatalf("params[0] is %T, want a map", req.Params[0])
	}
	// get_download_url_params in Workspace.spec declares only "objects" --
	// unlike most other RPC params here, there is no adminmode field.
	if _, hasAdminMode := params["adminmode"]; hasAdminMode {
		t.Errorf("request params include adminmode, but get_download_url_params has no such field")
	}
	objects, ok := params["objects"].([]interface{})
	if !ok || len(objects) != 1 || objects[0] != "/bob@patricbrc.org/home/x.txt" {
		t.Errorf("objects = %v, want [\"/bob@patricbrc.org/home/x.txt\"]", params["objects"])
	}
}

func TestGetDownloadURLPropagatesRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.1","result":null,"error":{"code":-32602,"message":"object not found","data":""},"id":"1"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	if _, err := c.GetDownloadURL([]string{"/bob@patricbrc.org/home/nope.txt"}); err == nil {
		t.Fatal("GetDownloadURL() = nil error, want the RPC error surfaced")
	}
}
