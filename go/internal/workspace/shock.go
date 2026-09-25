package workspace

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
)

// ShockThreshold is the size above which files are stored in Shock
const ShockThreshold = 10 * 1024 // 10KB

// ShockOpenRange opens a byte range of a Shock node for streaming, without
// buffering it in memory.
//
// It is a free function rather than a *Client method because a server
// handling many users' downloads needs a per-request token
// (e.g. a Workspace download record's own UserToken), not the single token a
// *Client bakes in -- reusing a shared *Client here would leak one user's
// credentials into another's request.
//
// length < 0 means "from start to EOF" and omits seek/length from the URL
// entirely, matching WorkspaceImpl.pm:1939 exactly: a plain "?download" when
// there is no Range header, "?download&seek=B&length=LEN" when there is.
// Accepts both 200 and 206, like ShockReadBytes below.
//
// The caller must close the returned ReadCloser. ctx cancellation (e.g. the
// client disconnecting) aborts the request rather than continuing to read a
// response nobody wants -- the Perl service's failure to do this caused a
// 100%-CPU spin (see Workspace/go/cmd/ws-download/PORT_STATUS.md, section
// 1.5.3), because the exception it should have raised was silently
// swallowed by the AnyEvent event loop.
func ShockOpenRange(ctx context.Context, hc *http.Client, shockURL, token string, start, length int64) (io.ReadCloser, error) {
	url := shockURL + "?download"
	if length >= 0 {
		url = fmt.Sprintf("%s&seek=%d&length=%d", url, start, length)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "OAuth "+token)
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, fmt.Errorf("shock read failed: %s - %s", resp.Status, string(body))
	}

	return resp.Body, nil
}

// ACLError reports a non-2xx response from EnsureShockReadACL, preserving the
// status code so a caller can distinguish (for example) a 401 worth retrying
// with a fresh service token from any other failure.
type ACLError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *ACLError) Error() string {
	return fmt.Sprintf("shock acl grant failed: %s - %s", e.Status, e.Body)
}

// EnsureShockReadACL grants user read access to a Shock node, authenticating
// as a service account rather than as the user being granted access. Mirrors
// the ACL PUT in _lookup_ws_file_details (WorkspaceImpl.pm:1817-1823, whose
// comment reads "ACL change requires using the workspace owner token").
//
// Two deliberate deviations from Perl, both fixes rather than behavior
// changes a caller needs to accommodate:
//
//   - hc must carry a timeout. Perl's LWP::UserAgent->new() here has none,
//     making this PUT one of the documented sources of the multi-hour
//     production stall this port exists to fix.
//   - The response is inspected and returned as an error on failure. Perl
//     assigns it to a variable and never looks at it (:1823), so a failed
//     grant today surfaces only as a mystery 403 when Shock is fetched
//     afterward, with nothing in this service's own logs to explain it.
//
// user is interpolated into the query string exactly as Perl does --
// unescaped, not through url.Values (which would percent-encode "@" as
// "%40"). A real BV-BRC username always contains "@", so matching Perl's
// literal wire format here, rather than a more "correct" encoding, is the
// safer choice until it's confirmed Shock accepts the encoded form the same
// way.
func EnsureShockReadACL(ctx context.Context, hc *http.Client, shockNodeURL, serviceToken, user string) error {
	target := shockNodeURL + "/acl/read?users=" + user

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, nil)
	if err != nil {
		return fmt.Errorf("building shock acl request: %w", err)
	}
	req.Header.Set("Authorization", "OAuth "+serviceToken)

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("granting shock read acl: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &ACLError{StatusCode: resp.StatusCode, Status: resp.Status, Body: string(body)}
	}
	return nil
}

// ShockReadBytes reads a range of bytes from a Shock URL
func (c *Client) ShockReadBytes(shockURL string, offset, length int64) ([]byte, error) {
	url := fmt.Sprintf("%s?download&seek=%d&length=%d", shockURL, offset, length)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.Token != nil {
		req.Header.Set("Authorization", c.Token.Authorization())
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("shock read failed: %s - %s", resp.Status, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ShockDownload downloads the entire content from a Shock URL
func (c *Client) ShockDownload(shockURL string) ([]byte, error) {
	url := shockURL + "?download"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if c.Token != nil {
		req.Header.Set("Authorization", c.Token.Authorization())
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("shock download failed: %s - %s", resp.Status, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ShockDownloadToWriter downloads content from Shock and writes to the provided writer
func (c *Client) ShockDownloadToWriter(shockURL string, w io.Writer) error {
	url := shockURL + "?download"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if c.Token != nil {
		req.Header.Set("Authorization", c.Token.Authorization())
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("shock download failed: %s - %s", resp.Status, string(body))
	}

	_, err = io.Copy(w, resp.Body)
	return err
}

// ShockDownloadToFile downloads content from Shock to a local file
func (c *Client) ShockDownloadToFile(shockURL string, localPath string) error {
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer file.Close()

	return c.ShockDownloadToWriter(shockURL, file)
}

// ShockUpload uploads content to a Shock URL (used with createUploadNodes)
func (c *Client) ShockUpload(shockURL string, reader io.Reader) error {
	// Read all content first (needed for multipart)
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read content: %w", err)
	}

	return c.ShockUploadBytes(shockURL, data)
}

// ShockUploadBytes uploads byte content to a Shock URL
func (c *Client) ShockUploadBytes(shockURL string, data []byte) error {
	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("upload", "file")
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := part.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	req, err := http.NewRequest("PUT", shockURL, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.Token != nil {
		req.Header.Set("Authorization", c.Token.Authorization())
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("shock upload failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// ShockUploadFile uploads a local file to a Shock URL
func (c *Client) ShockUploadFile(shockURL string, localPath string) error {
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()

	// Get file info for size
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Create multipart form with the file
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("upload", stat.Name())
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, file); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	req, err := http.NewRequest("PUT", shockURL, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if c.Token != nil {
		req.Header.Set("Authorization", c.Token.Authorization())
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("shock upload failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// DownloadFile downloads a workspace file to a local path
// Handles both inline data and Shock-stored files
func (c *Client) DownloadFile(wsPath, localPath string) error {
	entries, err := c.Get([]string{wsPath}, false)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("object not found: %s", wsPath)
	}

	entry := entries[0]

	// If data was inline, write it directly
	if entry.Meta.ShockURL == "" {
		return os.WriteFile(localPath, entry.Data, 0644)
	}

	// Download from Shock
	return c.ShockDownloadToFile(entry.Meta.ShockURL, localPath)
}

// UploadFile uploads a local file to a workspace path
// Uses Shock for files larger than ShockThreshold
func (c *Client) UploadFile(localPath, wsPath, objType string, overwrite bool) (*ObjectMeta, error) {
	file, err := os.Open(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if objType == "" {
		objType = "unspecified"
	}

	// For small files, upload inline
	if stat.Size() <= ShockThreshold {
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		objects := []CreateRequest{
			{
				Path: wsPath,
				Type: objType,
				Data: string(data),
			},
		}

		results, err := c.Create(objects, overwrite, false)
		if err != nil {
			return nil, err
		}
		if len(results) == 0 {
			return nil, fmt.Errorf("failed to create object")
		}
		return results[0], nil
	}

	// For large files, use Shock
	meta, err := c.CreateUploadNode(wsPath, objType, nil, overwrite)
	if err != nil {
		return nil, err
	}

	if meta.ShockURL == "" {
		return nil, fmt.Errorf("no shock URL returned for upload node")
	}

	// Reset file position
	if _, err := file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek file: %w", err)
	}

	if err := c.ShockUploadFile(meta.ShockURL, localPath); err != nil {
		return nil, err
	}

	return meta, nil
}

// UploadBytes uploads byte content to a workspace path
func (c *Client) UploadBytes(data []byte, wsPath, objType string, overwrite bool) (*ObjectMeta, error) {
	if objType == "" {
		objType = "unspecified"
	}

	// For small files, upload inline
	if len(data) <= ShockThreshold {
		objects := []CreateRequest{
			{
				Path: wsPath,
				Type: objType,
				Data: string(data),
			},
		}

		results, err := c.Create(objects, overwrite, false)
		if err != nil {
			return nil, err
		}
		if len(results) == 0 {
			return nil, fmt.Errorf("failed to create object")
		}
		return results[0], nil
	}

	// For large content, use Shock
	meta, err := c.CreateUploadNode(wsPath, objType, nil, overwrite)
	if err != nil {
		return nil, err
	}

	if meta.ShockURL == "" {
		return nil, fmt.Errorf("no shock URL returned for upload node")
	}

	if err := c.ShockUploadBytes(meta.ShockURL, data); err != nil {
		return nil, err
	}

	return meta, nil
}
