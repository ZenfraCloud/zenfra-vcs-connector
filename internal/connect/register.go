// ABOUTME: Control-plane client for connector instance registration and token refresh.
// ABOUTME: Register exchanges the bootstrap token for a short-lived vcs_connector JWT.
package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Control-plane paths, mirrored from zenfra-api's router.
const (
	registerPath = "/api/v1/vcs/connector/register"
	refreshPath  = "/api/v1/vcs/connector/refresh"
	tunnelPath   = "/api/v1/vcs/connector/tunnel"
)

// maxErrorBody caps how much of an error response body is read.
const maxErrorBody = 8 * 1024

// Instance is a registered connector instance and its current tunnel JWT.
type Instance struct {
	ConnectorID string    `json:"connector_id"`
	InstanceID  string    `json:"instance_id"`
	Token       string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
	Endpoint    string    `json:"endpoint"`
	Vendor      string    `json:"vendor"`
	// EnrollmentKey is this instance's own credential, returned only by the
	// registration that issued it. Persisted, it replaces the bootstrap token,
	// so revoking this instance cannot be undone with the fleet-wide one.
	EnrollmentKey string `json:"enrollment_key,omitempty"`
}

// APIError is a non-2xx response from the control plane.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("control plane returned %d (%s): %s", e.Status, e.Code, e.Message)
}

// Retryable reports whether waiting could plausibly change the outcome. A 4xx
// other than 429 means the credential or request is wrong, so retrying only burns
// attempts.
func (e *APIError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= http.StatusInternalServerError
}

// IsRetryable reports whether err is worth retrying after a backoff. Transport
// failures are; a rejected credential is not.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var classified interface{ Retryable() bool }
	if errors.As(err, &classified) {
		return classified.Retryable()
	}
	return true
}

// Client talks to the zenfra-api control plane over HTTPS.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewClient creates a control-plane client. A nil httpClient gets a default with
// proxy support from the environment.
func NewClient(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{baseURL: baseURL, http: httpClient}
}

// Register exchanges a registration credential — the connector's bootstrap token
// or this instance's own enrollment key — for an instance record and a fresh JWT.
func (c *Client) Register(ctx context.Context, credential, instanceKey, version string) (*Instance, error) {
	body, err := json.Marshal(map[string]string{"instance_key": instanceKey, "version": version})
	if err != nil {
		return nil, fmt.Errorf("marshal register request: %w", err)
	}
	return c.post(ctx, registerPath, credential, body)
}

// Refresh trades the current instance JWT for a fresh one, revoking the old jti.
func (c *Client) Refresh(ctx context.Context, token string) (*Instance, error) {
	return c.post(ctx, refreshPath, token, nil)
}

// post performs one authenticated JSON request and decodes the token response.
func (c *Client) post(ctx context.Context, path, bearer string, body []byte) (*Instance, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, decodeAPIError(resp)
	}

	var inst Instance
	if err := json.NewDecoder(resp.Body).Decode(&inst); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", path, err)
	}
	if inst.Token == "" {
		return nil, fmt.Errorf("%s response carried no token", path)
	}
	return &inst, nil
}

// decodeAPIError turns a non-2xx response into an *APIError.
func decodeAPIError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	apiErr := &APIError{Status: resp.StatusCode}
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &payload) == nil {
		apiErr.Code, apiErr.Message = payload.Error, payload.Message
	}
	if apiErr.Message == "" {
		apiErr.Message = http.StatusText(resp.StatusCode)
	}
	return apiErr
}
