package errorbased

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

// --- Mock transport client ---

// mockClient implements transport.Client for testing by returning canned
// transport.Response objects. This avoids http.ResponseWriter entirely.
type mockClient struct {
	doFunc func(ctx context.Context, req *transport.Request) (*transport.Response, error)
}

func (m *mockClient) Do(ctx context.Context, req *transport.Request) (*transport.Response, error) {
	return m.doFunc(ctx, req)
}

func (m *mockClient) SetProxy(proxyURL string) error  { return nil }
func (m *mockClient) SetRateLimit(rps float64)         {}
func (m *mockClient) Stats() *transport.TransportStats { return &transport.TransportStats{} }

// --- Mock client factory helpers ---

const normalPage = `<html><body>Normal page</body></html>`

// newMySQLErrorClient returns a mock client that simulates MySQL error-based injection.
// When the request URL or body contains "extractvalue" or "updatexml",
// it returns a MySQL XPATH syntax error containing the version string.
func newMySQLErrorClient() *mockClient {
	return &mockClient{
		doFunc: func(_ context.Context, req *transport.Request) (*transport.Response, error) {
			payload := req.URL + req.Body
			if strings.Contains(payload, "extractvalue") || strings.Contains(payload, "updatexml") {
				return &transport.Response{
					StatusCode: 500,
					Body:       []byte(`<html>Error: XPATH syntax error: '~8.0.32~'</html>`),
					Duration:   10 * time.Millisecond,
				}, nil
			}
			return &transport.Response{
				StatusCode: 200,
				Body:       []byte(normalPage),
				Duration:   10 * time.Millisecond,
			}, nil
		},
	}
}

// newPostgreSQLErrorClient returns a mock client that simulates PostgreSQL error-based injection.
// When the request URL or body contains "CAST", it returns a PostgreSQL type error.
func newPostgreSQLErrorClient() *mockClient {
	return &mockClient{
		doFunc: func(_ context.Context, req *transport.Request) (*transport.Response, error) {
			payload := req.URL + req.Body
			if strings.Contains(payload, "CAST") {
				return &transport.Response{
					StatusCode: 500,
					Body:       []byte(`ERROR: invalid input syntax for type integer: "PostgreSQL 15.3"`),
					Duration:   10 * time.Millisecond,
				}, nil
			}
			return &transport.Response{
				StatusCode: 200,
				Body:       []byte(normalPage),
				Duration:   10 * time.Millisecond,
			}, nil
		},
	}
}

// newSafeClient returns a mock client that always returns a normal response.
func newSafeClient() *mockClient {
	return &mockClient{
		doFunc: func(_ context.Context, req *transport.Request) (*transport.Response, error) {
			return &transport.Response{
				StatusCode: 200,
				Body:       []byte(normalPage),
				Duration:   10 * time.Millisecond,
			}, nil
		},
	}
}

// newMySQLLongDataClient simulates MySQL error-based injection with truncated data
// (>31 chars), returning different substrings based on SUBSTRING presence.
func newMySQLLongDataClient() *mockClient {
	fullVersion := "8.0.32-0ubuntu0.22.04.1-community"
	return &mockClient{
		doFunc: func(_ context.Context, req *transport.Request) (*transport.Response, error) {
			payload := req.URL + req.Body
			if strings.Contains(payload, "extractvalue") || strings.Contains(payload, "updatexml") {
				if strings.Contains(payload, "SUBSTRING") {
					// Check for second chunk (position 32, length 31)
					if strings.Contains(payload, "32") && strings.Contains(payload, "31") {
						if len(fullVersion) >= 32 {
							chunk := fullVersion[31:]
							return &transport.Response{
								StatusCode: 500,
								Body:       []byte("<html>Error: XPATH syntax error: '~" + chunk + "'</html>"),
								Duration:   10 * time.Millisecond,
							}, nil
						}
						return &transport.Response{
							StatusCode: 200,
							Body:       []byte(normalPage),
							Duration:   10 * time.Millisecond,
						}, nil
					}
					// First chunk (position 1, length 31)
					chunk := fullVersion
					if len(chunk) > 31 {
						chunk = chunk[:31]
					}
					return &transport.Response{
						StatusCode: 500,
						Body:       []byte("<html>Error: XPATH syntax error: '~" + chunk + "'</html>"),
						Duration:   10 * time.Millisecond,
					}, nil
				}

				// Non-SUBSTRING request: return first 31 chars (simulating MySQL truncation)
				truncated := fullVersion
				if len(truncated) > 31 {
					truncated = truncated[:31]
				}
				return &transport.Response{
					StatusCode: 500,
					Body:       []byte("<html>Error: XPATH syntax error: '~" + truncated + "'</html>"),
					Duration:   10 * time.Millisecond,
				}, nil
			}
			return &transport.Response{
				StatusCode: 200,
				Body:       []byte(normalPage),
				Duration:   10 * time.Millisecond,
			}, nil
		},
	}
}

// newMySQLBodyParamClient simulates MySQL error-based injection via POST body parameters.
func newMySQLBodyParamClient() *mockClient {
	return &mockClient{
		doFunc: func(_ context.Context, req *transport.Request) (*transport.Response, error) {
			if strings.Contains(req.Body, "extractvalue") || strings.Contains(req.Body, "updatexml") {
				return &transport.Response{
					StatusCode: 500,
					Body:       []byte(`<html>Error: XPATH syntax error: '~8.0.32~'</html>`),
					Duration:   10 * time.Millisecond,
				}, nil
			}
			return &transport.Response{
				StatusCode: 200,
				Body:       []byte(normalPage),
				Duration:   10 * time.Millisecond,
			}, nil
		},
	}
}

// --- Tests ---

func TestErrorBased_Name(t *testing.T) {
	eb := New()
	if got := eb.Name(); got != "error-based" {
		t.Errorf("Name() = %q, want %q", got, "error-based")
	}
}

func TestErrorBased_Priority(t *testing.T) {
	eb := New()
	if got := eb.Priority(); got != 1 {
		t.Errorf("Priority() = %d, want %d", got, 1)
	}
}

func TestErrorBased_DetectMySQL(t *testing.T) {
	client := newMySQLErrorClient()

	target := &engine.ScanTarget{
		URL:    "http://example.com/?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
		DBMS:      "MySQL",
		Client:    client,
	}

	eb := New()
	result, err := eb.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if !result.Injectable {
		t.Error("Detect() Injectable = false, want true for MySQL error endpoint")
	}
	if result.Confidence < 0.9 {
		t.Errorf("Detect() Confidence = %f, want >= 0.9", result.Confidence)
	}
	if result.Technique != "error-based" {
		t.Errorf("Detect() Technique = %q, want %q", result.Technique, "error-based")
	}
	if result.Evidence == "" {
		t.Error("Detect() Evidence is empty, want non-empty evidence")
	}
	if result.Payload == nil {
		t.Error("Detect() Payload is nil, want non-nil")
	}
}

func TestErrorBased_DetectPostgreSQL(t *testing.T) {
	client := newPostgreSQLErrorClient()

	target := &engine.ScanTarget{
		URL:    "http://example.com/?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
		DBMS:      "PostgreSQL",
		Client:    client,
	}

	eb := New()
	result, err := eb.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if !result.Injectable {
		t.Error("Detect() Injectable = false, want true for PostgreSQL error endpoint")
	}
	if result.Confidence < 0.9 {
		t.Errorf("Detect() Confidence = %f, want >= 0.9", result.Confidence)
	}
	if result.Evidence == "" {
		t.Error("Detect() Evidence is empty, want non-empty evidence")
	}
}

func TestErrorBased_DetectNotInjectable(t *testing.T) {
	client := newSafeClient()

	target := &engine.ScanTarget{
		URL:    "http://example.com/?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
		DBMS:      "MySQL",
		Client:    client,
	}

	eb := New()
	result, err := eb.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Injectable {
		t.Error("Detect() Injectable = true, want false for safe endpoint")
	}
}

func TestErrorBased_DetectUnknownDBMS(t *testing.T) {
	// When DBMS is unknown, the technique should try both MySQL and PostgreSQL payloads.
	client := newMySQLErrorClient()

	target := &engine.ScanTarget{
		URL:    "http://example.com/?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
		DBMS:      "", // Unknown DBMS
		Client:    client,
	}

	eb := New()
	result, err := eb.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if !result.Injectable {
		t.Error("Detect() Injectable = false, want true (MySQL payloads should work even without DBMS hint)")
	}
}

func TestErrorBased_ExtractMySQL(t *testing.T) {
	client := newMySQLErrorClient()

	target := &engine.ScanTarget{
		URL:    "http://example.com/?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.ExtractionRequest{
		InjectionRequest: technique.InjectionRequest{
			Target:    target,
			Parameter: param,
			Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
			DBMS:      "MySQL",
			Client:    client,
		},
		Query: "@@version",
	}

	eb := New()
	result, err := eb.Extract(context.Background(), req)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if result.Value != "8.0.32" {
		t.Errorf("Extract() Value = %q, want %q", result.Value, "8.0.32")
	}
	if result.Requests < 1 {
		t.Error("Extract() Requests should be at least 1")
	}
}

func TestErrorBased_ExtractPostgreSQL(t *testing.T) {
	client := newPostgreSQLErrorClient()

	target := &engine.ScanTarget{
		URL:    "http://example.com/?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.ExtractionRequest{
		InjectionRequest: technique.InjectionRequest{
			Target:    target,
			Parameter: param,
			Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
			DBMS:      "PostgreSQL",
			Client:    client,
		},
		Query: "version()",
	}

	eb := New()
	result, err := eb.Extract(context.Background(), req)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if result.Value != "PostgreSQL 15.3" {
		t.Errorf("Extract() Value = %q, want %q", result.Value, "PostgreSQL 15.3")
	}
	if result.Requests < 1 {
		t.Error("Extract() Requests should be at least 1")
	}
}

func TestErrorBased_ExtractMySQLLongData(t *testing.T) {
	client := newMySQLLongDataClient()

	target := &engine.ScanTarget{
		URL:    "http://example.com/?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.ExtractionRequest{
		InjectionRequest: technique.InjectionRequest{
			Target:    target,
			Parameter: param,
			Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
			DBMS:      "MySQL",
			Client:    client,
		},
		Query: "@@version",
	}

	eb := New()
	result, err := eb.Extract(context.Background(), req)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	expected := "8.0.32-0ubuntu0.22.04.1-community"
	if result.Value != expected {
		t.Errorf("Extract() Value = %q, want %q", result.Value, expected)
	}
	if result.Requests < 2 {
		t.Errorf("Extract() Requests = %d, want >= 2 (should use SUBSTRING for chunked extraction)", result.Requests)
	}
}

func TestErrorBased_DetectBodyParameter(t *testing.T) {
	client := newMySQLBodyParamClient()

	target := &engine.ScanTarget{
		URL:         "http://example.com/",
		Method:      "POST",
		Body:        "id=1",
		ContentType: "application/x-www-form-urlencoded",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationBody, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	req := &technique.InjectionRequest{
		Target:    target,
		Parameter: param,
		Baseline:  &transport.Response{StatusCode: 200, Body: []byte(normalPage)},
		DBMS:      "MySQL",
		Client:    client,
	}

	eb := New()
	result, err := eb.Detect(context.Background(), req)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if !result.Injectable {
		t.Error("Detect() Injectable = false, want true for POST body parameter")
	}
}

// --- parseErrorResponse unit tests ---

func TestParseErrorResponse_MySQL(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "extractvalue with tilde delimiters",
			body: `<html>Error: XPATH syntax error: '~8.0.32~'</html>`,
			want: "8.0.32",
		},
		{
			name: "extractvalue with single tilde",
			body: `XPATH syntax error: '~8.0.32'`,
			want: "8.0.32",
		},
		{
			name: "updatexml with tilde delimiters",
			body: `<html>Error: XPATH syntax error: '~root@localhost~'</html>`,
			want: "root@localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseErrorResponse(tt.body, "MySQL")
			if got != tt.want {
				t.Errorf("parseErrorResponse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseErrorResponse_PostgreSQL(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "CAST type error",
			body: `ERROR: invalid input syntax for type integer: "PostgreSQL 15.3"`,
			want: "PostgreSQL 15.3",
		},
		{
			name: "CAST type error in HTML",
			body: `<html>ERROR: invalid input syntax for type integer: "mydb"</html>`,
			want: "mydb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseErrorResponse(tt.body, "PostgreSQL")
			if got != tt.want {
				t.Errorf("parseErrorResponse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseErrorResponse_NoMatch(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		dbmsName string
	}{
		{
			name:     "normal HTML page",
			body:     `<html><body>Normal page</body></html>`,
			dbmsName: "MySQL",
		},
		{
			name:     "error but no SQL data",
			body:     `Internal Server Error`,
			dbmsName: "PostgreSQL",
		},
		{
			name:     "empty body",
			body:     ``,
			dbmsName: "MySQL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseErrorResponse(tt.body, tt.dbmsName)
			if got != "" {
				t.Errorf("parseErrorResponse() = %q, want empty string", got)
			}
		})
	}
}

func TestParseErrorResponse_UnknownDBMS(t *testing.T) {
	// When DBMS is unknown, parseErrorResponse should try all patterns.
	mysqlBody := `XPATH syntax error: '~8.0.32~'`
	got := parseErrorResponse(mysqlBody, "")
	if got != "8.0.32" {
		t.Errorf("parseErrorResponse(unknown DBMS, MySQL error) = %q, want %q", got, "8.0.32")
	}

	pgBody := `ERROR: invalid input syntax for type integer: "PostgreSQL 15.3"`
	got = parseErrorResponse(pgBody, "")
	if got != "PostgreSQL 15.3" {
		t.Errorf("parseErrorResponse(unknown DBMS, PG error) = %q, want %q", got, "PostgreSQL 15.3")
	}
}

// --- Interface compliance test ---

func TestErrorBased_ImplementsTechnique(t *testing.T) {
	var _ technique.Technique = (*ErrorBased)(nil)
}
