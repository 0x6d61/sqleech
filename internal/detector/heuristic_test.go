package detector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/transport"
)

// newVulnSafeServer creates a test server with two endpoints:
//
//	/vuln?id=X - vulnerable to SQL injection
//	/safe?id=X - always returns the same response
func newVulnSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		id := r.URL.Query().Get("id")
		// Also check POST body for id parameter
		if id == "" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			id = r.PostFormValue("id")
		}

		switch path {
		case "/vuln":
			if strings.Contains(id, "'") {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `<html><body>Error: You have an error in your SQL syntax near '''</body></html>`)
				return
			}
			if strings.Contains(id, "AND 1=2") {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `<html><body>No results found.</body></html>`)
				return
			}
			// Normal response (baseline and AND 1=1 match)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Product Details</h1><p>Item #1: Widget</p><p>Price: $9.99</p></body></html>`)
		case "/safe":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Static Page</h1><p>This content never changes.</p></body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Not Found")
		}
	}))
}

func newTestClient() transport.Client {
	c, _ := transport.NewClient(transport.ClientOptions{})
	return c
}

func TestDetectAll_VulnerableParameter(t *testing.T) {
	srv := newVulnSafeServer()
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.IsInjectable {
		t.Error("expected parameter to be flagged as injectable")
	}
	if r.Parameter.Name != "id" {
		t.Errorf("expected parameter name 'id', got %q", r.Parameter.Name)
	}
}

func TestDetectAll_SafeParameter(t *testing.T) {
	srv := newVulnSafeServer()
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/safe?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.IsInjectable {
		t.Error("expected safe parameter NOT to be flagged as injectable")
	}
	if r.CausesError {
		t.Error("expected safe parameter NOT to cause error")
	}
}

func TestDetectAll_ErrorProbe(t *testing.T) {
	srv := newVulnSafeServer()
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	r := results[0]
	if !r.CausesError {
		t.Error("expected CausesError to be true for vulnerable parameter")
	}
	if len(r.ErrorSignatures) == 0 {
		t.Error("expected ErrorSignatures to contain SQL error matches")
	}

	// Verify MySQL error was detected
	found := false
	for dbms := range r.ErrorSignatures {
		if dbms == "MySQL" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MySQL in ErrorSignatures, got %v", r.ErrorSignatures)
	}
}

func TestDetectAll_BooleanProbe(t *testing.T) {
	srv := newVulnSafeServer()
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	r := results[0]
	// For a truly injectable parameter, the error probe returning SQL errors
	// is sufficient to flag injectable. The boolean probe (TRUE matches baseline,
	// FALSE differs) provides additional confidence.
	if !r.IsInjectable {
		t.Error("expected parameter to be flagged as injectable based on heuristics")
	}
}

func TestDetectAll_NumericParameter(t *testing.T) {
	srv := newVulnSafeServer()
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	r := results[0]
	if r.Parameter.Type != engine.TypeInteger {
		t.Errorf("expected TypeInteger, got %d", r.Parameter.Type)
	}
	if !r.IsInjectable {
		t.Error("expected numeric parameter to be injectable")
	}
}

func TestDetectAll_MultipleParameters(t *testing.T) {
	// Create a server that only treats 'id' as vulnerable, 'page' is safe
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `Error: You have an error in your SQL syntax`)
			return
		}
		if strings.Contains(id, "AND 1=2") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body>No results.</body></html>`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Products</h1><p>Item #1</p></body></html>`)
	}))
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/search?id=1&page=5",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
			{Name: "page", Value: "5", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	injectableCount := 0
	var injectableName string
	for _, r := range results {
		if r.IsInjectable {
			injectableCount++
			injectableName = r.Parameter.Name
		}
	}

	if injectableCount != 1 {
		t.Errorf("expected exactly 1 injectable parameter, got %d", injectableCount)
	}
	if injectableName != "id" {
		t.Errorf("expected injectable parameter to be 'id', got %q", injectableName)
	}
}

func TestBuildProbeRequest_QueryParam(t *testing.T) {
	target := &engine.ScanTarget{
		URL:    "http://example.com/page?id=1&name=test",
		Method: "GET",
		Headers: map[string]string{
			"X-Custom": "value",
		},
		Cookies: map[string]string{
			"session": "abc123",
		},
	}

	param := engine.Parameter{
		Name:     "id",
		Value:    "1",
		Location: engine.LocationQuery,
		Type:     engine.TypeInteger,
	}

	req := buildProbeRequest(target, param, "1' AND '1'='1")

	// Verify URL has modified parameter
	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("failed to parse URL: %v", err)
	}

	gotID := parsed.Query().Get("id")
	if gotID != "1' AND '1'='1" {
		t.Errorf("expected id='1' AND '1'='1', got %q", gotID)
	}

	// Other parameters should be preserved
	gotName := parsed.Query().Get("name")
	if gotName != "test" {
		t.Errorf("expected name='test', got %q", gotName)
	}

	// Headers should be preserved
	if req.Headers["X-Custom"] != "value" {
		t.Errorf("expected X-Custom header 'value', got %q", req.Headers["X-Custom"])
	}

	// Cookies should be preserved
	if req.Cookies["session"] != "abc123" {
		t.Errorf("expected session cookie 'abc123', got %q", req.Cookies["session"])
	}

	// Method should be preserved
	if req.Method != "GET" {
		t.Errorf("expected method GET, got %q", req.Method)
	}
}

func TestBuildProbeRequest_BodyParam(t *testing.T) {
	target := &engine.ScanTarget{
		URL:         "http://example.com/login",
		Method:      "POST",
		Body:        "user=admin&pass=secret",
		ContentType: "application/x-www-form-urlencoded",
	}

	param := engine.Parameter{
		Name:     "user",
		Value:    "admin",
		Location: engine.LocationBody,
		Type:     engine.TypeString,
	}

	req := buildProbeRequest(target, param, "admin' OR '1'='1")

	// URL should not be modified
	if req.URL != "http://example.com/login" {
		t.Errorf("expected URL unchanged, got %q", req.URL)
	}

	// Body should have the modified parameter
	bodyValues, err := url.ParseQuery(req.Body)
	if err != nil {
		t.Fatalf("failed to parse body: %v", err)
	}

	gotUser := bodyValues.Get("user")
	if gotUser != "admin' OR '1'='1" {
		t.Errorf("expected user='admin' OR '1'='1', got %q", gotUser)
	}

	// Other body params should be preserved
	gotPass := bodyValues.Get("pass")
	if gotPass != "secret" {
		t.Errorf("expected pass='secret', got %q", gotPass)
	}

	// ContentType should be preserved
	if req.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected content type preserved, got %q", req.ContentType)
	}
}

func TestBuildBaselineRequest(t *testing.T) {
	target := &engine.ScanTarget{
		URL:         "http://example.com/page?id=1",
		Method:      "GET",
		Body:        "",
		ContentType: "",
		Headers: map[string]string{
			"Accept": "text/html",
		},
		Cookies: map[string]string{
			"token": "xyz",
		},
	}

	req := buildBaselineRequest(target)

	if req.Method != "GET" {
		t.Errorf("expected method GET, got %q", req.Method)
	}
	if req.URL != "http://example.com/page?id=1" {
		t.Errorf("expected URL 'http://example.com/page?id=1', got %q", req.URL)
	}
	if req.Body != "" {
		t.Errorf("expected empty body, got %q", req.Body)
	}
	if req.Headers["Accept"] != "text/html" {
		t.Errorf("expected Accept header 'text/html', got %q", req.Headers["Accept"])
	}
	if req.Cookies["token"] != "xyz" {
		t.Errorf("expected token cookie 'xyz', got %q", req.Cookies["token"])
	}
}

func TestDetectAll_ContextCancelled(t *testing.T) {
	srv := newVulnSafeServer()
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := detector.DetectAll(ctx, target)
	if err == nil {
		t.Error("expected error when context is cancelled")
	}
}

func TestDetectAll_StringParameter(t *testing.T) {
	// Server vulnerable to string-context injection
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(name, "'") && !strings.Contains(name, "AND") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `Error: You have an error in your SQL syntax near ''' at line 1`)
			return
		}
		if strings.Contains(name, "' AND '1'='2") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body>No results found.</body></html>`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>User Profile</h1><p>Name: Alice</p></body></html>`)
	}))
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/user?name=Alice",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "name", Value: "Alice", Location: engine.LocationQuery, Type: engine.TypeString},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.IsInjectable {
		t.Error("expected string parameter to be injectable")
	}
	if !r.CausesError {
		t.Error("expected CausesError to be true")
	}
}

func TestNewHeuristicDetector_DefaultThreshold(t *testing.T) {
	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	if detector.threshold != 0.98 {
		t.Errorf("expected default threshold 0.98, got %f", detector.threshold)
	}
}

func TestDetectAll_NoParameters(t *testing.T) {
	srv := newVulnSafeServer()
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:        srv.URL + "/safe",
		Method:     "GET",
		Parameters: []engine.Parameter{},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results for no parameters, got %d", len(results))
	}
}

func TestDetectAll_PostBodyParameter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		username := r.PostFormValue("username")
		if strings.Contains(username, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `Error: You have an error in your SQL syntax`)
			return
		}
		if strings.Contains(username, "AND") && strings.Contains(username, "1=2") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body>No match.</body></html>`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Welcome admin</h1></body></html>`)
	}))
	defer srv.Close()

	client := newTestClient()
	de := NewDiffEngine()
	detector := NewHeuristicDetector(client, de)

	target := &engine.ScanTarget{
		URL:         srv.URL + "/login",
		Method:      "POST",
		Body:        "username=admin&password=pass123",
		ContentType: "application/x-www-form-urlencoded",
		Parameters: []engine.Parameter{
			{Name: "username", Value: "admin", Location: engine.LocationBody, Type: engine.TypeString},
			{Name: "password", Value: "pass123", Location: engine.LocationBody, Type: engine.TypeString},
		},
	}

	results, err := detector.DetectAll(context.Background(), target)
	if err != nil {
		t.Fatalf("DetectAll returned error: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	injectableCount := 0
	for _, r := range results {
		if r.IsInjectable {
			injectableCount++
			if r.Parameter.Name != "username" {
				t.Errorf("expected injectable parameter 'username', got %q", r.Parameter.Name)
			}
		}
	}

	if injectableCount != 1 {
		t.Errorf("expected 1 injectable parameter, got %d", injectableCount)
	}
}
