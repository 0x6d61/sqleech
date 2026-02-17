package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/transport"
)

// --- Test helpers ---

// newTestClient creates a transport client for testing.
func newTestClient() transport.Client {
	c, _ := transport.NewClient(transport.ClientOptions{})
	return c
}

// newMySQLServer creates a mock server that behaves like a MySQL-backed application.
// - Responds with MySQL error messages when `'` is injected
// - Accepts SLEEP(0) without error
// - Responds to @@version queries
// - Rejects PostgreSQL-specific syntax (::int, pg_sleep)
func newMySQLServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			id = r.PostFormValue("id")
		}

		// Single quote causes MySQL-specific error
		if strings.Contains(id, "'") && !strings.Contains(id, "AND") && !strings.Contains(id, "SLEEP") && !strings.Contains(id, "@@") && !strings.Contains(id, "CONV") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>Error: You have an error in your SQL syntax near ''' at line 1</body></html>`)
			return
		}

		// SLEEP(0) is accepted (MySQL supports this)
		if strings.Contains(id, "SLEEP(0)") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
			return
		}

		// pg_sleep causes error (not MySQL)
		if strings.Contains(id, "pg_sleep") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>Error: Unknown function pg_sleep</body></html>`)
			return
		}

		// @@version works (MySQL system variable)
		if strings.Contains(id, "@@version") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
			return
		}

		// CONV function works (MySQL-specific)
		if strings.Contains(id, "CONV(") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
			return
		}

		// ::int cast causes error (not MySQL syntax)
		if strings.Contains(id, "::int") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>Error: Syntax error near ::int</body></html>`)
			return
		}

		// CURRENT_SETTING causes error (not MySQL)
		if strings.Contains(id, "CURRENT_SETTING") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>Error: Unknown function CURRENT_SETTING</body></html>`)
			return
		}

		// Normal response
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
	}))
}

// newPostgreSQLServer creates a mock server that behaves like a PostgreSQL-backed application.
// - Responds with PostgreSQL error messages when `'` is injected
// - Accepts pg_sleep(0) without error
// - Responds to ::int cast syntax
// - Rejects MySQL-specific syntax (SLEEP, @@version, CONV)
func newPostgreSQLServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			id = r.PostFormValue("id")
		}

		// Single quote causes PostgreSQL-specific error
		if strings.Contains(id, "'") && !strings.Contains(id, "AND") && !strings.Contains(id, "pg_sleep") && !strings.Contains(id, "::") && !strings.Contains(id, "CURRENT_SETTING") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>ERROR:  syntax error at or near "'" LINE 1: SELECT * FROM products WHERE id=1'</body></html>`)
			return
		}

		// pg_sleep(0) is accepted (PostgreSQL supports this)
		if strings.Contains(id, "pg_sleep(0)") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
			return
		}

		// SLEEP(0) causes error (not PostgreSQL syntax)
		if strings.Contains(id, "SLEEP(0)") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>ERROR: function sleep(integer) does not exist</body></html>`)
			return
		}

		// ::int cast works (PostgreSQL-specific)
		if strings.Contains(id, "::int") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
			return
		}

		// @@version causes error (not PostgreSQL)
		if strings.Contains(id, "@@version") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>ERROR: operator does not exist: @@ unknown</body></html>`)
			return
		}

		// CONV function causes error (not PostgreSQL)
		if strings.Contains(id, "CONV(") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `<html><body>ERROR: function conv does not exist</body></html>`)
			return
		}

		// CURRENT_SETTING works (PostgreSQL-specific)
		if strings.Contains(id, "CURRENT_SETTING") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
			return
		}

		// Normal response
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Product</h1><p>Item #1: Widget</p></body></html>`)
	}))
}

// newUnknownServer creates a mock server that does not exhibit any DBMS-specific behavior.
func newUnknownServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always returns the same generic response regardless of input
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><body><h1>Static Page</h1><p>Content here.</p></body></html>`)
	}))
}

// makeTarget creates a ScanTarget for the given server URL with a query parameter.
func makeTarget(serverURL string) *engine.ScanTarget {
	return &engine.ScanTarget{
		URL:    serverURL + "/search?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
}

// makeParam returns the first parameter from the target for convenience.
func makeParam(target *engine.ScanTarget) *engine.Parameter {
	return &target.Parameters[0]
}

// --- MySQLFingerprinter tests ---

func TestMySQLFingerprinter_DBMS(t *testing.T) {
	fp := &MySQLFingerprinter{}
	if fp.DBMS() != "MySQL" {
		t.Errorf("expected DBMS() == 'MySQL', got %q", fp.DBMS())
	}
}

func TestMySQLFingerprinter_Identify(t *testing.T) {
	srv := newMySQLServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	// Get a baseline response
	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	fp := &MySQLFingerprinter{}
	result, err := fp.Fingerprint(context.Background(), &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}

	if !result.Identified {
		t.Error("expected MySQL to be identified")
	}
	if result.DBMS != "MySQL" {
		t.Errorf("expected DBMS 'MySQL', got %q", result.DBMS)
	}
	if result.Confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7, got %f", result.Confidence)
	}
}

// --- PostgreSQLFingerprinter tests ---

func TestPostgreSQLFingerprinter_DBMS(t *testing.T) {
	fp := &PostgreSQLFingerprinter{}
	if fp.DBMS() != "PostgreSQL" {
		t.Errorf("expected DBMS() == 'PostgreSQL', got %q", fp.DBMS())
	}
}

func TestPostgreSQLFingerprinter_Identify(t *testing.T) {
	srv := newPostgreSQLServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	// Get a baseline response
	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	fp := &PostgreSQLFingerprinter{}
	result, err := fp.Fingerprint(context.Background(), &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}

	if !result.Identified {
		t.Error("expected PostgreSQL to be identified")
	}
	if result.DBMS != "PostgreSQL" {
		t.Errorf("expected DBMS 'PostgreSQL', got %q", result.DBMS)
	}
	if result.Confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7, got %f", result.Confidence)
	}
}

// --- Registry tests ---

func TestRegistry_NewRegistry(t *testing.T) {
	reg := NewRegistry()
	if reg == nil {
		t.Fatal("expected non-nil registry")
	}
	if len(reg.fingerprinters) != 2 {
		t.Errorf("expected 2 fingerprinters registered, got %d", len(reg.fingerprinters))
	}

	// Verify both MySQL and PostgreSQL are registered
	names := make(map[string]bool)
	for _, fp := range reg.fingerprinters {
		names[fp.DBMS()] = true
	}
	if !names["MySQL"] {
		t.Error("expected MySQL fingerprinter to be registered")
	}
	if !names["PostgreSQL"] {
		t.Error("expected PostgreSQL fingerprinter to be registered")
	}
}

func TestRegistry_IdentifyMySQL(t *testing.T) {
	srv := newMySQLServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	// Get a baseline response
	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	reg := NewRegistry()
	info, err := reg.Identify(context.Background(), &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err != nil {
		t.Fatalf("Identify returned error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil DBMSInfo")
	}
	if info.Name != "MySQL" {
		t.Errorf("expected DBMS 'MySQL', got %q", info.Name)
	}
	if info.Confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7, got %f", info.Confidence)
	}
}

func TestRegistry_IdentifyPostgreSQL(t *testing.T) {
	srv := newPostgreSQLServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	// Get a baseline response
	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	reg := NewRegistry()
	info, err := reg.Identify(context.Background(), &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err != nil {
		t.Fatalf("Identify returned error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil DBMSInfo")
	}
	if info.Name != "PostgreSQL" {
		t.Errorf("expected DBMS 'PostgreSQL', got %q", info.Name)
	}
	if info.Confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7, got %f", info.Confidence)
	}
}

func TestRegistry_UnknownDBMS(t *testing.T) {
	srv := newUnknownServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	// Get a baseline response
	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	reg := NewRegistry()
	info, err := reg.Identify(context.Background(), &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err != nil {
		t.Fatalf("Identify returned error: %v", err)
	}
	if info != nil {
		t.Errorf("expected nil DBMSInfo for unknown server, got %+v", info)
	}
}

// --- IdentifyFromErrors tests ---

func TestIdentifyFromErrors_MySQL(t *testing.T) {
	errors := map[string][]string{
		"MySQL": {"You have an error in your SQL syntax"},
	}

	info := IdentifyFromErrors(errors)
	if info == nil {
		t.Fatal("expected non-nil DBMSInfo")
	}
	if info.Name != "MySQL" {
		t.Errorf("expected DBMS 'MySQL', got %q", info.Name)
	}
	if info.Confidence != 0.7 {
		t.Errorf("expected confidence 0.7, got %f", info.Confidence)
	}
}

func TestIdentifyFromErrors_PostgreSQL(t *testing.T) {
	errors := map[string][]string{
		"PostgreSQL": {"ERROR:  syntax error at or near"},
	}

	info := IdentifyFromErrors(errors)
	if info == nil {
		t.Fatal("expected non-nil DBMSInfo")
	}
	if info.Name != "PostgreSQL" {
		t.Errorf("expected DBMS 'PostgreSQL', got %q", info.Name)
	}
	if info.Confidence != 0.7 {
		t.Errorf("expected confidence 0.7, got %f", info.Confidence)
	}
}

func TestIdentifyFromErrors_NoErrors(t *testing.T) {
	// Empty map
	info := IdentifyFromErrors(map[string][]string{})
	if info != nil {
		t.Errorf("expected nil for empty errors, got %+v", info)
	}

	// Nil map
	info = IdentifyFromErrors(nil)
	if info != nil {
		t.Errorf("expected nil for nil errors, got %+v", info)
	}
}

func TestIdentifyFromErrors_GenericOnly(t *testing.T) {
	// Generic errors should not identify a specific DBMS
	errors := map[string][]string{
		"Generic": {"SQL syntax error"},
	}

	info := IdentifyFromErrors(errors)
	if info != nil {
		t.Errorf("expected nil for generic-only errors, got %+v", info)
	}
}

func TestIdentifyFromErrors_MultipleDBMS(t *testing.T) {
	// When multiple DBMS match, the one with more error signatures wins
	errors := map[string][]string{
		"MySQL":      {"You have an error in your SQL syntax", "MySqlException"},
		"PostgreSQL": {"ERROR:  syntax error at or near"},
	}

	info := IdentifyFromErrors(errors)
	if info == nil {
		t.Fatal("expected non-nil DBMSInfo")
	}
	// MySQL has 2 matches vs PostgreSQL's 1
	if info.Name != "MySQL" {
		t.Errorf("expected DBMS 'MySQL' (more matches), got %q", info.Name)
	}
}

// --- Helper function tests ---

func TestBuildRequest_QueryParam(t *testing.T) {
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

	param := &engine.Parameter{
		Name:     "id",
		Value:    "1",
		Location: engine.LocationQuery,
		Type:     engine.TypeInteger,
	}

	req := buildRequest(target, param, "1' AND SLEEP(0)-- -")

	if req.Method != "GET" {
		t.Errorf("expected method GET, got %q", req.Method)
	}

	// Verify the URL contains the modified parameter
	if !strings.Contains(req.URL, "AND+SLEEP") && !strings.Contains(req.URL, "AND%20SLEEP") && !strings.Contains(req.URL, "SLEEP") {
		t.Errorf("expected URL to contain SLEEP payload, got %q", req.URL)
	}

	// Headers should be preserved
	if req.Headers["X-Custom"] != "value" {
		t.Errorf("expected X-Custom header, got %q", req.Headers["X-Custom"])
	}

	// Cookies should be preserved
	if req.Cookies["session"] != "abc123" {
		t.Errorf("expected session cookie, got %q", req.Cookies["session"])
	}
}

func TestBuildRequest_BodyParam(t *testing.T) {
	target := &engine.ScanTarget{
		URL:         "http://example.com/login",
		Method:      "POST",
		Body:        "user=admin&pass=secret",
		ContentType: "application/x-www-form-urlencoded",
	}

	param := &engine.Parameter{
		Name:     "user",
		Value:    "admin",
		Location: engine.LocationBody,
		Type:     engine.TypeString,
	}

	req := buildRequest(target, param, "admin' AND pg_sleep(0)-- -")

	// URL should not be modified
	if req.URL != "http://example.com/login" {
		t.Errorf("expected URL unchanged, got %q", req.URL)
	}

	// Body should contain the modified parameter
	if !strings.Contains(req.Body, "pg_sleep") {
		t.Errorf("expected body to contain pg_sleep payload, got %q", req.Body)
	}

	// ContentType should be preserved
	if req.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("expected content type preserved, got %q", req.ContentType)
	}
}

func TestSendProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back a fixed confirmation; the test only checks that
		// the probe was received and the response is readable.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "probe-received")
	}))
	defer srv.Close()

	client := newTestClient()
	target := &engine.ScanTarget{
		URL:    srv.URL + "/test?id=1",
		Method: "GET",
		Parameters: []engine.Parameter{
			{Name: "id", Value: "1", Location: engine.LocationQuery, Type: engine.TypeInteger},
		},
	}
	param := &target.Parameters[0]

	resp, err := sendProbe(context.Background(), client, target, param, "1' AND 1=1-- -")
	if err != nil {
		t.Fatalf("sendProbe returned error: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body := resp.BodyString()
	if body != "probe-received" {
		t.Errorf("expected response body 'probe-received', got %q", body)
	}
}

// --- Context cancellation test ---

func TestMySQLFingerprinter_ContextCancelled(t *testing.T) {
	srv := newMySQLServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	fp := &MySQLFingerprinter{}
	_, err = fp.Fingerprint(ctx, &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err == nil {
		t.Error("expected error when context is cancelled")
	}
}

// --- MySQL should NOT identify on a PostgreSQL server ---

func TestMySQLFingerprinter_NotIdentifyPostgreSQL(t *testing.T) {
	srv := newPostgreSQLServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	fp := &MySQLFingerprinter{}
	result, err := fp.Fingerprint(context.Background(), &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}

	// Should not confidently identify as MySQL
	if result.Identified && result.Confidence >= 0.7 {
		t.Errorf("MySQL fingerprinter should not identify PostgreSQL server with high confidence, got confidence %f", result.Confidence)
	}
}

// --- PostgreSQL should NOT identify on a MySQL server ---

func TestPostgreSQLFingerprinter_NotIdentifyMySQL(t *testing.T) {
	srv := newMySQLServer()
	defer srv.Close()

	client := newTestClient()
	target := makeTarget(srv.URL)
	param := makeParam(target)

	baselineReq := buildRequest(target, param, param.Value)
	baseline, err := client.Do(context.Background(), baselineReq)
	if err != nil {
		t.Fatalf("failed to get baseline: %v", err)
	}

	fp := &PostgreSQLFingerprinter{}
	result, err := fp.Fingerprint(context.Background(), &FingerprintRequest{
		Target:    target,
		Parameter: param,
		Baseline:  baseline,
		Client:    client,
	})

	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}

	// Should not confidently identify as PostgreSQL
	if result.Identified && result.Confidence >= 0.7 {
		t.Errorf("PostgreSQL fingerprinter should not identify MySQL server with high confidence, got confidence %f", result.Confidence)
	}
}
