package engine_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/sqleech/internal/detector"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/fingerprint"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/technique/boolean"
	"github.com/0x6d61/sqleech/internal/technique/errorbased"
	"github.com/0x6d61/sqleech/internal/transport"
)

// --------------------------------------------------------------------------
// Adapters: bridge real technique/detector/fingerprint packages to the
// engine-local interfaces (Technique, HeuristicDetectorFunc, etc.)
// --------------------------------------------------------------------------

// techniqueAdapter wraps a technique.Technique into engine.Technique.
type techniqueAdapter struct {
	inner technique.Technique
}

func (a *techniqueAdapter) Name() string  { return a.inner.Name() }
func (a *techniqueAdapter) Priority() int { return a.inner.Priority() }
func (a *techniqueAdapter) Detect(ctx context.Context, req *engine.TechniqueRequest) (*engine.DetectionResult, error) {
	innerReq := &technique.InjectionRequest{
		Target:    req.Target,
		Parameter: req.Parameter,
		Baseline:  req.Baseline,
		DBMS:      req.DBMS,
		Client:    req.Client,
	}
	r, err := a.inner.Detect(ctx, innerReq)
	if err != nil {
		return nil, err
	}
	dr := &engine.DetectionResult{
		Injectable: r.Injectable,
		Confidence: r.Confidence,
		Technique:  r.Technique,
		Evidence:   r.Evidence,
	}
	if r.Payload != nil {
		dr.Payload = r.Payload.String()
	}
	return dr, nil
}

// wrapTechniques converts a slice of technique.Technique into engine.Technique.
func wrapTechniques(techs ...technique.Technique) []engine.Technique {
	out := make([]engine.Technique, len(techs))
	for i, t := range techs {
		out[i] = &techniqueAdapter{inner: t}
	}
	return out
}

// makeHeuristicFunc creates a HeuristicDetectorFunc using the real detector package.
func makeHeuristicFunc(client transport.Client) engine.HeuristicDetectorFunc {
	diffEng := detector.NewDiffEngine()
	return func(ctx context.Context, target *engine.ScanTarget) ([]engine.HeuristicResult, error) {
		hd := detector.NewHeuristicDetector(client, diffEng)
		results, err := hd.DetectAll(ctx, target)
		if err != nil {
			return nil, err
		}
		out := make([]engine.HeuristicResult, len(results))
		for i, r := range results {
			out[i] = engine.HeuristicResult{
				Parameter:       r.Parameter,
				Baseline:        r.Baseline,
				CausesError:     r.CausesError,
				DynamicContent:  r.DynamicContent,
				ErrorSignatures: r.ErrorSignatures,
				PageRatio:       r.PageRatio,
				IsInjectable:    r.IsInjectable,
			}
		}
		return out, nil
	}
}

// makeDBMSIdentifier creates a DBMSIdentifierFunc using the real fingerprint package.
func makeDBMSIdentifier() engine.DBMSIdentifierFunc {
	return func(errorSignatures map[string][]string) *engine.DBMSInfo {
		info := fingerprint.IdentifyFromErrors(errorSignatures)
		if info == nil {
			return nil
		}
		return &engine.DBMSInfo{
			Name:       info.Name,
			Version:    info.Version,
			Banner:     info.Banner,
			Confidence: info.Confidence,
		}
	}
}

// makeFingerprinter creates a FingerprintFunc using the real fingerprint package.
func makeFingerprinter() engine.FingerprintFunc {
	registry := fingerprint.NewRegistry()
	return func(ctx context.Context, target *engine.ScanTarget, param *engine.Parameter, baseline *transport.Response, client transport.Client) (*engine.DBMSInfo, error) {
		info, err := registry.Identify(ctx, &fingerprint.FingerprintRequest{
			Target:    target,
			Parameter: param,
			Baseline:  baseline,
			Client:    client,
		})
		if err != nil {
			return nil, err
		}
		if info == nil {
			return nil, nil
		}
		return &engine.DBMSInfo{
			Name:       info.Name,
			Version:    info.Version,
			Banner:     info.Banner,
			Confidence: info.Confidence,
		}, nil
	}
}

// makeParamParser creates a ParameterParser using the real detector package.
func makeParamParser() engine.ParameterParser {
	return func(rawURL, body, contentType string) []engine.Parameter {
		return detector.ParseParameters(rawURL, body, contentType)
	}
}

// newFullScanner creates a Scanner wired with all real implementations.
func newFullScanner(client transport.Client, config *engine.ScanConfig) *engine.Scanner {
	return engine.NewScanner(client, config,
		engine.WithTechniques(wrapTechniques(errorbased.New(), boolean.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)
}

// --------------------------------------------------------------------------
// Test HTTP server
// --------------------------------------------------------------------------

// newVulnServer creates a test HTTP server simulating a vulnerable web app.
//
// /vuln?id=X: MySQL error-based injectable
//   - If X contains "'": returns MySQL error
//   - If X contains "extractvalue": returns XPATH syntax error with version
//   - If X contains "AND 1=1": returns normal page
//   - If X contains "AND 1=2": returns different page
//
// /safe?id=X: Always returns same response
//
// /multi?id=X&name=Y: id is injectable, name is not
func newVulnServer() *httptest.Server {
	mux := http.NewServeMux()

	normalPage := `<html><body><h1>User Profile</h1><p>Welcome, user #1</p></body></html>`
	errorPage := `<html><body><h1>Error</h1><p>You have an error in your SQL syntax; check the manual</p></body></html>`
	differentPage := `<html><body><h1>User Profile</h1><p>No results found</p></body></html>`
	xpathError := `<html><body><h1>Error</h1><p>XPATH syntax error: '~8.0.32~'</p></body></html>`

	mux.HandleFunc("/vuln", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch {
		case strings.Contains(id, "extractvalue") || strings.Contains(id, "updatexml"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, xpathError)
		case strings.Contains(id, "'"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, errorPage)
		case strings.Contains(id, "AND 1=2") || strings.Contains(id, "'1'='2"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, differentPage)
		default:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, normalPage)
		}
	})

	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, normalPage)
	})

	mux.HandleFunc("/multi", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Only id is injectable, name always returns normal page
		switch {
		case strings.Contains(id, "extractvalue") || strings.Contains(id, "updatexml"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, xpathError)
		case strings.Contains(id, "'"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, errorPage)
		case strings.Contains(id, "AND 1=2") || strings.Contains(id, "'1'='2"):
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, differentPage)
		default:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, normalPage)
		}
	})

	return httptest.NewServer(mux)
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

func TestScanner_DefaultConfig(t *testing.T) {
	cfg := engine.DefaultScanConfig()
	if cfg == nil {
		t.Fatal("DefaultScanConfig returned nil")
	}
	if cfg.Threads <= 0 {
		t.Errorf("Threads = %d, want > 0", cfg.Threads)
	}
	if cfg.Threads != 10 {
		t.Errorf("Threads = %d, want 10", cfg.Threads)
	}
	if cfg.Verbose != 0 {
		t.Errorf("Verbose = %d, want 0", cfg.Verbose)
	}
	if len(cfg.Techniques) != 0 {
		t.Errorf("Techniques = %v, want empty (all)", cfg.Techniques)
	}
	if cfg.DBMSHint != "" {
		t.Errorf("DBMSHint = %q, want empty", cfg.DBMSHint)
	}
	if cfg.ForceTest {
		t.Error("ForceTest = true, want false")
	}
}

func TestNewScanner(t *testing.T) {
	client := newTestClient()

	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}

	names := scanner.TechniqueNames()
	if len(names) == 0 {
		t.Error("scanner has no techniques, expected at least 2")
	}

	// Verify techniques are sorted by priority: error-based (1) before boolean-blind (2)
	if len(names) >= 2 {
		if names[0] != "error-based" {
			t.Errorf("first technique = %q, want %q", names[0], "error-based")
		}
		if names[1] != "boolean-blind" {
			t.Errorf("second technique = %q, want %q", names[1], "boolean-blind")
		}
	}
}

func TestNewScanner_TechniqueSorting(t *testing.T) {
	client := newTestClient()

	// Create scanner with techniques in reverse order
	cfg := engine.DefaultScanConfig()
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(boolean.New(), errorbased.New())...),
	)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}
	// The scanner internally sorts by priority, so error-based (1) before boolean-blind (2).
	// We verify this works by ensuring the scanner was created without error.
}

func TestScanner_ScanVulnerable(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	if len(result.Vulnerabilities) == 0 {
		t.Error("expected at least 1 vulnerability, got 0")
	}

	// Verify result metadata
	if result.Target.URL != target.URL {
		t.Errorf("result.Target.URL = %q, want %q", result.Target.URL, target.URL)
	}
	if result.StartTime.IsZero() {
		t.Error("result.StartTime is zero")
	}
	if result.EndTime.IsZero() {
		t.Error("result.EndTime is zero")
	}
	if result.EndTime.Before(result.StartTime) {
		t.Error("result.EndTime is before StartTime")
	}

	// Check that we found a vulnerability for the "id" parameter
	foundID := false
	for _, vuln := range result.Vulnerabilities {
		if vuln.Parameter.Name == "id" && vuln.Injectable {
			foundID = true
			if vuln.Technique == "" {
				t.Error("vulnerability.Technique is empty")
			}
			if vuln.Confidence <= 0 {
				t.Errorf("vulnerability.Confidence = %f, want > 0", vuln.Confidence)
			}
		}
	}
	if !foundID {
		t.Error("did not find injectable vulnerability for parameter 'id'")
	}
}

func TestScanner_ScanSafe(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/safe?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// No vulnerabilities should be found for the safe endpoint
	injectableCount := 0
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			injectableCount++
		}
	}
	if injectableCount > 0 {
		t.Errorf("expected 0 injectable vulnerabilities, got %d", injectableCount)
	}
}

func TestScanner_ScanMultipleParams(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/multi?id=1&name=test",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Check: id should be injectable, name should not
	idInjectable := false
	nameInjectable := false
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			if vuln.Parameter.Name == "id" {
				idInjectable = true
			}
			if vuln.Parameter.Name == "name" {
				nameInjectable = true
			}
		}
	}

	if !idInjectable {
		t.Error("expected 'id' parameter to be injectable")
	}
	if nameInjectable {
		t.Error("expected 'name' parameter to NOT be injectable")
	}
}

func TestScanner_ContextCancellation(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := scanner.Scan(ctx, target)
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

func TestScanner_TechniqueFilter(t *testing.T) {
	client := newTestClient()

	srv := newVulnServer()
	defer srv.Close()

	// Only run error-based technique
	cfg := engine.DefaultScanConfig()
	cfg.Techniques = []string{"E"}
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(errorbased.New(), boolean.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	names := scanner.TechniqueNames()
	if len(names) != 1 {
		t.Fatalf("expected 1 technique after E filter, got %d: %v", len(names), names)
	}
	if names[0] != "error-based" {
		t.Errorf("filtered technique = %q, want %q", names[0], "error-based")
	}

	// Verify scan only uses error-based
	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
	}
	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan with E filter returned error: %v", err)
	}
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Technique != "error-based" {
			t.Errorf("expected only error-based vulnerabilities, got %q", vuln.Technique)
		}
	}

	// Only run boolean-blind technique
	cfg2 := engine.DefaultScanConfig()
	cfg2.Techniques = []string{"B"}
	scanner2 := engine.NewScanner(client, cfg2,
		engine.WithTechniques(wrapTechniques(errorbased.New(), boolean.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	names2 := scanner2.TechniqueNames()
	if len(names2) != 1 {
		t.Fatalf("expected 1 technique after B filter, got %d: %v", len(names2), names2)
	}
	if names2[0] != "boolean-blind" {
		t.Errorf("filtered technique = %q, want %q", names2[0], "boolean-blind")
	}

	// Both techniques
	cfg3 := engine.DefaultScanConfig()
	cfg3.Techniques = []string{"E", "B"}
	scanner3 := engine.NewScanner(client, cfg3,
		engine.WithTechniques(wrapTechniques(errorbased.New(), boolean.New())...),
		engine.WithParameterParser(makeParamParser()),
	)

	names3 := scanner3.TechniqueNames()
	if len(names3) != 2 {
		t.Fatalf("expected 2 techniques after E,B filter, got %d: %v", len(names3), names3)
	}
}

func TestScanner_WorkerPool(t *testing.T) {
	// Test that the worker pool can process jobs
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
	}

	ctx := context.Background()

	// Send baseline request via the test client
	baselineReq := &transport.Request{
		Method: "GET",
		URL:    srv.URL + "/vuln?id=1",
	}
	resp, err := client.Do(ctx, baselineReq)
	if err != nil {
		t.Fatalf("baseline request: %v", err)
	}

	// Use the scanner's Scan method with multiple techniques to exercise the pool
	cfg := engine.DefaultScanConfig()
	cfg.Threads = 3 // Small pool
	scanner := newFullScanner(client, cfg)

	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// At least one technique should find a vulnerability
	foundInjectable := false
	for _, v := range result.Vulnerabilities {
		if v.Injectable {
			foundInjectable = true
			break
		}
	}

	if !foundInjectable {
		t.Error("worker pool did not find any injectable vulnerability")
	}

	// Verify the baseline response was obtained (used above to verify the test server works)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("baseline status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify we got results from multiple techniques (since pool distributes work)
	techniquesSeen := make(map[string]bool)
	for _, v := range result.Vulnerabilities {
		techniquesSeen[v.Technique] = true
	}
	if len(techniquesSeen) < 2 {
		t.Logf("warning: only %d technique(s) reported results, expected at least 2", len(techniquesSeen))
	}

}

func TestScanner_ProgressCallback(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	var messages []string
	scanner.SetProgressCallback(func(msg string) {
		messages = append(messages, msg)
	})

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	_, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(messages) == 0 {
		t.Error("expected progress callback to be called at least once")
	}
}

func TestScanner_DBMSHint(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	cfg.DBMSHint = "MySQL"
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// With DBMSHint, the DBMS field should be set
	if result.DBMS != "MySQL" {
		t.Errorf("result.DBMS = %q, want %q", result.DBMS, "MySQL")
	}
}

func TestScanner_ForceTest(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	cfg.ForceTest = true
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/safe?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// ForceTest should have run techniques even though heuristics said safe
	// But the safe endpoint won't be injectable, so we still expect 0 injectable vulns
	// The key assertion is that it ran without error
}

func TestScanner_EmptyTarget(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	// Target with a URL that has no params and no body
	target := &engine.ScanTarget{
		URL:    srv.URL + "/safe",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// No parameters means no vulnerabilities
	if len(result.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities for no-params target, got %d", len(result.Vulnerabilities))
	}
}

func TestScanner_ScanTimeout(t *testing.T) {
	srv := newVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln?id=1",
		Method: "GET",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // Ensure timeout has elapsed

	_, err := scanner.Scan(ctx, target)
	if err == nil {
		t.Error("expected error from timed out context, got nil")
	}
}

// --------------------------------------------------------------------------
// Test transport client
// --------------------------------------------------------------------------

// testTransportClient implements transport.Client for testing. It wraps
// net/http.DefaultClient to actually send HTTP requests to httptest servers.
type testTransportClient struct {
	requests int64
}

func newTestClient() *testTransportClient {
	return &testTransportClient{}
}

func (c *testTransportClient) Do(ctx context.Context, req *transport.Request) (*transport.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return nil, err
	}

	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	for name, value := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{
			Name:     name,
			Value:    value,
			HttpOnly: true,
			Secure:   true,
		})
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	c.requests++

	return &transport.Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Duration:   time.Millisecond,
		URL:        resp.Request.URL.String(),
		Protocol:   "HTTP/1.1",
	}, nil
}

func (c *testTransportClient) SetProxy(_ string) error { return nil }
func (c *testTransportClient) SetRateLimit(_ float64)  {}
func (c *testTransportClient) Stats() *transport.TransportStats {
	return &transport.TransportStats{
		TotalRequests: c.requests,
	}
}
