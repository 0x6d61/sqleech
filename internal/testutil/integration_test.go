package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/sqleech/internal/detector"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/fingerprint"
	"github.com/0x6d61/sqleech/internal/report"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/technique/boolean"
	"github.com/0x6d61/sqleech/internal/technique/errorbased"
	"github.com/0x6d61/sqleech/internal/technique/timebased"
	"github.com/0x6d61/sqleech/internal/technique/union"
	"github.com/0x6d61/sqleech/internal/transport"
)

// --------------------------------------------------------------------------
// Adapters: bridge real technique/detector/fingerprint packages to the
// engine-local interfaces (Technique, HeuristicDetectorFunc, etc.)
// These are identical to the ones in engine/scanner_test.go but duplicated
// here to keep the testutil package self-contained.
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
		engine.WithTechniques(wrapTechniques(errorbased.New(), boolean.New(), timebased.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)
}

// --------------------------------------------------------------------------
// Test transport client
// --------------------------------------------------------------------------

// testTransportClient implements transport.Client for testing.
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

	start := time.Now()
	resp, err := http.DefaultClient.Do(httpReq)
	duration := time.Since(start)
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
		Duration:   duration,
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

// --------------------------------------------------------------------------
// Integration Tests
// --------------------------------------------------------------------------

func TestIntegration_ErrorBasedMySQL(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/error-mysql?id=1",
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

	// Assert: at least 1 injectable vulnerability found
	var foundInjectable bool
	var foundErrorBased bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			if vuln.Technique == "error-based" {
				foundErrorBased = true
			}
		}
	}

	if !foundInjectable {
		t.Error("expected at least 1 injectable vulnerability, found none")
	}
	if !foundErrorBased {
		t.Error("expected error-based technique to detect vulnerability")
	}

	// Assert: DBMS contains "MySQL"
	if !strings.Contains(result.DBMS, "MySQL") {
		t.Errorf("DBMS = %q, want to contain 'MySQL'", result.DBMS)
	}
}

func TestIntegration_ErrorBasedPostgreSQL(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/error-postgres?id=1",
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

	// Assert: vulnerability found
	var foundInjectable bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			break
		}
	}

	if !foundInjectable {
		t.Error("expected at least 1 injectable vulnerability for PostgreSQL endpoint")
	}

	// Assert: DBMS contains "PostgreSQL"
	if !strings.Contains(result.DBMS, "PostgreSQL") {
		t.Errorf("DBMS = %q, want to contain 'PostgreSQL'", result.DBMS)
	}
}

func TestIntegration_BooleanBlind(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/boolean?id=1",
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

	// Assert: vulnerability found
	var foundInjectable bool
	var foundBooleanBlind bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			if vuln.Technique == "boolean-blind" {
				foundBooleanBlind = true
			}
		}
	}

	if !foundInjectable {
		t.Error("expected at least 1 injectable vulnerability for boolean-blind endpoint")
	}
	if !foundBooleanBlind {
		t.Error("expected boolean-blind technique to detect vulnerability")
	}
}

func TestIntegration_SafeEndpoint(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/safe?id=1",
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

	// Assert: NO injectable vulnerabilities found
	injectableCount := 0
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			injectableCount++
		}
	}
	if injectableCount > 0 {
		t.Errorf("expected 0 injectable vulnerabilities for safe endpoint, got %d", injectableCount)
	}
}

func TestIntegration_MultipleParameters(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/multi?id=1&name=test",
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

	// Assert: vulnerability found for "id" parameter
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
	// Assert: no vulnerability for "name" parameter
	if nameInjectable {
		t.Error("expected 'name' parameter to NOT be injectable")
	}
}

func TestIntegration_JSONReport(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/error-mysql?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Generate JSON report
	reporter, err := report.New("json")
	if err != nil {
		t.Fatalf("failed to create JSON reporter: %v", err)
	}

	var buf bytes.Buffer
	err = reporter.Generate(ctx, result, &buf)
	if err != nil {
		t.Fatalf("failed to generate JSON report: %v", err)
	}

	output := buf.String()

	// Assert: valid JSON output
	var jsonData map[string]any
	if err := json.Unmarshal([]byte(output), &jsonData); err != nil {
		t.Fatalf("report output is not valid JSON: %v\noutput: %s", err, output)
	}

	// Assert: contains vulnerability data
	vulns, ok := jsonData["vulnerabilities"]
	if !ok {
		t.Fatal("JSON report missing 'vulnerabilities' field")
	}
	vulnSlice, ok := vulns.([]any)
	if !ok {
		t.Fatal("JSON 'vulnerabilities' is not an array")
	}
	if len(vulnSlice) == 0 {
		t.Error("JSON report has empty vulnerabilities array")
	}

	// Assert: contains tool name
	if tool, ok := jsonData["tool"]; !ok || tool != "sqleech" {
		t.Errorf("JSON report tool = %v, want 'sqleech'", jsonData["tool"])
	}

	// Assert: format is "json"
	if reporter.Format() != "json" {
		t.Errorf("reporter.Format() = %q, want 'json'", reporter.Format())
	}
}

func TestIntegration_TextReport(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/error-mysql?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	// Generate text report
	reporter, err := report.New("text")
	if err != nil {
		t.Fatalf("failed to create text reporter: %v", err)
	}

	var buf bytes.Buffer
	err = reporter.Generate(ctx, result, &buf)
	if err != nil {
		t.Fatalf("failed to generate text report: %v", err)
	}

	output := buf.String()

	// Assert: output contains "SQL Injection Found"
	if !strings.Contains(output, "SQL Injection Found") {
		t.Errorf("text report should contain 'SQL Injection Found', got:\n%s", output)
	}

	// Assert: output contains target URL
	if !strings.Contains(output, "/vuln/error-mysql") {
		t.Errorf("text report should contain target URL, got:\n%s", output)
	}

	// Assert: format is "text"
	if reporter.Format() != "text" {
		t.Errorf("reporter.Format() = %q, want 'text'", reporter.Format())
	}
}

func TestIntegration_ContextCancellation(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/error-mysql?id=1",
		Method: "GET",
	}

	// Create context with immediate cancel
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := scanner.Scan(ctx, target)
	elapsed := time.Since(start)

	// Assert: scan should return quickly (not hang)
	if elapsed > 5*time.Second {
		t.Errorf("cancelled scan took too long: %v", elapsed)
	}

	// Assert: should return error from cancelled context
	if err == nil {
		t.Error("expected error from cancelled context, got nil")
	}
}

func TestIntegration_PostParameter(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:         srv.URL + "/vuln/post",
		Method:      "POST",
		Body:        "username=admin&password=secret",
		ContentType: "application/x-www-form-urlencoded",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	// Assert: vulnerability found in POST body parameter
	var foundInjectable bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Parameter.Name == "username" {
			foundInjectable = true
			break
		}
	}

	if !foundInjectable {
		t.Error("expected 'username' POST parameter to be injectable")
		t.Logf("vulnerabilities found: %d", len(result.Vulnerabilities))
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
}

func TestIntegration_TimeBased_MySQL(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()

	// Use short sleep (1s) with low tolerance so integration test stays fast.
	// The VulnServer handler sleeps min(n, 1s), so threshold = 0 + 0.3*1s = 300ms.
	// ForceTest=true bypasses heuristics: timebased endpoints show no content difference,
	// so heuristics would mark them as non-injectable without this flag.
	cfg := engine.DefaultScanConfig()
	cfg.ForceTest = true
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(timebased.NewWithConfig(1, 0.3))...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/timebased-mysql?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	var foundTimeBased bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Technique == "time-based" {
			foundTimeBased = true
		}
	}

	if !foundTimeBased {
		t.Error("expected time-based technique to detect vulnerability on /vuln/timebased-mysql")
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	t.Logf("request count: %d", result.RequestCount)
}

func TestIntegration_ErrorBased_MSSQL(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	scanner := newFullScanner(client, cfg)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/error-mssql?id=1",
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

	// Assert: at least 1 injectable vulnerability found
	var foundInjectable bool
	var foundErrorBased bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			if vuln.Technique == "error-based" {
				foundErrorBased = true
			}
		}
	}

	if !foundInjectable {
		t.Error("expected at least 1 injectable vulnerability, found none")
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	if !foundErrorBased {
		t.Error("expected error-based technique to detect MSSQL vulnerability")
	}

	// Assert: DBMS contains "MSSQL"
	if !strings.Contains(result.DBMS, "MSSQL") {
		t.Errorf("DBMS = %q, want to contain 'MSSQL'", result.DBMS)
	}
}

func TestIntegration_TimeBased_PostgreSQL(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()

	cfg := engine.DefaultScanConfig()
	cfg.ForceTest = true
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(timebased.NewWithConfig(1, 0.3))...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/timebased-postgres?id=1",
		Method: "GET",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	var foundTimeBased bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Technique == "time-based" {
			foundTimeBased = true
		}
	}

	if !foundTimeBased {
		t.Error("expected time-based technique to detect vulnerability on /vuln/timebased-postgres")
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	t.Logf("request count: %d", result.RequestCount)
}

func TestIntegration_UnionBased_MySQL(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	// ForceTest=true bypasses heuristics: the UNION endpoint returns the same
	// page for single-quote probes, so heuristics would skip it without this flag.
	cfg.ForceTest = true
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(union.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/union-mysql?id=1",
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

	var foundUnion bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Technique == "union-based" {
			foundUnion = true
		}
	}

	if !foundUnion {
		t.Error("expected union-based technique to detect vulnerability on /vuln/union-mysql")
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	t.Logf("request count: %d", result.RequestCount)
}

func TestIntegration_UnionBased_PostgreSQL(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	client := newTestClient()
	cfg := engine.DefaultScanConfig()
	cfg.ForceTest = true
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(union.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	target := &engine.ScanTarget{
		URL:    srv.URL + "/vuln/union-postgres?id=1",
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

	var foundUnion bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Technique == "union-based" {
			foundUnion = true
		}
	}

	if !foundUnion {
		t.Error("expected union-based technique to detect vulnerability on /vuln/union-postgres")
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	t.Logf("request count: %d", result.RequestCount)
}
