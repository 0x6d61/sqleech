//go:build e2e

// Package e2e contains end-to-end tests that require the Docker test
// environment defined in testenv/docker-compose.yml.
//
// Run with:
//
//	make e2e
//
// Or manually:
//
//	cd testenv && docker compose up -d --build --wait
//	go test -v -tags e2e -count=1 -timeout 120s ./e2e/...
package e2e_test

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/sqleech/internal/detector"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/fingerprint"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/technique/boolean"
	"github.com/0x6d61/sqleech/internal/technique/errorbased"
	"github.com/0x6d61/sqleech/internal/technique/timebased"
	"github.com/0x6d61/sqleech/internal/transport"
)

const defaultE2EURL = "http://localhost:18080"

// e2eBaseURL returns the base URL of the test environment.
// If the server is unreachable, the test is skipped automatically.
func e2eBaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("SQLEECH_E2E_URL")
	if url == "" {
		url = defaultE2EURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/health", nil)
	if err != nil {
		t.Skipf("cannot build health-check request for %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Skipf("E2E server not available at %s (start with: make e2e-up): %v", url, err)
	}
	return url
}

// newE2EClient creates a real HTTP transport client suitable for E2E testing.
func newE2EClient(t *testing.T) transport.Client {
	t.Helper()
	client, err := transport.NewClient(transport.ClientOptions{
		Timeout:         30 * time.Second,
		FollowRedirects: true,
	})
	if err != nil {
		t.Fatalf("failed to create transport client: %v", err)
	}
	return client
}

// --------------------------------------------------------------------------
// Dependency-injection adapters (mirror of internal/testutil/integration_test.go)
// --------------------------------------------------------------------------

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

func wrapTechniques(techs ...technique.Technique) []engine.Technique {
	out := make([]engine.Technique, len(techs))
	for i, t := range techs {
		out[i] = &techniqueAdapter{inner: t}
	}
	return out
}

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

func makeParamParser() engine.ParameterParser {
	return func(rawURL, body, contentType string) []engine.Parameter {
		return detector.ParseParameters(rawURL, body, contentType)
	}
}

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
// E2E Tests
// --------------------------------------------------------------------------

func TestE2E_MySQL_ErrorBased(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)
	scanner := newFullScanner(client, engine.DefaultScanConfig())

	target := &engine.ScanTarget{
		URL:    base + "/mysql/user?id=1",
		Method: http.MethodGet,
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var foundInjectable, foundErrorBased bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			if vuln.Technique == "error-based" {
				foundErrorBased = true
			}
		}
	}

	if !foundInjectable {
		t.Error("expected at least 1 injectable vulnerability")
	}
	if !foundErrorBased {
		t.Error("expected error-based technique to detect the vulnerability")
	}
	if !strings.Contains(result.DBMS, "MySQL") {
		t.Errorf("DBMS = %q, want to contain 'MySQL'", result.DBMS)
	}
	t.Logf("DBMS: %s, request count: %d", result.DBMS, result.RequestCount)
}

func TestE2E_PostgreSQL_ErrorBased(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)
	scanner := newFullScanner(client, engine.DefaultScanConfig())

	target := &engine.ScanTarget{
		URL:    base + "/pg/user?id=1",
		Method: http.MethodGet,
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

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
	if !strings.Contains(result.DBMS, "PostgreSQL") {
		t.Errorf("DBMS = %q, want to contain 'PostgreSQL'", result.DBMS)
	}
	t.Logf("DBMS: %s, request count: %d", result.DBMS, result.RequestCount)
}

func TestE2E_MySQL_SearchEndpoint(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)
	scanner := newFullScanner(client, engine.DefaultScanConfig())

	// LIKE '%<q>%' context injection
	target := &engine.ScanTarget{
		URL:    base + "/mysql/search?q=widget",
		Method: http.MethodGet,
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var foundInjectable bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			break
		}
	}

	if !foundInjectable {
		t.Error("expected injection to be detected in LIKE-context search endpoint")
	}
	t.Logf("vulnerabilities: %d, request count: %d", len(result.Vulnerabilities), result.RequestCount)
}

func TestE2E_PostgreSQL_SearchEndpoint(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)
	scanner := newFullScanner(client, engine.DefaultScanConfig())

	// ILIKE '%<q>%' context injection
	target := &engine.ScanTarget{
		URL:    base + "/pg/search?q=widget",
		Method: http.MethodGet,
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var foundInjectable bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			break
		}
	}

	if !foundInjectable {
		t.Error("expected injection to be detected in ILIKE-context search endpoint")
	}
	t.Logf("vulnerabilities: %d, request count: %d", len(result.Vulnerabilities), result.RequestCount)
}

func TestE2E_SafeEndpoint(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)
	scanner := newFullScanner(client, engine.DefaultScanConfig())

	// Parameterized query — should NOT be detected as injectable
	target := &engine.ScanTarget{
		URL:    base + "/safe/mysql/user?id=1",
		Method: http.MethodGet,
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			t.Errorf("false positive: safe endpoint reported injectable (param=%s, technique=%s)",
				vuln.Parameter.Name, vuln.Technique)
		}
	}
	t.Logf("injectable count: 0 (expected), request count: %d", result.RequestCount)
}

func TestE2E_POST_MySQL(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)
	scanner := newFullScanner(client, engine.DefaultScanConfig())

	target := &engine.ScanTarget{
		URL:         base + "/mysql/login",
		Method:      http.MethodPost,
		Body:        "username=admin&password=secret",
		ContentType: "application/x-www-form-urlencoded",
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var foundInjectable bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable {
			foundInjectable = true
			break
		}
	}

	if !foundInjectable {
		t.Error("expected injection to be detected in POST login endpoint")
		t.Logf("vulnerabilities found: %d", len(result.Vulnerabilities))
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	t.Logf("request count: %d", result.RequestCount)
}

func TestE2E_TimeBased_MySQL(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)

	// Use a dedicated time-based scanner with ForceTest=true.
	// The /mysql/sleep endpoint only differs in response TIME, not content,
	// so heuristics would skip it without ForceTest.
	cfg := engine.DefaultScanConfig()
	cfg.ForceTest = true
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(timebased.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	target := &engine.ScanTarget{
		URL:    base + "/mysql/sleep?id=1",
		Method: http.MethodGet,
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var foundTimeBased bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Technique == "time-based" {
			foundTimeBased = true
		}
	}

	if !foundTimeBased {
		t.Error("expected time-based injection to be detected on /mysql/sleep")
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	t.Logf("request count: %d", result.RequestCount)
}

func TestE2E_TimeBased_PostgreSQL(t *testing.T) {
	base := e2eBaseURL(t)
	client := newE2EClient(t)

	cfg := engine.DefaultScanConfig()
	cfg.ForceTest = true
	scanner := engine.NewScanner(client, cfg,
		engine.WithTechniques(wrapTechniques(timebased.New())...),
		engine.WithParameterParser(makeParamParser()),
		engine.WithHeuristicDetector(makeHeuristicFunc(client)),
		engine.WithDBMSIdentifier(makeDBMSIdentifier()),
		engine.WithFingerprinter(makeFingerprinter()),
	)

	target := &engine.ScanTarget{
		URL:    base + "/pg/sleep?id=1",
		Method: http.MethodGet,
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var foundTimeBased bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Injectable && vuln.Technique == "time-based" {
			foundTimeBased = true
		}
	}

	if !foundTimeBased {
		t.Error("expected time-based injection to be detected on /pg/sleep")
		for _, v := range result.Vulnerabilities {
			t.Logf("  param=%s technique=%s injectable=%v", v.Parameter.Name, v.Technique, v.Injectable)
		}
	}
	t.Logf("request count: %d", result.RequestCount)
}
