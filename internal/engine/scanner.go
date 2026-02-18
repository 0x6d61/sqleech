package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/0x6d61/sqleech/internal/transport"
)

// ScanConfig holds configuration for a scan.
type ScanConfig struct {
	Threads    int      // Number of concurrent workers (default 10)
	Verbose    int      // Verbosity level 0-3
	Techniques []string // Filter: "E" (error), "B" (boolean). Empty = all.
	DBMSHint   string   // DBMS hint to skip fingerprinting
	ForceTest  bool     // Test all params even if heuristics say safe
}

// DefaultScanConfig returns sensible defaults.
func DefaultScanConfig() *ScanConfig {
	return &ScanConfig{
		Threads: 10,
		Verbose: 0,
	}
}

// --------------------------------------------------------------------------
// Interfaces for dependency injection (break import cycles)
// --------------------------------------------------------------------------

// ParameterParser extracts parameters from URL/body.
type ParameterParser func(rawURL, body, contentType string) []Parameter

// HeuristicResult contains results of initial heuristic checks for a parameter.
type HeuristicResult struct {
	Parameter       Parameter
	Baseline        *transport.Response
	CausesError     bool
	DynamicContent  bool
	ErrorSignatures map[string][]string
	PageRatio       float64
	IsInjectable    bool
}

// HeuristicDetectorFunc runs heuristic detection on all parameters of a target.
type HeuristicDetectorFunc func(ctx context.Context, target *ScanTarget) ([]HeuristicResult, error)

// DBMSInfo contains identified DBMS information.
type DBMSInfo struct {
	Name       string
	Version    string
	Banner     string
	Confidence float64
}

// DBMSIdentifierFunc identifies DBMS from error signatures (fast-path).
type DBMSIdentifierFunc func(errorSignatures map[string][]string) *DBMSInfo

// FingerprintFunc runs full DBMS fingerprinting probes.
type FingerprintFunc func(ctx context.Context, target *ScanTarget, param *Parameter, baseline *transport.Response, client transport.Client) (*DBMSInfo, error)

// Technique defines a SQL injection detection method.
type Technique interface {
	Name() string
	Priority() int
	Detect(ctx context.Context, req *TechniqueRequest) (*DetectionResult, error)
}

// TechniqueRequest contains everything needed to test an injection point.
type TechniqueRequest struct {
	Target    *ScanTarget
	Parameter *Parameter
	Baseline  *transport.Response
	DBMS      string
	Client    transport.Client
}

// DetectionResult indicates whether injection was detected.
type DetectionResult struct {
	Injectable bool
	Confidence float64
	Technique  string
	Payload    string
	Evidence   string
}

// --------------------------------------------------------------------------
// Scanner
// --------------------------------------------------------------------------

// Scanner orchestrates the full scan pipeline.
type Scanner struct {
	client        transport.Client
	config        *ScanConfig
	logger        *slog.Logger
	techniques    []Technique
	parseParams   ParameterParser
	heuristicFunc HeuristicDetectorFunc
	identifyFunc  DBMSIdentifierFunc
	fpFunc        FingerprintFunc

	// Progress callback
	onProgress func(msg string)
}

// ScannerOption configures a Scanner.
type ScannerOption func(*Scanner)

// WithTechniques sets the techniques available to the scanner.
func WithTechniques(techs ...Technique) ScannerOption {
	return func(s *Scanner) {
		s.techniques = techs
	}
}

// WithParameterParser sets the function used to parse parameters.
func WithParameterParser(fn ParameterParser) ScannerOption {
	return func(s *Scanner) {
		s.parseParams = fn
	}
}

// WithHeuristicDetector sets the heuristic detection function.
func WithHeuristicDetector(fn HeuristicDetectorFunc) ScannerOption {
	return func(s *Scanner) {
		s.heuristicFunc = fn
	}
}

// WithDBMSIdentifier sets the fast-path DBMS identification function.
func WithDBMSIdentifier(fn DBMSIdentifierFunc) ScannerOption {
	return func(s *Scanner) {
		s.identifyFunc = fn
	}
}

// WithFingerprinter sets the full DBMS fingerprinting function.
func WithFingerprinter(fn FingerprintFunc) ScannerOption {
	return func(s *Scanner) {
		s.fpFunc = fn
	}
}

// techniqueFilterMap maps single-character technique codes to technique names.
var techniqueFilterMap = map[string]string{
	"E": "error-based",
	"B": "boolean-blind",
	"T": "time-based",
	"U": "union-based",
}

// NewScanner creates a scanner with all components wired up.
func NewScanner(client transport.Client, config *ScanConfig, opts ...ScannerOption) *Scanner {
	if config == nil {
		config = DefaultScanConfig()
	}

	// Create logger with configured verbosity level.
	logLevel := slog.LevelError
	switch {
	case config.Verbose >= 3:
		logLevel = slog.LevelDebug
	case config.Verbose >= 2:
		logLevel = slog.LevelInfo
	case config.Verbose >= 1:
		logLevel = slog.LevelWarn
	}

	logger := slog.New(slog.NewTextHandler(
		discardWriter{},
		&slog.HandlerOptions{Level: logLevel},
	))

	s := &Scanner{
		client: client,
		config: config,
		logger: logger,
	}

	// Apply options.
	for _, opt := range opts {
		opt(s)
	}

	// Filter techniques if a filter is specified.
	if len(config.Techniques) > 0 && len(s.techniques) > 0 {
		allowedNames := make(map[string]bool)
		for _, code := range config.Techniques {
			if name, ok := techniqueFilterMap[code]; ok {
				allowedNames[name] = true
			}
		}
		var filtered []Technique
		for _, t := range s.techniques {
			if allowedNames[t.Name()] {
				filtered = append(filtered, t)
			}
		}
		s.techniques = filtered
	}

	// Sort techniques by priority (lower = higher priority).
	sort.Slice(s.techniques, func(i, j int) bool {
		return s.techniques[i].Priority() < s.techniques[j].Priority()
	})

	return s
}

// TechniqueNames returns the names of all loaded techniques in priority order.
func (s *Scanner) TechniqueNames() []string {
	names := make([]string, len(s.techniques))
	for i, t := range s.techniques {
		names[i] = t.Name()
	}
	return names
}

// SetProgressCallback sets a function called with status messages.
func (s *Scanner) SetProgressCallback(fn func(string)) {
	s.onProgress = fn
}

// progress sends a status message via the progress callback if set.
func (s *Scanner) progress(format string, args ...any) {
	if s.onProgress != nil {
		s.onProgress(fmt.Sprintf(format, args...))
	}
}

// Scan runs the full pipeline against a target.
//
// Pipeline:
//  1. Parse parameters (if target.Parameters is empty, parse from URL/body)
//  2. Send baseline request
//  3. Run heuristic detection on all parameters
//  4. Filter to potentially injectable parameters
//  5. Run DBMS fingerprinting (use heuristic error signatures as fast-path)
//  6. For each injectable parameter, run techniques via worker pool
//  7. Aggregate results
func (s *Scanner) Scan(ctx context.Context, target *ScanTarget) (*ScanResult, error) {
	result := &ScanResult{
		Target:    *target,
		StartTime: time.Now(),
	}

	defer func() {
		result.EndTime = time.Now()
		if stats := s.client.Stats(); stats != nil {
			result.RequestCount = stats.TotalRequests
		}
	}()

	// Step 0: Check context before starting.
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("scan cancelled before start: %w", err)
	}

	// Step 1: Parse parameters if not provided.
	if len(target.Parameters) == 0 && s.parseParams != nil {
		target.Parameters = s.parseParams(target.URL, target.Body, target.ContentType)
	}

	if len(target.Parameters) == 0 {
		s.progress("no parameters found in target")
		return result, nil
	}

	s.progress("found %d parameter(s) to test", len(target.Parameters))

	// Step 2: Send baseline request.
	baselineReq := buildBaselineRequest(target)
	baseline, err := s.client.Do(ctx, baselineReq)
	if err != nil {
		return result, fmt.Errorf("baseline request failed: %w", err)
	}
	s.progress("baseline request completed (status %d, %d bytes)", baseline.StatusCode, len(baseline.Body))

	// Step 3: Run heuristic detection on all parameters.
	type paramInfo struct {
		param           Parameter
		baseline        *transport.Response
		errorSignatures map[string][]string
	}

	var injectableParams []paramInfo

	if s.heuristicFunc != nil {
		heuristicResults, hErr := s.heuristicFunc(ctx, target)
		if hErr != nil {
			s.logger.Warn("heuristic detection failed", "error", hErr)
			result.Errors = append(result.Errors, fmt.Errorf("heuristic detection: %w", hErr))
		}

		// Step 4: Filter to injectable parameters.
		if heuristicResults != nil {
			for _, hr := range heuristicResults {
				if hr.IsInjectable || s.config.ForceTest {
					s.progress("parameter %q is potentially injectable (heuristic)", hr.Parameter.Name)
					pi := paramInfo{
						param:           hr.Parameter,
						baseline:        hr.Baseline,
						errorSignatures: hr.ErrorSignatures,
					}
					injectableParams = append(injectableParams, pi)
				}
			}
		}

		// If heuristics failed but ForceTest is on, use all parameters.
		if heuristicResults == nil && s.config.ForceTest {
			for _, p := range target.Parameters {
				injectableParams = append(injectableParams, paramInfo{
					param:    p,
					baseline: baseline,
				})
			}
		}
	} else {
		// No heuristic function configured: test all parameters directly.
		for _, p := range target.Parameters {
			injectableParams = append(injectableParams, paramInfo{
				param:    p,
				baseline: baseline,
			})
		}
	}

	if len(injectableParams) == 0 {
		s.progress("no injectable parameters found")
		return result, nil
	}

	// Step 5: DBMS fingerprinting.
	dbmsName := s.config.DBMSHint
	if dbmsName == "" && s.identifyFunc != nil {
		// Fast-path: try to identify from error signatures already collected.
		for _, pi := range injectableParams {
			if len(pi.errorSignatures) > 0 {
				info := s.identifyFunc(pi.errorSignatures)
				if info != nil {
					dbmsName = info.Name
					s.progress("DBMS identified from error signatures: %s (confidence %.0f%%)", info.Name, info.Confidence*100)
					break
				}
			}
		}
	}

	if dbmsName == "" && s.fpFunc != nil && len(injectableParams) > 0 {
		// Slow-path: run full fingerprinting probes.
		pi := injectableParams[0]
		info, fpErr := s.fpFunc(ctx, target, &pi.param, pi.baseline, s.client)
		if fpErr != nil {
			s.logger.Warn("fingerprinting failed", "error", fpErr)
			result.Errors = append(result.Errors, fmt.Errorf("fingerprinting: %w", fpErr))
		} else if info != nil {
			dbmsName = info.Name
			result.DBMSVersion = info.Version
			s.progress("DBMS identified: %s %s (confidence %.0f%%)", info.Name, info.Version, info.Confidence*100)
		}
	}

	result.DBMS = dbmsName
	s.progress("using DBMS: %s", dbmsName)

	// Step 6: Run techniques via worker pool.
	if len(s.techniques) == 0 {
		s.progress("no techniques configured")
		return result, nil
	}

	pool := newWorkerPool(s.config.Threads)

	pool.start(ctx, s.client, target)

	// Submit all jobs: each injectable parameter x each technique.
	jobCount := 0
	for _, pi := range injectableParams {
		for _, tech := range s.techniques {
			pool.submit(job{
				parameter: pi.param,
				technique: tech,
				baseline:  pi.baseline,
				dbms:      dbmsName,
			})
			jobCount++
		}
	}
	s.progress("submitted %d detection jobs to %d workers", jobCount, s.config.Threads)

	pool.close()

	// Step 7: Aggregate results.
	for vuln := range pool.results {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	// Count injectable findings.
	injectableCount := 0
	for _, v := range result.Vulnerabilities {
		if v.Injectable {
			injectableCount++
		}
	}
	s.progress("scan complete: %d vulnerability findings (%d injectable)", len(result.Vulnerabilities), injectableCount)

	return result, nil
}

// buildBaselineRequest creates a transport.Request from a ScanTarget with
// original parameter values.
func buildBaselineRequest(target *ScanTarget) *transport.Request {
	req := &transport.Request{
		Method:      target.Method,
		URL:         target.URL,
		Body:        target.Body,
		ContentType: target.ContentType,
	}

	if target.Headers != nil {
		req.Headers = make(map[string]string, len(target.Headers))
		for k, v := range target.Headers {
			req.Headers[k] = v
		}
	}

	if target.Cookies != nil {
		req.Cookies = make(map[string]string, len(target.Cookies))
		for k, v := range target.Cookies {
			req.Cookies[k] = v
		}
	}

	return req
}

// discardWriter is an io.Writer that discards all data (used for quiet logging).
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
