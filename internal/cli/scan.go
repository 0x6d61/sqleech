package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"

	"github.com/0x6d61/sqleech/internal/detector"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/fingerprint"
	"github.com/0x6d61/sqleech/internal/report"
	"github.com/0x6d61/sqleech/internal/session"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/technique/boolean"
	"github.com/0x6d61/sqleech/internal/technique/errorbased"
	"github.com/0x6d61/sqleech/internal/technique/timebased"
	"github.com/0x6d61/sqleech/internal/transport"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target URL for SQL injection vulnerabilities",
	Long: `Scan performs SQL injection detection against the specified target URL.
It tests all discovered parameters using the configured techniques.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	// Session flag is scan-specific (not shared with other commands)
	scanCmd.Flags().String("session", "", "Session file path for saving/resuming scans (SQLite)")
}

// runScan is the main scan command handler. It wires up the full scanner
// pipeline: transport → heuristics → fingerprinting → techniques → report.
func runScan(cmd *cobra.Command, args []string) error {
	fmt.Println("[!] Legal disclaimer: Usage of sqleech for attacking targets without prior mutual consent is illegal.")

	// ------------------------------------------------------------------ //
	// 1. Read flags
	// ------------------------------------------------------------------ //
	targetURL, _ := cmd.Flags().GetString("url")
	if targetURL == "" {
		return fmt.Errorf("target URL is required (use --url or -u)")
	}

	method, _ := cmd.Flags().GetString("method")
	data, _ := cmd.Flags().GetString("data")
	cookieStr, _ := cmd.Flags().GetString("cookie")
	rawHeaders, _ := cmd.Flags().GetStringArray("header")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	forceSSL, _ := cmd.Flags().GetBool("force-ssl")
	randomAgent, _ := cmd.Flags().GetBool("random-agent")
	verbose, _ := cmd.Flags().GetInt("verbose")
	outputPath, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	dbmsHint, _ := cmd.Flags().GetString("dbms")
	techniqueStr, _ := cmd.Flags().GetString("technique")
	forceTest, _ := cmd.Flags().GetBool("force-test")
	threads, _ := cmd.Flags().GetInt("threads")
	sessionPath, _ := cmd.Flags().GetString("session")

	// ------------------------------------------------------------------ //
	// 2. Normalize URL and method
	// ------------------------------------------------------------------ //
	if forceSSL {
		targetURL = strings.Replace(targetURL, "http://", "https://", 1)
		if !strings.HasPrefix(targetURL, "https://") {
			targetURL = "https://" + targetURL
		}
	}
	if data != "" && method == "GET" {
		method = "POST"
	}

	headers := parseHeaders(rawHeaders)
	cookies := parseCookieString(cookieStr)

	// ------------------------------------------------------------------ //
	// 3. Transport client
	// ------------------------------------------------------------------ //
	client, err := transport.NewClient(transport.ClientOptions{
		Timeout:         timeout,
		ProxyURL:        proxyURL,
		FollowRedirects: true,
		RandomUserAgent: randomAgent,
	})
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// ------------------------------------------------------------------ //
	// 4. ScanConfig
	// ------------------------------------------------------------------ //
	cfg := engine.DefaultScanConfig()
	cfg.Threads = threads
	cfg.Verbose = verbose
	cfg.DBMSHint = dbmsHint
	cfg.ForceTest = forceTest
	if techniqueStr != "" {
		// Split on comma, normalise to upper-case.
		// Accepted codes: E (error-based), B (boolean-blind), T (time-based)
		for _, code := range strings.Split(techniqueStr, ",") {
			code = strings.TrimSpace(strings.ToUpper(code))
			if code != "" {
				cfg.Techniques = append(cfg.Techniques, code)
			}
		}
	}

	// ------------------------------------------------------------------ //
	// 5. Context (CTRL+C cancels the scan gracefully)
	// ------------------------------------------------------------------ //
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// ------------------------------------------------------------------ //
	// 6. Session (optional): try to load previous state for this target
	// ------------------------------------------------------------------ //
	var store session.Store
	if sessionPath != "" {
		s, err := session.NewSQLiteStore(sessionPath)
		if err != nil {
			return fmt.Errorf("failed to open session file %q: %w", sessionPath, err)
		}
		defer s.Close()
		store = s

		if existing, err := store.Load(ctx, targetURL); err == nil && existing != nil {
			fmt.Printf("[*] Resuming session %s (progress %.0f%%)\n",
				existing.ID, existing.Progress*100)
		}
	}

	// ------------------------------------------------------------------ //
	// 7. Build scanner
	// ------------------------------------------------------------------ //
	scanner := buildScanner(client, cfg)

	if verbose > 0 {
		scanner.SetProgressCallback(func(msg string) {
			fmt.Printf("[*] %s\n", msg)
		})
		fmt.Printf("[*] Target: %s\n", targetURL)
		fmt.Printf("[*] Method: %s\n", method)
		if len(cfg.Techniques) > 0 {
			fmt.Printf("[*] Techniques: %s\n", strings.Join(cfg.Techniques, ","))
		}
		if proxyURL != "" {
			fmt.Printf("[*] Proxy: %s\n", proxyURL)
		}
	}

	// ------------------------------------------------------------------ //
	// 8. Build ScanTarget
	// ------------------------------------------------------------------ //
	target := &engine.ScanTarget{
		URL:     targetURL,
		Method:  method,
		Headers: headers,
		Body:    data,
		Cookies: cookies,
	}
	if data != "" {
		if _, hasContentType := headers["Content-Type"]; !hasContentType {
			target.ContentType = "application/x-www-form-urlencoded"
		}
	}

	// ------------------------------------------------------------------ //
	// 9. Run scan
	// ------------------------------------------------------------------ //
	fmt.Printf("[*] Starting scan against: %s\n", targetURL)

	result, err := scanner.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	// ------------------------------------------------------------------ //
	// 10. Save to session
	// ------------------------------------------------------------------ //
	if store != nil && result != nil {
		state := scanResultToState(result)
		if saveErr := store.Save(ctx, state); saveErr != nil && verbose > 0 {
			fmt.Fprintf(os.Stderr, "[!] Failed to save session: %v\n", saveErr)
		}
	}

	// ------------------------------------------------------------------ //
	// 11. Generate report
	// ------------------------------------------------------------------ //
	reporter, err := report.New(format)
	if err != nil {
		return fmt.Errorf("unknown report format %q: %w", format, err)
	}

	out := os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file %q: %w", outputPath, err)
		}
		defer f.Close()
		out = f
	}

	if err := reporter.Generate(ctx, result, out); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}

// --------------------------------------------------------------------------
// Scanner wiring helpers
// --------------------------------------------------------------------------

// buildScanner creates an engine.Scanner wired with all real implementations:
// error-based, boolean-blind, time-based techniques; the heuristic detector;
// the DBMS fingerprinter; and the parameter parser.
func buildScanner(client transport.Client, cfg *engine.ScanConfig) *engine.Scanner {
	return engine.NewScanner(client, cfg,
		engine.WithTechniques(
			wrapTechnique(errorbased.New()),
			wrapTechnique(boolean.New()),
			wrapTechnique(timebased.New()),
		),
		engine.WithParameterParser(buildParamParser()),
		engine.WithHeuristicDetector(buildHeuristicDetector(client)),
		engine.WithDBMSIdentifier(buildDBMSIdentifier()),
		engine.WithFingerprinter(buildFingerprinter()),
	)
}

// techniqueAdapter bridges technique.Technique → engine.Technique.
type techniqueAdapter struct{ inner technique.Technique }

func (a *techniqueAdapter) Name() string  { return a.inner.Name() }
func (a *techniqueAdapter) Priority() int { return a.inner.Priority() }
func (a *techniqueAdapter) Detect(ctx context.Context, req *engine.TechniqueRequest) (*engine.DetectionResult, error) {
	r, err := a.inner.Detect(ctx, &technique.InjectionRequest{
		Target:    req.Target,
		Parameter: req.Parameter,
		Baseline:  req.Baseline,
		DBMS:      req.DBMS,
		Client:    req.Client,
	})
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

func wrapTechnique(t technique.Technique) engine.Technique {
	return &techniqueAdapter{inner: t}
}

func buildParamParser() engine.ParameterParser {
	return func(rawURL, body, contentType string) []engine.Parameter {
		return detector.ParseParameters(rawURL, body, contentType)
	}
}

func buildHeuristicDetector(client transport.Client) engine.HeuristicDetectorFunc {
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

func buildDBMSIdentifier() engine.DBMSIdentifierFunc {
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

func buildFingerprinter() engine.FingerprintFunc {
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

// --------------------------------------------------------------------------
// Session helpers
// --------------------------------------------------------------------------

// scanResultToState converts an engine.ScanResult to a session.ScanState
// for persistence. Vulnerabilities are serialised as generic JSON objects.
func scanResultToState(result *engine.ScanResult) *session.ScanState {
	// Marshal vulnerabilities to generic interface{} via JSON round-trip.
	var vulns []interface{}
	if b, err := json.Marshal(result.Vulnerabilities); err == nil {
		_ = json.Unmarshal(b, &vulns)
	}

	progress := 1.0
	if len(result.Vulnerabilities) == 0 {
		progress = 1.0 // scan finished, nothing found
	}

	return &session.ScanState{
		TargetURL:       result.Target.URL,
		Vulnerabilities: vulns,
		DBMS:            result.DBMS,
		DBMSVersion:     result.DBMSVersion,
		Progress:        progress,
	}
}

// --------------------------------------------------------------------------
// Flag helpers (kept from original scan.go)
// --------------------------------------------------------------------------

// parseCookieString parses a cookie header string (e.g., "name1=val1; name2=val2")
// into a map of name->value pairs.
func parseCookieString(raw string) map[string]string {
	cookies := make(map[string]string)
	if raw == "" {
		return cookies
	}
	pairs := strings.Split(raw, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			cookies[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return cookies
}

// parseHeaders parses header strings (e.g., "X-Custom: value") into a map.
func parseHeaders(rawHeaders []string) map[string]string {
	headers := make(map[string]string)
	for _, h := range rawHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}
