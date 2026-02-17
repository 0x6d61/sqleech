// Package detector provides parameter extraction and SQL injection detection.
package detector

import (
	"context"
	"fmt"
	"net/url"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/transport"
)

// defaultThreshold is the default similarity threshold. Responses with a
// body ratio below this value are considered "different".
const defaultThreshold = 0.98

// HeuristicResult contains results of initial heuristic checks for a parameter.
type HeuristicResult struct {
	Parameter       engine.Parameter
	Baseline        *transport.Response
	CausesError     bool                // Single quote causes DB error
	DynamicContent  bool                // Parameter value affects response
	ErrorSignatures map[string][]string // DBMS -> matched errors
	PageRatio       float64             // Similarity between baseline and error probe
	IsInjectable    bool                // Overall heuristic assessment
}

// HeuristicDetector performs quick probes to identify injectable parameters.
type HeuristicDetector struct {
	client     transport.Client
	diffEngine *DiffEngine
	threshold  float64 // Default 0.98 - responses below this ratio are "different"
}

// NewHeuristicDetector creates a new detector with the default threshold.
func NewHeuristicDetector(client transport.Client, diffEngine *DiffEngine) *HeuristicDetector {
	return &HeuristicDetector{
		client:     client,
		diffEngine: diffEngine,
		threshold:  defaultThreshold,
	}
}

// DetectAll tests all parameters and returns heuristic results.
// It sends a baseline request first, then probes each parameter.
func (d *HeuristicDetector) DetectAll(ctx context.Context, target *engine.ScanTarget) ([]HeuristicResult, error) {
	if len(target.Parameters) == 0 {
		return nil, nil
	}

	// Send baseline request
	baselineReq := buildBaselineRequest(target)
	baseline, err := d.client.Do(ctx, baselineReq)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	var results []HeuristicResult
	for _, param := range target.Parameters {
		result, err := d.detectParameter(ctx, target, param, baseline)
		if err != nil {
			return nil, fmt.Errorf("detecting parameter %q: %w", param.Name, err)
		}
		results = append(results, *result)
	}

	return results, nil
}

// detectParameter performs heuristic probes on a single parameter.
func (d *HeuristicDetector) detectParameter(ctx context.Context, target *engine.ScanTarget, param engine.Parameter, baseline *transport.Response) (*HeuristicResult, error) {
	result := &HeuristicResult{
		Parameter:       param,
		Baseline:        baseline,
		ErrorSignatures: make(map[string][]string),
	}

	// --- Probe 1: Error probe (append single quote) ---
	errorPayload := param.Value + "'"
	errorResp, err := d.sendProbe(ctx, target, param, errorPayload)
	if err != nil {
		return nil, fmt.Errorf("error probe: %w", err)
	}

	// Check for SQL error signatures in the error probe response
	sqlErrors := FindSQLErrors(errorResp.Body)
	if len(sqlErrors) > 0 {
		result.CausesError = true
		result.ErrorSignatures = sqlErrors
	}

	// Compute page ratio between baseline and error response
	result.PageRatio = d.diffEngine.Ratio(baseline.Body, errorResp.Body)

	// --- Probe 2: Boolean TRUE probe ---
	var truePayload string
	if param.Type == engine.TypeInteger || param.Type == engine.TypeFloat {
		truePayload = param.Value + " AND 1=1"
	} else {
		truePayload = param.Value + "' AND '1'='1"
	}

	trueResp, err := d.sendProbe(ctx, target, param, truePayload)
	if err != nil {
		return nil, fmt.Errorf("boolean true probe: %w", err)
	}

	trueRatio := d.diffEngine.Ratio(baseline.Body, trueResp.Body)

	// --- Probe 3: Boolean FALSE probe ---
	var falsePayload string
	if param.Type == engine.TypeInteger || param.Type == engine.TypeFloat {
		falsePayload = param.Value + " AND 1=2"
	} else {
		falsePayload = param.Value + "' AND '1'='2"
	}

	falseResp, err := d.sendProbe(ctx, target, param, falsePayload)
	if err != nil {
		return nil, fmt.Errorf("boolean false probe: %w", err)
	}

	falseRatio := d.diffEngine.Ratio(baseline.Body, falseResp.Body)

	// Check if response is dynamic (FALSE probe differs from baseline)
	if d.diffEngine.IsDifferent(baseline.Body, falseResp.Body, d.threshold) {
		result.DynamicContent = true
	}

	// --- Probe 4: Numeric overflow (only for integer types) ---
	if param.Type == engine.TypeInteger {
		_, err := d.sendProbe(ctx, target, param, "99999999999")
		if err != nil {
			return nil, fmt.Errorf("numeric overflow probe: %w", err)
		}
		// Overflow response is collected but not currently used in the
		// injectable decision -- future enhancements may leverage it.
	}

	// --- Decision logic ---
	// A parameter is heuristically injectable if:
	// 1. Error probe causes SQL error signatures, OR
	// 2. TRUE probe matches baseline AND FALSE probe differs from baseline
	booleanInjectable := trueRatio >= d.threshold && falseRatio < d.threshold

	result.IsInjectable = result.CausesError || booleanInjectable

	return result, nil
}

// sendProbe sends a request with a modified parameter value and returns the response.
func (d *HeuristicDetector) sendProbe(ctx context.Context, target *engine.ScanTarget, param engine.Parameter, payload string) (*transport.Response, error) {
	req := buildProbeRequest(target, param, payload)
	return d.client.Do(ctx, req)
}

// buildProbeRequest creates a request with the given parameter modified to the payload value.
// If param.Location == LocationQuery, the URL query parameter is modified.
// If param.Location == LocationBody, the POST body parameter is modified.
// All other parameters are preserved unchanged.
func buildProbeRequest(target *engine.ScanTarget, param engine.Parameter, payload string) *transport.Request {
	req := &transport.Request{
		Method:      target.Method,
		URL:         target.URL,
		Body:        target.Body,
		ContentType: target.ContentType,
	}

	// Copy headers
	if target.Headers != nil {
		req.Headers = make(map[string]string, len(target.Headers))
		for k, v := range target.Headers {
			req.Headers[k] = v
		}
	}

	// Copy cookies
	if target.Cookies != nil {
		req.Cookies = make(map[string]string, len(target.Cookies))
		for k, v := range target.Cookies {
			req.Cookies[k] = v
		}
	}

	switch param.Location {
	case engine.LocationQuery:
		req.URL = modifyQueryParam(target.URL, param.Name, payload)
	case engine.LocationBody:
		req.Body = modifyBodyParam(target.Body, param.Name, payload)
	}

	return req
}

// buildBaselineRequest creates a request with original parameter values.
func buildBaselineRequest(target *engine.ScanTarget) *transport.Request {
	req := &transport.Request{
		Method:      target.Method,
		URL:         target.URL,
		Body:        target.Body,
		ContentType: target.ContentType,
	}

	// Copy headers
	if target.Headers != nil {
		req.Headers = make(map[string]string, len(target.Headers))
		for k, v := range target.Headers {
			req.Headers[k] = v
		}
	}

	// Copy cookies
	if target.Cookies != nil {
		req.Cookies = make(map[string]string, len(target.Cookies))
		for k, v := range target.Cookies {
			req.Cookies[k] = v
		}
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
