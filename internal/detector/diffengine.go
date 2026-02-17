package detector

import (
	"fmt"
	"regexp"
	"strings"
)

// ResponseData holds an HTTP response for comparison.
type ResponseData struct {
	StatusCode    int
	Headers       map[string][]string
	Body          []byte
	ContentLength int64
}

// DiffResult holds the result of comparing two HTTP responses.
type DiffResult struct {
	StatusCodeChanged  bool
	ContentLengthDelta int64
	BodyRatio          float64
	HeaderDiffs        map[string][2]string
	KeywordMatches     []string
}

// DiffEngine compares HTTP responses to detect behavioral differences.
type DiffEngine struct {
	DynamicPatterns []*regexp.Regexp
}

// NewDiffEngine creates a DiffEngine with default dynamic content patterns.
// These patterns strip session IDs, CSRF tokens, timestamps, and other
// dynamic values that change between requests but are not meaningful for
// SQL injection detection.
func NewDiffEngine() *DiffEngine {
	return &DiffEngine{
		DynamicPatterns: []*regexp.Regexp{
			// CSRF tokens in hidden fields or meta tags
			regexp.MustCompile(`(?i)(csrf[_-]?token|_token|authenticity_token)([^"]*"[^"]*"|[^']*'[^']*'|=[^\s&]+)`),
			// Session identifiers (sess_xxx, PHPSESSID, JSESSIONID, etc.)
			regexp.MustCompile(`(?i)(sess(ion)?[_-]?(id)?|phpsessid|jsessionid|sid)\s*[:=]\s*[^\s<"'&]+`),
			// Generic session-like tokens: sess_ followed by alphanumeric
			regexp.MustCompile(`(?i)\bsess[_-][a-zA-Z0-9]+\b`),
			// ISO 8601 timestamps
			regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s<"']*`),
			// Unix timestamps (10+ digit numbers)
			regexp.MustCompile(`\b\d{10,13}\b`),
			// Long hex strings (hashes, tokens, nonces)
			regexp.MustCompile(`[0-9a-fA-F]{32,}`),
			// UUIDs
			regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
		},
	}
}

// stripDynamic removes dynamic content from a string using DynamicPatterns.
// This allows meaningful comparison even when session IDs, CSRF tokens,
// timestamps, and other per-request values differ.
func (d *DiffEngine) stripDynamic(s string) string {
	for _, pat := range d.DynamicPatterns {
		s = pat.ReplaceAllString(s, "")
	}
	return s
}

// Ratio computes a similarity ratio between two byte slices (0.0 to 1.0).
// Dynamic content (session IDs, timestamps, etc.) is stripped before comparison.
// Uses a line-based comparison for multi-line responses.
func (d *DiffEngine) Ratio(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Strip dynamic content before comparison
	sa := d.stripDynamic(string(a))
	sb := d.stripDynamic(string(b))

	// Fast path: if stripped content is identical, return 1.0
	if sa == sb {
		return 1.0
	}

	linesA := strings.Split(sa, "\n")
	linesB := strings.Split(sb, "\n")

	matches := 0
	total := len(linesA) + len(linesB)

	used := make([]bool, len(linesB))
	for _, la := range linesA {
		for j, lb := range linesB {
			if !used[j] && la == lb {
				matches += 2
				used[j] = true
				break
			}
		}
	}

	return float64(matches) / float64(total)
}

// IsDifferent returns true if the similarity ratio of two bodies is below the
// given threshold.
func (d *DiffEngine) IsDifferent(a, b []byte, threshold float64) bool {
	return d.Ratio(a, b) < threshold
}

// DiffDetails compares two ResponseData objects and returns detailed differences.
func (d *DiffEngine) DiffDetails(a, b *ResponseData) *DiffResult {
	result := &DiffResult{
		HeaderDiffs: make(map[string][2]string),
	}

	if a == nil && b == nil {
		return result
	}
	if a == nil || b == nil {
		if a != nil || b != nil {
			result.StatusCodeChanged = true
		}
		return result
	}

	// Status code comparison
	result.StatusCodeChanged = a.StatusCode != b.StatusCode

	// Content length delta
	result.ContentLengthDelta = b.ContentLength - a.ContentLength

	// Body ratio
	result.BodyRatio = d.Ratio(a.Body, b.Body)

	// Header diffs
	allHeaders := make(map[string]struct{})
	for k := range a.Headers {
		allHeaders[k] = struct{}{}
	}
	for k := range b.Headers {
		allHeaders[k] = struct{}{}
	}
	for header := range allHeaders {
		aVal := ""
		bVal := ""
		if v, ok := a.Headers[header]; ok && len(v) > 0 {
			aVal = v[0]
		}
		if v, ok := b.Headers[header]; ok && len(v) > 0 {
			bVal = v[0]
		}
		if aVal != bVal {
			result.HeaderDiffs[header] = [2]string{aVal, bVal}
		}
	}

	// SQL error keyword detection in body b (the "injected" response)
	sqlErrors := FindSQLErrors(b.Body)
	for dbms, errors := range sqlErrors {
		for _, e := range errors {
			result.KeywordMatches = append(result.KeywordMatches, fmt.Sprintf("[%s] %s", dbms, e))
		}
	}

	return result
}
