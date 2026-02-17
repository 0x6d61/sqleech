// Package detector provides parameter extraction and SQL injection detection.
package detector

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/0x6d61/sqleech/internal/engine"
)

// integerPattern matches an optional minus sign followed by one or more digits.
var integerPattern = regexp.MustCompile(`^-?[0-9]+$`)

// floatPattern matches an optional minus sign, one or more digits, a dot, then one or more digits.
var floatPattern = regexp.MustCompile(`^-?[0-9]+\.[0-9]+$`)

// ParseParameters extracts all parameters from a URL and body.
// url: the full URL (e.g., "http://example.com/page?id=1&name=test")
// body: the POST body (e.g., "user=admin&pass=123")
// contentType: the Content-Type header value
// Returns: slice of engine.Parameter
func ParseParameters(rawURL, body, contentType string) []engine.Parameter {
	var params []engine.Parameter
	params = append(params, ParseURLParameters(rawURL)...)
	params = append(params, ParseBodyParameters(body, contentType)...)
	return params
}

// ParseURLParameters extracts parameters from URL query string only.
func ParseURLParameters(rawURL string) []engine.Parameter {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	return parseFormValues(parsed.Query(), engine.LocationQuery)
}

// ParseBodyParameters extracts parameters from POST body.
// Supports application/x-www-form-urlencoded.
func ParseBodyParameters(body, contentType string) []engine.Parameter {
	if body == "" {
		return nil
	}

	if !isFormURLEncoded(contentType) {
		return nil
	}

	values, err := url.ParseQuery(body)
	if err != nil {
		return nil
	}

	return parseFormValues(values, engine.LocationBody)
}

// InferType guesses the parameter type from its value.
// - Integers: "123", "-45", "0"
// - Floats: "1.5", "-3.14", "0.0"
// - Strings: everything else
func InferType(value string) engine.ParameterType {
	if integerPattern.MatchString(value) {
		return engine.TypeInteger
	}
	if floatPattern.MatchString(value) {
		return engine.TypeFloat
	}
	return engine.TypeString
}

// parseFormValues converts url.Values into a slice of engine.Parameter with the
// given location. It preserves multiple values for the same key.
func parseFormValues(values url.Values, location engine.ParameterLocation) []engine.Parameter {
	var params []engine.Parameter
	for name, vals := range values {
		for _, v := range vals {
			params = append(params, engine.Parameter{
				Name:     name,
				Value:    v,
				Location: location,
				Type:     InferType(v),
			})
		}
	}
	return params
}

// isFormURLEncoded checks whether the content type indicates
// application/x-www-form-urlencoded. An empty content type is treated as
// form-urlencoded for convenience (common in simple POST requests).
func isFormURLEncoded(contentType string) bool {
	if contentType == "" {
		return true
	}
	// Strip parameters like "; charset=utf-8"
	mediaType := strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	return strings.EqualFold(mediaType, "application/x-www-form-urlencoded")
}
