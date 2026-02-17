package fingerprint

import (
	"context"
	"net/url"

	"github.com/0x6d61/sqleech/internal/engine"
	"github.com/0x6d61/sqleech/internal/transport"
)

// sendProbe sends a request with a modified parameter value and returns the response.
func sendProbe(ctx context.Context, client transport.Client, target *engine.ScanTarget, param *engine.Parameter, payload string) (*transport.Response, error) {
	req := buildRequest(target, param, payload)
	return client.Do(ctx, req)
}

// buildRequest creates a transport.Request from a ScanTarget with a modified parameter.
// It copies all headers, cookies, and other fields from the target, then
// replaces the specified parameter's value with the given payload.
func buildRequest(target *engine.ScanTarget, param *engine.Parameter, payload string) *transport.Request {
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

// responseSimilar returns true when the probe response status code matches
// the baseline and the body lengths are within a reasonable tolerance.
// This is used as a lightweight similarity check for behavioural probes.
func responseSimilar(baseline, probe *transport.Response) bool {
	if baseline == nil || probe == nil {
		return false
	}
	// A probe is "accepted" if the server responds with a 2xx status.
	return probe.StatusCode >= 200 && probe.StatusCode < 300
}
