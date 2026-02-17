// Package transport provides the HTTP transport abstraction layer
// used by all injection testing flows.
package transport

import "time"

// Request represents an HTTP request to be sent by the transport client.
type Request struct {
	// Method is the HTTP method (GET, POST, PUT, etc.).
	Method string

	// URL is the target URL.
	URL string

	// Headers contains custom HTTP headers to include.
	Headers map[string]string

	// Body is the request body content.
	Body string

	// ContentType is the Content-Type header value.
	ContentType string

	// Cookies contains cookies to include in the request.
	Cookies map[string]string

	// FollowRedirects overrides the client-level redirect setting
	// for this specific request. nil means use the client default.
	FollowRedirects *bool

	// Timeout overrides the client-level timeout for this specific
	// request. Zero means use the client default.
	Timeout time.Duration
}

// Clone returns a deep copy of the Request.
func (r *Request) Clone() *Request {
	if r == nil {
		return nil
	}

	clone := &Request{
		Method:      r.Method,
		URL:         r.URL,
		Body:        r.Body,
		ContentType: r.ContentType,
		Timeout:     r.Timeout,
	}

	if r.Headers != nil {
		clone.Headers = make(map[string]string, len(r.Headers))
		for k, v := range r.Headers {
			clone.Headers[k] = v
		}
	}

	if r.Cookies != nil {
		clone.Cookies = make(map[string]string, len(r.Cookies))
		for k, v := range r.Cookies {
			clone.Cookies[k] = v
		}
	}

	if r.FollowRedirects != nil {
		val := *r.FollowRedirects
		clone.FollowRedirects = &val
	}

	return clone
}
