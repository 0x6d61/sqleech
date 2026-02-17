package transport

import (
	"net/http"
	"time"
)

// Response represents an HTTP response received from the transport client.
type Response struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Headers contains the response headers.
	Headers http.Header

	// Body is the raw response body.
	Body []byte

	// ContentLength is the content length from the response header.
	ContentLength int64

	// Duration is the precise round-trip time for the request.
	Duration time.Duration

	// URL is the final URL after any redirects.
	URL string

	// Protocol is the protocol version (e.g., "HTTP/1.1", "HTTP/2.0").
	Protocol string
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	return string(r.Body)
}
