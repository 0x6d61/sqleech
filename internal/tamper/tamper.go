// Package tamper provides payload transformation functions that help bypass
// Web Application Firewalls (WAFs) and input filters during SQL injection testing.
//
// Each Tamper transforms a raw injection string before it is URL-encoded and
// sent in an HTTP request. Tampers can be composed into a Chain that applies
// them in order.
//
// Built-in tampers:
//   - space2comment: Replaces spaces with /**/ comments
//   - uppercase:     Converts SQL keywords to UPPER CASE
//   - charencode:    Hex-encodes non-alphanumeric characters (%XX)
//   - between:       Replaces > comparisons with BETWEEN x AND x+1
//
// Usage:
//
//	chain := tamper.BuildChain("space2comment", "uppercase")
//	client = tamper.WrapClient(client, chain)
package tamper

import (
	"context"
	"net/url"
	"strings"

	"github.com/0x6d61/sqleech/internal/transport"
)

// Tamper transforms a raw SQL injection payload string.
type Tamper interface {
	// Name returns the tamper's short identifier (e.g. "space2comment").
	Name() string
	// Apply transforms the payload string and returns the modified version.
	Apply(s string) string
}

// Chain applies multiple tampers sequentially.
type Chain []Tamper

// Apply runs each tamper in order and returns the fully-transformed string.
func (c Chain) Apply(s string) string {
	for _, t := range c {
		s = t.Apply(s)
	}
	return s
}

// registry maps tamper names to their constructors.
var registry = map[string]func() Tamper{
	"space2comment": func() Tamper { return &space2commentTamper{} },
	"uppercase":     func() Tamper { return &uppercaseTamper{} },
	"charencode":    func() Tamper { return &charEncodeTamper{} },
	"between":       func() Tamper { return &betweenTamper{} },
}

// Lookup returns the Tamper for the given name, or nil if not found.
func Lookup(name string) Tamper {
	fn, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil
	}
	return fn()
}

// Available returns all registered tamper names in alphabetical order.
func Available() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// BuildChain constructs a Chain from the given tamper names.
// Names that are not registered are silently ignored.
func BuildChain(names ...string) Chain {
	var chain Chain
	for _, name := range names {
		t := Lookup(name)
		if t != nil {
			chain = append(chain, t)
		}
	}
	return chain
}

// --------------------------------------------------------------------------
// Transport client wrapper
// --------------------------------------------------------------------------

// tamperedClient wraps a transport.Client and applies the chain to all
// query parameter values and URL-encoded body values before sending.
type tamperedClient struct {
	inner transport.Client
	chain Chain
}

// WrapClient returns a transport.Client that applies chain to every outgoing
// request's query-parameter values and form-body values.
// If chain is empty, the original client is returned unchanged.
func WrapClient(client transport.Client, chain Chain) transport.Client {
	if len(chain) == 0 {
		return client
	}
	return &tamperedClient{inner: client, chain: chain}
}

func (c *tamperedClient) Do(ctx context.Context, req *transport.Request) (*transport.Response, error) {
	return c.inner.Do(ctx, applyTamperToRequest(req, c.chain))
}

func (c *tamperedClient) SetProxy(proxyURL string) error   { return c.inner.SetProxy(proxyURL) }
func (c *tamperedClient) SetRateLimit(rps float64)         { c.inner.SetRateLimit(rps) }
func (c *tamperedClient) Stats() *transport.TransportStats { return c.inner.Stats() }

// applyTamperToRequest applies the chain to query-parameter values and
// URL-encoded body values in the request, returning a modified copy.
func applyTamperToRequest(req *transport.Request, chain Chain) *transport.Request {
	out := *req // shallow copy

	if req.URL != "" {
		out.URL = tamperURLParams(req.URL, chain)
	}

	if req.Body != "" && isFormEncoded(req.ContentType) {
		out.Body = tamperBodyParams(req.Body, chain)
	}

	return &out
}

// tamperURLParams applies the chain to each query parameter value in rawURL.
func tamperURLParams(rawURL string, chain Chain) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	for key, values := range q {
		for i, v := range values {
			values[i] = chain.Apply(v)
		}
		q[key] = values
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// tamperBodyParams applies the chain to each value in a URL-encoded body.
func tamperBodyParams(body string, chain Chain) string {
	values, err := url.ParseQuery(body)
	if err != nil {
		return body
	}
	for key, vals := range values {
		for i, v := range vals {
			vals[i] = chain.Apply(v)
		}
		values[key] = vals
	}
	return values.Encode()
}

// isFormEncoded returns true for application/x-www-form-urlencoded content.
func isFormEncoded(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "application/x-www-form-urlencoded")
}

// Compile-time check that tamperedClient implements transport.Client.
var _ transport.Client = (*tamperedClient)(nil)
