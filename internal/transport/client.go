package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Client is the interface for the HTTP transport layer. All injection
// testing flows go through this interface.
type Client interface {
	// Do sends an HTTP request and returns the response.
	Do(ctx context.Context, req *Request) (*Response, error)

	// SetProxy configures an HTTP/SOCKS5 proxy for all subsequent requests.
	SetProxy(proxyURL string) error

	// SetRateLimit sets the maximum requests per second.
	SetRateLimit(rps float64)

	// Stats returns transport statistics.
	Stats() *TransportStats
}

// TransportStats holds aggregate statistics for the transport client.
type TransportStats struct {
	TotalRequests int64
	TotalDuration time.Duration
	AvgDuration   time.Duration
}

// ClientOptions holds configuration for creating a new DefaultClient.
type ClientOptions struct {
	// Timeout is the default timeout for all requests.
	Timeout time.Duration

	// ProxyURL is the proxy URL (HTTP or SOCKS5).
	ProxyURL string

	// FollowRedirects controls whether redirects are followed.
	FollowRedirects bool

	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool

	// RandomUserAgent enables random User-Agent header selection.
	RandomUserAgent bool

	// MaxRPS is the maximum requests per second (0 = unlimited).
	MaxRPS float64
}

// DefaultClient is the default implementation of the Client interface,
// backed by net/http.
type DefaultClient struct {
	httpClient      *http.Client
	opts            ClientOptions
	limiter         *rate.Limiter
	mu              sync.RWMutex
	totalRequests   int64
	totalDurationNs int64
}

// NewClient creates a new DefaultClient with the given options.
func NewClient(opts ClientOptions) (*DefaultClient, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
		},
		// Enable HTTP/2 by default via ForceAttemptHTTP2
		ForceAttemptHTTP2: true,
	}

	// Configure proxy if provided.
	if opts.ProxyURL != "" {
		proxyURL, err := url.Parse(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	// Configure redirect policy.
	if !opts.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	dc := &DefaultClient{
		httpClient: client,
		opts:       opts,
	}

	// Configure rate limiter if specified.
	if opts.MaxRPS > 0 {
		dc.limiter = rate.NewLimiter(rate.Limit(opts.MaxRPS), 1)
	}

	return dc, nil
}

// Do sends an HTTP request and returns the response. It applies rate
// limiting, timing measurement, custom headers, cookies, and optional
// per-request overrides.
func (c *DefaultClient) Do(ctx context.Context, req *Request) (*Response, error) {
	// Rate limiting
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter: %w", err)
		}
	}

	// Build the stdlib HTTP request.
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set Content-Type if provided.
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	// Set custom headers.
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set cookies.
	for name, value := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	// Set random User-Agent if enabled and no explicit User-Agent header.
	if c.opts.RandomUserAgent && httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", RandomUserAgent())
	}

	// Determine which HTTP client to use. If we need per-request overrides
	// for redirect policy or timeout, we create a shallow copy.
	httpClient := c.httpClient
	needCustomClient := false

	if req.FollowRedirects != nil {
		needCustomClient = true
	}
	if req.Timeout > 0 {
		needCustomClient = true
	}

	if needCustomClient {
		cc := *c.httpClient
		if req.Timeout > 0 {
			cc.Timeout = req.Timeout
		}
		if req.FollowRedirects != nil {
			if *req.FollowRedirects {
				cc.CheckRedirect = nil // follow redirects (default behavior)
			} else {
				cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				}
			}
		}
		httpClient = &cc
	}

	// Perform the request with timing.
	start := time.Now()
	httpResp, err := httpClient.Do(httpReq)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	// Read the response body.
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Determine protocol version string.
	protocol := fmt.Sprintf("HTTP/%d.%d", httpResp.ProtoMajor, httpResp.ProtoMinor)

	resp := &Response{
		StatusCode:    httpResp.StatusCode,
		Headers:       httpResp.Header,
		Body:          body,
		ContentLength: httpResp.ContentLength,
		Duration:      duration,
		URL:           httpResp.Request.URL.String(),
		Protocol:      protocol,
	}

	// Update statistics.
	c.mu.Lock()
	c.totalRequests++
	c.totalDurationNs += duration.Nanoseconds()
	c.mu.Unlock()

	return resp, nil
}

// SetProxy configures an HTTP or SOCKS5 proxy for subsequent requests.
func (c *DefaultClient) SetProxy(proxyURL string) error {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("invalid proxy URL: missing scheme or host")
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("cannot set proxy: transport is not *http.Transport")
	}

	transport.Proxy = http.ProxyURL(parsedURL)
	return nil
}

// SetRateLimit sets the maximum number of requests per second.
// A value of 0 or less disables rate limiting.
func (c *DefaultClient) SetRateLimit(rps float64) {
	if rps <= 0 {
		c.limiter = nil
		return
	}
	c.limiter = rate.NewLimiter(rate.Limit(rps), 1)
}

// Stats returns aggregate transport statistics.
func (c *DefaultClient) Stats() *TransportStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &TransportStats{
		TotalRequests: c.totalRequests,
		TotalDuration: time.Duration(c.totalDurationNs),
	}
	if c.totalRequests > 0 {
		stats.AvgDuration = time.Duration(c.totalDurationNs / c.totalRequests)
	}
	return stats
}
