package tamper_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x6d61/sqleech/internal/tamper"
	"github.com/0x6d61/sqleech/internal/transport"
)

// --------------------------------------------------------------------------
// space2comment
// --------------------------------------------------------------------------

func TestSpace2Comment_Name(t *testing.T) {
	tp := tamper.BuildChain("space2comment")[0]
	if tp.Name() != "space2comment" {
		t.Errorf("Name() = %q, want 'space2comment'", tp.Name())
	}
}

func TestSpace2Comment_Apply(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{" UNION SELECT NULL-- -", "/**/UNION/**/SELECT/**/NULL--/**/-"},
		{"AND 1=1", "AND/**/1=1"},
		{"no spaces", "no/**/spaces"},
		{"", ""},
		{"nochange", "nochange"},
	}
	tp := tamper.BuildChain("space2comment")[0]
	for _, c := range cases {
		got := tp.Apply(c.in)
		if got != c.want {
			t.Errorf("space2comment.Apply(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --------------------------------------------------------------------------
// uppercase
// --------------------------------------------------------------------------

func TestUppercase_Name(t *testing.T) {
	tp := tamper.BuildChain("uppercase")[0]
	if tp.Name() != "uppercase" {
		t.Errorf("Name() = %q, want 'uppercase'", tp.Name())
	}
}

func TestUppercase_Apply(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"union select null", "UNION SELECT NULL"},
		{"and 1=1", "AND 1=1"},
		{"UNION SELECT NULL", "UNION SELECT NULL"}, // already uppercase
		{"sleep(5)", "SLEEP(5)"},
		{"1=1", "1=1"}, // no keywords
		{"", ""},
	}
	tp := tamper.BuildChain("uppercase")[0]
	for _, c := range cases {
		got := tp.Apply(c.in)
		if got != c.want {
			t.Errorf("uppercase.Apply(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --------------------------------------------------------------------------
// charencode
// --------------------------------------------------------------------------

func TestCharencode_Name(t *testing.T) {
	tp := tamper.BuildChain("charencode")[0]
	if tp.Name() != "charencode" {
		t.Errorf("Name() = %q, want 'charencode'", tp.Name())
	}
}

func TestCharencode_Apply(t *testing.T) {
	tp := tamper.BuildChain("charencode")[0]
	cases := []struct {
		in       string
		contains string // substring that must appear in output
	}{
		{"'", "%27"},
		{"=", "%3D"},
		{" ", "%20"},
		{"abc123", "abc123"}, // safe chars unchanged
		{"_-.*~", "_-.*~"},   // safe chars unchanged
	}
	for _, c := range cases {
		got := tp.Apply(c.in)
		if !strings.Contains(got, c.contains) {
			t.Errorf("charencode.Apply(%q) = %q, want to contain %q", c.in, got, c.contains)
		}
	}
}

func TestCharencode_SafeCharsUnchanged(t *testing.T) {
	tp := tamper.BuildChain("charencode")[0]
	safe := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.*~"
	got := tp.Apply(safe)
	if got != safe {
		t.Errorf("charencode changed safe chars: %q → %q", safe, got)
	}
}

// --------------------------------------------------------------------------
// between
// --------------------------------------------------------------------------

func TestBetween_Name(t *testing.T) {
	tp := tamper.BuildChain("between")[0]
	if tp.Name() != "between" {
		t.Errorf("Name() = %q, want 'between'", tp.Name())
	}
}

func TestBetween_Apply(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{
			"ASCII(SUBSTRING(password,1,1))>64",
			"ASCII(SUBSTRING(password,1,1)) BETWEEN 65 AND 65",
		},
		{
			"LEN(col)>10",
			"LEN(col) BETWEEN 11 AND 11",
		},
		{"no comparison here", "no comparison here"},
		{"1=1", "1=1"}, // equality: not affected
	}
	tp := tamper.BuildChain("between")[0]
	for _, c := range cases {
		got := tp.Apply(c.in)
		if got != c.want {
			t.Errorf("between.Apply(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --------------------------------------------------------------------------
// Chain
// --------------------------------------------------------------------------

func TestChain_Apply_MultipleOrder(t *testing.T) {
	// space2comment then uppercase
	chain := tamper.BuildChain("space2comment", "uppercase")
	got := chain.Apply(" union select null ")
	// spaces → /**/, then keywords → upper
	// " union select null " → "/**/union/**/select/**/null/**/" → "/**/UNION/**/SELECT/**/NULL/**/"
	want := "/**/UNION/**/SELECT/**/NULL/**/"
	if got != want {
		t.Errorf("chain.Apply = %q, want %q", got, want)
	}
}

func TestChain_Apply_Empty(t *testing.T) {
	var chain tamper.Chain
	got := chain.Apply("unchanged")
	if got != "unchanged" {
		t.Errorf("empty chain should return input unchanged, got %q", got)
	}
}

// --------------------------------------------------------------------------
// Lookup / Available
// --------------------------------------------------------------------------

func TestLookup_KnownNames(t *testing.T) {
	for _, name := range []string{"space2comment", "uppercase", "charencode", "between"} {
		tp := tamper.Lookup(name)
		if tp == nil {
			t.Errorf("Lookup(%q) returned nil", name)
		}
	}
}

func TestLookup_CaseInsensitive(t *testing.T) {
	tp := tamper.Lookup("SPACE2COMMENT")
	if tp == nil {
		t.Error("Lookup('SPACE2COMMENT') returned nil, want case-insensitive match")
	}
}

func TestLookup_Unknown(t *testing.T) {
	tp := tamper.Lookup("nonexistent")
	if tp != nil {
		t.Errorf("Lookup('nonexistent') = %v, want nil", tp)
	}
}

func TestAvailable_ContainsBuiltins(t *testing.T) {
	available := tamper.Available()
	required := []string{"space2comment", "uppercase", "charencode", "between"}
	set := make(map[string]bool, len(available))
	for _, n := range available {
		set[n] = true
	}
	for _, r := range required {
		if !set[r] {
			t.Errorf("Available() missing %q", r)
		}
	}
}

func TestBuildChain_UnknownIgnored(t *testing.T) {
	chain := tamper.BuildChain("space2comment", "nonexistent", "uppercase")
	if len(chain) != 2 {
		t.Errorf("BuildChain with unknown: len = %d, want 2", len(chain))
	}
}

// --------------------------------------------------------------------------
// WrapClient
// --------------------------------------------------------------------------

func TestWrapClient_AppliesSpace2Comment(t *testing.T) {
	var receivedURL string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	base, err := transport.NewClient(transport.ClientOptions{})
	if err != nil {
		t.Fatalf("transport.NewClient: %v", err)
	}

	chain := tamper.BuildChain("space2comment")
	client := tamper.WrapClient(base, chain)

	req := &transport.Request{
		Method: "GET",
		URL:    srv.URL + "/?id=1 UNION SELECT NULL-- -",
	}
	_, err = client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	// After tamper + URL encoding, spaces should NOT appear
	if strings.Contains(receivedURL, "+") || strings.Contains(receivedURL, "%20") {
		// spaces appear as + or %20 in URL encoding
		// space2comment converts " " → "/**/" before URL encoding,
		// so the raw query should have %2F%2A%2A%2F (/**/encoded) instead of +
		t.Logf("receivedURL = %s", receivedURL)
		// We check that /*/ pattern is NOT replaced with literal spaces
		// but also not with + signs. The tamper should have turned spaces to /**/
		if !strings.Contains(receivedURL, "%2F%2A%2A%2F") && !strings.Contains(receivedURL, "/**") {
			t.Errorf("expected /*/ comment in URL, got: %s", receivedURL)
		}
	}
}

func TestWrapClient_EmptyChain_PassThrough(t *testing.T) {
	base, err := transport.NewClient(transport.ClientOptions{})
	if err != nil {
		t.Fatalf("transport.NewClient: %v", err)
	}

	// WrapClient with empty chain should return the original client
	client := tamper.WrapClient(base, nil)
	if client != base {
		t.Error("WrapClient with empty chain should return the original client")
	}
}

func TestWrapClient_FormBody(t *testing.T) {
	var receivedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		receivedBody = r.FormValue("username")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	base, err := transport.NewClient(transport.ClientOptions{})
	if err != nil {
		t.Fatalf("transport.NewClient: %v", err)
	}

	chain := tamper.BuildChain("uppercase")
	client := tamper.WrapClient(base, chain)

	req := &transport.Request{
		Method:      "POST",
		URL:         srv.URL + "/login",
		Body:        "username=admin union select null&password=secret",
		ContentType: "application/x-www-form-urlencoded",
	}
	_, err = client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	// uppercase tamper should have converted "union" and "select" to uppercase
	if !strings.Contains(receivedBody, "UNION") {
		t.Errorf("expected uppercase UNION in body, got: %q", receivedBody)
	}
	if !strings.Contains(receivedBody, "SELECT") {
		t.Errorf("expected uppercase SELECT in body, got: %q", receivedBody)
	}
}
