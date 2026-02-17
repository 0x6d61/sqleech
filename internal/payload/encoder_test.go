package payload

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestURLEncoder_Name(t *testing.T) {
	t.Parallel()
	e := &URLEncoder{}
	if e.Name() != "url" {
		t.Errorf("Name() = %q, want %q", e.Name(), "url")
	}
}

func TestURLEncoder(t *testing.T) {
	t.Parallel()
	e := &URLEncoder{}

	tests := []struct {
		name  string
		input string
		check func(string) bool
		desc  string
	}{
		{
			name:  "space encoding",
			input: "AND 1=1",
			check: func(s string) bool { return strings.Contains(s, "%20") || strings.Contains(s, "+") },
			desc:  "should encode spaces",
		},
		{
			name:  "single quote",
			input: "'OR 1=1",
			check: func(s string) bool { return strings.Contains(s, "%27") },
			desc:  "should encode single quotes",
		},
		{
			name:  "plain alphanumeric",
			input: "abc123",
			check: func(s string) bool { return s == "abc123" },
			desc:  "alphanumeric should not change",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.Encode(tt.input)
			if !tt.check(got) {
				t.Errorf("URLEncoder.Encode(%q) = %q: %s", tt.input, got, tt.desc)
			}
		})
	}
}

func TestDoubleURLEncoder_Name(t *testing.T) {
	t.Parallel()
	e := &DoubleURLEncoder{}
	if e.Name() != "doubleurl" {
		t.Errorf("Name() = %q, want %q", e.Name(), "doubleurl")
	}
}

func TestDoubleURLEncoder(t *testing.T) {
	t.Parallel()
	e := &DoubleURLEncoder{}

	// A space is first URL-encoded to %20, then the % is encoded to %25,
	// resulting in %2520.
	got := e.Encode("A B")
	if !strings.Contains(got, "%25") {
		t.Errorf("DoubleURLEncoder.Encode(\"A B\") = %q, expected double-encoded percent", got)
	}
}

func TestHexEncoder_Name(t *testing.T) {
	t.Parallel()
	e := &HexEncoder{}
	if e.Name() != "hex" {
		t.Errorf("Name() = %q, want %q", e.Name(), "hex")
	}
}

func TestHexEncoder(t *testing.T) {
	t.Parallel()
	e := &HexEncoder{}

	got := e.Encode("AB")
	// 'A' = 0x41, 'B' = 0x42 → should contain "41" and "42"
	if !strings.Contains(got, "41") || !strings.Contains(got, "42") {
		t.Errorf("HexEncoder.Encode(\"AB\") = %q, expected hex values 41 and 42", got)
	}
}

func TestUnicodeEncoder_Name(t *testing.T) {
	t.Parallel()
	e := &UnicodeEncoder{}
	if e.Name() != "unicode" {
		t.Errorf("Name() = %q, want %q", e.Name(), "unicode")
	}
}

func TestUnicodeEncoder(t *testing.T) {
	t.Parallel()
	e := &UnicodeEncoder{}

	got := e.Encode("A")
	// 'A' = 0x41 → %u0041
	if !strings.Contains(got, "%u00") {
		t.Errorf("UnicodeEncoder.Encode(\"A\") = %q, expected %%u00XX format", got)
	}
}

func TestBase64Encoder_Name(t *testing.T) {
	t.Parallel()
	e := &Base64Encoder{}
	if e.Name() != "base64" {
		t.Errorf("Name() = %q, want %q", e.Name(), "base64")
	}
}

func TestBase64Encoder(t *testing.T) {
	t.Parallel()
	e := &Base64Encoder{}

	input := "hello world"
	got := e.Encode(input)
	want := base64.StdEncoding.EncodeToString([]byte(input))
	if got != want {
		t.Errorf("Base64Encoder.Encode(%q) = %q, want %q", input, got, want)
	}
}

func TestChainEncoder_Name(t *testing.T) {
	t.Parallel()
	e := NewChainEncoder(&URLEncoder{}, &Base64Encoder{})
	if e.Name() != "chain" {
		t.Errorf("Name() = %q, want %q", e.Name(), "chain")
	}
}

func TestChainEncoder(t *testing.T) {
	t.Parallel()
	// Chain: URL encode, then Base64 encode.
	chain := NewChainEncoder(&URLEncoder{}, &Base64Encoder{})

	input := "' OR 1=1"
	got := chain.Encode(input)

	// Manually apply in order.
	step1 := (&URLEncoder{}).Encode(input)
	step2 := (&Base64Encoder{}).Encode(step1)

	if got != step2 {
		t.Errorf("ChainEncoder.Encode(%q) = %q, want %q", input, got, step2)
	}
}

func TestChainEncoder_Empty(t *testing.T) {
	t.Parallel()
	chain := NewChainEncoder()
	input := "unchanged"
	got := chain.Encode(input)
	if got != input {
		t.Errorf("ChainEncoder with no encoders: Encode(%q) = %q, want %q", input, got, input)
	}
}
