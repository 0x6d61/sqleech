package payload

import "testing"

func TestPayloadString(t *testing.T) {
	t.Parallel()
	p := &Payload{
		Prefix: "'",
		Core:   "AND 1=1",
		Suffix: "-- -",
	}
	got := p.String()
	want := "'AND 1=1-- -"
	if got != want {
		t.Errorf("Payload.String() = %q, want %q", got, want)
	}
}

func TestPayloadString_Empty(t *testing.T) {
	t.Parallel()
	p := &Payload{}
	got := p.String()
	if got != "" {
		t.Errorf("Payload.String() with empty fields = %q, want empty string", got)
	}
}

func TestBuilder_Fluent(t *testing.T) {
	t.Parallel()
	// Ensure all builder methods return *Builder for chaining.
	b := NewBuilder().
		WithPrefix("'").
		WithCore("AND 1=1").
		WithSuffix("-- -").
		WithTechnique("error-based").
		WithDBMS("MySQL").
		WithEncoder(&URLEncoder{})
	if b == nil {
		t.Fatal("Builder chain returned nil")
	}
}

func TestBuilder_Build(t *testing.T) {
	t.Parallel()
	p := NewBuilder().
		WithPrefix("'").
		WithCore("AND 1=1").
		WithSuffix("-- -").
		WithTechnique("error-based").
		WithDBMS("MySQL").
		Build()

	if p.Prefix != "'" {
		t.Errorf("Prefix = %q, want %q", p.Prefix, "'")
	}
	if p.Core != "AND 1=1" {
		t.Errorf("Core = %q, want %q", p.Core, "AND 1=1")
	}
	if p.Suffix != "-- -" {
		t.Errorf("Suffix = %q, want %q", p.Suffix, "-- -")
	}
	if p.Technique != "error-based" {
		t.Errorf("Technique = %q, want %q", p.Technique, "error-based")
	}
	if p.DBMS != "MySQL" {
		t.Errorf("DBMS = %q, want %q", p.DBMS, "MySQL")
	}
	// Without encoder, Encoded should equal the raw string.
	want := "'AND 1=1-- -"
	if p.Encoded != want {
		t.Errorf("Encoded = %q, want %q", p.Encoded, want)
	}
}

func TestBuilder_WithEncoder(t *testing.T) {
	t.Parallel()
	p := NewBuilder().
		WithPrefix("").
		WithCore("1 AND 1=1").
		WithSuffix("-- -").
		WithEncoder(&URLEncoder{}).
		Build()

	// URL encoding should encode the space characters.
	if p.Encoded == p.String() {
		t.Error("expected Encoded to differ from raw string after URL encoding")
	}
	if p.Encoded == "" {
		t.Error("Encoded should not be empty")
	}
}

func TestBuilder_MultipleEncoders(t *testing.T) {
	t.Parallel()
	// Apply URL encoding then Base64 encoding.
	p := NewBuilder().
		WithPrefix("").
		WithCore("test").
		WithSuffix("").
		WithEncoder(&URLEncoder{}).
		WithEncoder(&Base64Encoder{}).
		Build()

	// The result should be base64 of URL-encoded "test".
	// "test" URL-encoded is "test" (no special chars), then base64 is "dGVzdA==".
	if p.Encoded == "" {
		t.Error("Encoded should not be empty")
	}
	// Verify ordering: URL encode first, then base64.
	urlEnc := (&URLEncoder{}).Encode("test")
	b64 := (&Base64Encoder{}).Encode(urlEnc)
	if p.Encoded != b64 {
		t.Errorf("Encoded = %q, want %q (URL then Base64)", p.Encoded, b64)
	}
}

func TestBuilder_NoEncoder(t *testing.T) {
	t.Parallel()
	p := NewBuilder().
		WithPrefix("'").
		WithCore("OR 1=1").
		WithSuffix("#").
		Build()

	raw := p.String()
	if p.Encoded != raw {
		t.Errorf("Encoded = %q, want %q (no encoder applied)", p.Encoded, raw)
	}
}

func TestCommonBoundaries(t *testing.T) {
	t.Parallel()
	boundaries := CommonBoundaries()
	if len(boundaries) == 0 {
		t.Error("CommonBoundaries() returned empty slice")
	}
	for i, b := range boundaries {
		if b.Suffix == "" {
			t.Errorf("boundary[%d] has empty Suffix", i)
		}
	}
}
