package payload

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// unreserved contains RFC 3986 unreserved characters that do not need
// percent-encoding: ALPHA / DIGIT / "-" / "." / "_" / "~".
func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// percentEncode applies RFC 3986 percent-encoding to every byte that is not
// an unreserved character. Spaces become %20 (not +).
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Encoder transforms a payload string.
type Encoder interface {
	Name() string
	Encode(s string) string
}

// URLEncoder performs URL encoding.
type URLEncoder struct{}

// Name returns the encoder name.
func (e *URLEncoder) Name() string { return "url" }

// Encode applies URL percent-encoding to the input string.
// All non-unreserved characters (per RFC 3986) are percent-encoded.
// Spaces are encoded as %20 (not +) which is standard for payload encoding.
func (e *URLEncoder) Encode(s string) string {
	return percentEncode(s)
}

// DoubleURLEncoder performs double URL encoding.
type DoubleURLEncoder struct{}

// Name returns the encoder name.
func (e *DoubleURLEncoder) Name() string { return "doubleurl" }

// Encode applies URL percent-encoding twice: first encode, then encode the result again.
func (e *DoubleURLEncoder) Encode(s string) string {
	first := percentEncode(s)
	return percentEncode(first)
}

// HexEncoder converts each byte to its hex representation (0xHH).
type HexEncoder struct{}

// Name returns the encoder name.
func (e *HexEncoder) Name() string { return "hex" }

// Encode converts each byte of the input to 0xHH format.
func (e *HexEncoder) Encode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "0x%02x", s[i])
	}
	return b.String()
}

// UnicodeEncoder converts each byte to unicode escape format (%u00XX).
type UnicodeEncoder struct{}

// Name returns the encoder name.
func (e *UnicodeEncoder) Name() string { return "unicode" }

// Encode converts each byte of the input to %u00XX format.
func (e *UnicodeEncoder) Encode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%u00%02x", s[i])
	}
	return b.String()
}

// Base64Encoder encodes to standard base64.
type Base64Encoder struct{}

// Name returns the encoder name.
func (e *Base64Encoder) Name() string { return "base64" }

// Encode applies standard base64 encoding.
func (e *Base64Encoder) Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// ChainEncoder applies multiple encoders in sequence.
type ChainEncoder struct {
	encoders []Encoder
}

// NewChainEncoder creates a ChainEncoder with the given encoders.
func NewChainEncoder(encoders ...Encoder) *ChainEncoder {
	return &ChainEncoder{encoders: encoders}
}

// Name returns the encoder name.
func (e *ChainEncoder) Name() string { return "chain" }

// Encode applies each encoder in order.
func (e *ChainEncoder) Encode(s string) string {
	result := s
	for _, enc := range e.encoders {
		result = enc.Encode(result)
	}
	return result
}
