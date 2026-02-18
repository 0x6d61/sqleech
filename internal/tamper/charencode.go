package tamper

import (
	"fmt"
	"strings"
)

// charEncodeTamper hex-encodes non-alphanumeric, non-safe characters in the
// payload using %XX notation. This can bypass WAFs that match on literal
// SQL special characters.
//
// Safe characters (left unchanged): A-Z a-z 0-9 _ - . * ~
//
// Example:
//
//	"' OR 1=1--" → "%27%20OR%201%3D1--"
type charEncodeTamper struct{}

func (t *charEncodeTamper) Name() string { return "charencode" }

func (t *charEncodeTamper) Apply(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for _, ch := range s {
		if isSafeChar(ch) {
			b.WriteRune(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

// isSafeChar returns true for characters that do NOT need to be encoded.
// These are: alphanumerics, and the set _ - . * ~
func isSafeChar(r rune) bool {
	return (r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '_' || r == '-' || r == '.' || r == '*' || r == '~'
}
