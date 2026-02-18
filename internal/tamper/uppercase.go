package tamper

import (
	"regexp"
	"strings"
)

// sqlKeywords is the set of SQL keywords that will be uppercased.
// Ordered longest-first to avoid partial matches (e.g. "SELECT" before "SEC").
var sqlKeywords = []string{
	"INFORMATION_SCHEMA",
	"CURRENT_TIMESTAMP",
	"CURRENT_DATABASE",
	"CURRENT_SETTING",
	"CURRENT_USER",
	"CONVERT",
	"BETWEEN",
	"SUBSTRING",
	"CONCAT",
	"SELECT",
	"INSERT",
	"UPDATE",
	"DELETE",
	"UNION",
	"WHERE",
	"ORDER",
	"GROUP",
	"HAVING",
	"LIMIT",
	"OFFSET",
	"SLEEP",
	"WAITFOR",
	"DELAY",
	"CAST",
	"FROM",
	"INTO",
	"NULL",
	"AND",
	"NOT",
	"OR",
	"BY",
	"AS",
	"IS",
	"IN",
}

// sqlKeywordPattern matches any SQL keyword (case-insensitive, word-bounded).
var sqlKeywordPattern *regexp.Regexp

func init() {
	// Build a single alternation regex: (?i)\b(KEYWORD1|KEYWORD2|...)\b
	parts := make([]string, len(sqlKeywords))
	for i, kw := range sqlKeywords {
		parts[i] = regexp.QuoteMeta(kw)
	}
	sqlKeywordPattern = regexp.MustCompile(`(?i)\b(` + strings.Join(parts, "|") + `)\b`)
}

// uppercaseTamper converts SQL keywords to UPPER CASE to bypass case-sensitive
// WAF signatures that look for lowercase SQL keywords.
//
// Example:
//
//	"union select null" → "UNION SELECT NULL"
type uppercaseTamper struct{}

func (t *uppercaseTamper) Name() string { return "uppercase" }

func (t *uppercaseTamper) Apply(s string) string {
	return sqlKeywordPattern.ReplaceAllStringFunc(s, strings.ToUpper)
}
