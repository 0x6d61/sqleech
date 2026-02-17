// Package detector provides parameter extraction and SQL injection detection.
package detector

import (
	"regexp"
	"strings"
)

// dbmsPatterns maps DBMS names to their error message patterns.
// Each pattern is compiled as a case-insensitive regex.
var dbmsPatterns = map[string][]*regexp.Regexp{
	"MySQL": {
		regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
		regexp.MustCompile(`(?i)Warning:.*\bmysql_`),
		regexp.MustCompile(`(?i)MySqlException`),
		regexp.MustCompile(`(?i)valid MySQL result`),
		regexp.MustCompile(`(?i)MySqlClient\.`),
		regexp.MustCompile(`(?i)com\.mysql\.jdbc`),
	},
	"PostgreSQL": {
		regexp.MustCompile(`(?i)ERROR:\s+syntax error at or near`),
		regexp.MustCompile(`(?i)pg_query\(\)`),
		regexp.MustCompile(`(?i)pg_exec\(\)`),
		regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
		regexp.MustCompile(`(?i)Npgsql\.`),
	},
	"MSSQL": {
		regexp.MustCompile(`(?i)Unclosed quotation mark`),
		regexp.MustCompile(`(?i)\bOLE DB\b.*\bSQL Server\b`),
		regexp.MustCompile(`(?i)\bSQL Server\b.*\bOLE DB\b`),
		regexp.MustCompile(`(?i)Microsoft SQL Native Client`),
		regexp.MustCompile(`(?i)\[ODBC SQL Server Driver\]`),
		regexp.MustCompile(`(?i)SqlException`),
		regexp.MustCompile(`(?i)Msg \d+, Level \d+, State \d+`),
	},
	"Oracle": {
		regexp.MustCompile(`ORA-\d{5}`),
		regexp.MustCompile(`(?i)Oracle.*Driver`),
		regexp.MustCompile(`(?i)oracle\.jdbc`),
		regexp.MustCompile(`(?i)OracleException`),
	},
	"SQLite": {
		regexp.MustCompile(`(?i)SQLITE_ERROR`),
		regexp.MustCompile(`(?i)SQLite3::query`),
		regexp.MustCompile(`(?i)sqlite3\.OperationalError`),
		regexp.MustCompile(`(?i)\[SQLITE_ERROR\]`),
		regexp.MustCompile(`(?i)SQLite\.Exception`),
	},
	"Generic": {
		regexp.MustCompile(`(?i)SQL syntax.*error`),
		regexp.MustCompile(`(?i)unexpected end of SQL command`),
		regexp.MustCompile(`(?i)quoted string not properly terminated`),
		regexp.MustCompile(`(?i)syntax error`),
	},
}

// FindSQLErrors scans the response body for known SQL error messages.
// It returns a map of DBMS name to matched error strings.
func FindSQLErrors(body []byte) map[string][]string {
	if len(body) == 0 {
		return nil
	}

	text := string(body)
	result := make(map[string][]string)

	for dbms, patterns := range dbmsPatterns {
		for _, pat := range patterns {
			matches := pat.FindAllString(text, -1)
			for _, m := range matches {
				// Avoid duplicate entries
				if !containsString(result[dbms], m) {
					result[dbms] = append(result[dbms], m)
				}
			}
		}
	}

	// Remove the Generic entry if the matched text is also matched by a
	// specific DBMS (to reduce noise). We keep Generic only if there is
	// no other DBMS match or the generic match is unique.
	// For simplicity, always keep Generic if detected.

	// Clean up empty slices
	for k, v := range result {
		if len(v) == 0 {
			delete(result, k)
		}
		_ = v
	}

	return result
}

// containsString checks if a string slice contains a value (case-insensitive).
func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
