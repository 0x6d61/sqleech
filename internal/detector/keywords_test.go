package detector

import (
	"strings"
	"testing"
)

func TestFindSQLErrors_MySQL(t *testing.T) {
	body := []byte("Error: You have an error in your SQL syntax; check the manual")
	result := FindSQLErrors(body)

	mysqlErrors, ok := result["MySQL"]
	if !ok {
		t.Fatal("expected MySQL errors to be detected")
	}
	if len(mysqlErrors) == 0 {
		t.Fatal("expected at least one MySQL error match")
	}

	found := false
	for _, e := range mysqlErrors {
		if strings.Contains(e, "You have an error in your SQL syntax") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected MySQL syntax error match, got %v", mysqlErrors)
	}
}

func TestFindSQLErrors_PostgreSQL(t *testing.T) {
	body := []byte("ERROR: syntax error at or near \"SELECT\"")
	result := FindSQLErrors(body)

	pgErrors, ok := result["PostgreSQL"]
	if !ok {
		t.Fatal("expected PostgreSQL errors to be detected")
	}
	if len(pgErrors) == 0 {
		t.Fatal("expected at least one PostgreSQL error match")
	}
}

func TestFindSQLErrors_MSSQL(t *testing.T) {
	body := []byte("Unclosed quotation mark after the character string ''.")
	result := FindSQLErrors(body)

	mssqlErrors, ok := result["MSSQL"]
	if !ok {
		t.Fatal("expected MSSQL errors to be detected")
	}
	if len(mssqlErrors) == 0 {
		t.Fatal("expected at least one MSSQL error match")
	}
}

func TestFindSQLErrors_Oracle(t *testing.T) {
	body := []byte("ORA-00933: SQL command not properly ended")
	result := FindSQLErrors(body)

	oraErrors, ok := result["Oracle"]
	if !ok {
		t.Fatal("expected Oracle errors to be detected")
	}
	if len(oraErrors) == 0 {
		t.Fatal("expected at least one Oracle error match")
	}
}

func TestFindSQLErrors_SQLite(t *testing.T) {
	body := []byte("SQLITE_ERROR: near \"FROM\": syntax error")
	result := FindSQLErrors(body)

	sqliteErrors, ok := result["SQLite"]
	if !ok {
		t.Fatal("expected SQLite errors to be detected")
	}
	if len(sqliteErrors) == 0 {
		t.Fatal("expected at least one SQLite error match")
	}
}

func TestFindSQLErrors_MultipleDBMS(t *testing.T) {
	// Response containing errors from both MySQL and Generic
	body := []byte(`
		<html>
		<body>
		Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource
		SQL syntax error detected
		</body>
		</html>
	`)
	result := FindSQLErrors(body)

	if _, ok := result["MySQL"]; !ok {
		t.Error("expected MySQL errors to be detected")
	}
	if _, ok := result["Generic"]; !ok {
		t.Error("expected Generic errors to be detected")
	}
}

func TestFindSQLErrors_NoErrors(t *testing.T) {
	body := []byte("<html><body><h1>Welcome to our website</h1><p>Everything is fine.</p></body></html>")
	result := FindSQLErrors(body)

	if len(result) != 0 {
		t.Errorf("expected no errors in clean response, got %v", result)
	}
}

func TestFindSQLErrors_CaseSensitivity(t *testing.T) {
	// SQL error keywords should be matched case-insensitively for Generic patterns
	// but some keywords are case-specific (like ORA- codes)
	body := []byte("you have an error in your sql syntax")

	// The exact keyword is "You have an error in your SQL syntax" (mixed case)
	// This tests whether the search is case-insensitive
	result := FindSQLErrors(body)

	// We expect case-insensitive matching for better detection
	if _, ok := result["MySQL"]; !ok {
		t.Error("expected case-insensitive matching to detect MySQL error")
	}
}

func TestFindSQLErrors_EmptyBody(t *testing.T) {
	result := FindSQLErrors([]byte{})
	if len(result) != 0 {
		t.Errorf("expected no errors for empty body, got %v", result)
	}
}

func TestFindSQLErrors_NilBody(t *testing.T) {
	result := FindSQLErrors(nil)
	if len(result) != 0 {
		t.Errorf("expected no errors for nil body, got %v", result)
	}
}

func TestFindSQLErrors_GenericErrors(t *testing.T) {
	body := []byte("unexpected end of SQL command")
	result := FindSQLErrors(body)

	genericErrors, ok := result["Generic"]
	if !ok {
		t.Fatal("expected Generic errors to be detected")
	}
	found := false
	for _, e := range genericErrors {
		if strings.Contains(e, "unexpected end of SQL command") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'unexpected end of SQL command' match, got %v", genericErrors)
	}
}
