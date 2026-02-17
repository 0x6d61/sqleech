package dbms

import "testing"

func TestRegistryMySQL(t *testing.T) {
	d := Registry("MySQL")
	if d == nil {
		t.Fatal("Registry(\"MySQL\") returned nil")
	}
	if d.Name() != "MySQL" {
		t.Errorf("expected Name() = \"MySQL\", got %q", d.Name())
	}
}

func TestRegistryMySQLLowercase(t *testing.T) {
	d := Registry("mysql")
	if d == nil {
		t.Fatal("Registry(\"mysql\") returned nil")
	}
	if d.Name() != "MySQL" {
		t.Errorf("expected Name() = \"MySQL\", got %q", d.Name())
	}
}

func TestRegistryPostgreSQL(t *testing.T) {
	d := Registry("PostgreSQL")
	if d == nil {
		t.Fatal("Registry(\"PostgreSQL\") returned nil")
	}
	if d.Name() != "PostgreSQL" {
		t.Errorf("expected Name() = \"PostgreSQL\", got %q", d.Name())
	}
}

func TestRegistryPostgresLowercase(t *testing.T) {
	d := Registry("postgres")
	if d == nil {
		t.Fatal("Registry(\"postgres\") returned nil")
	}
	if d.Name() != "PostgreSQL" {
		t.Errorf("expected Name() = \"PostgreSQL\", got %q", d.Name())
	}
}

func TestRegistryPostgresqlLowercase(t *testing.T) {
	d := Registry("postgresql")
	if d == nil {
		t.Fatal("Registry(\"postgresql\") returned nil")
	}
	if d.Name() != "PostgreSQL" {
		t.Errorf("expected Name() = \"PostgreSQL\", got %q", d.Name())
	}
}

func TestRegistryUnknown(t *testing.T) {
	d := Registry("Unknown")
	if d != nil {
		t.Errorf("Registry(\"Unknown\") should return nil, got %v", d)
	}
}

func TestRegistryEmpty(t *testing.T) {
	d := Registry("")
	if d != nil {
		t.Errorf("Registry(\"\") should return nil, got %v", d)
	}
}
