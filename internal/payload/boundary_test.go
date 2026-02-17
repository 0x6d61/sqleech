package payload

import (
	"testing"
)

func TestCommonBoundaries_NotEmpty(t *testing.T) {
	t.Parallel()
	boundaries := CommonBoundaries()
	if len(boundaries) == 0 {
		t.Error("CommonBoundaries() returned empty slice")
	}
}

func TestCommonBoundaries_AllHaveSuffix(t *testing.T) {
	t.Parallel()
	for i, b := range CommonBoundaries() {
		if b.Suffix == "" {
			t.Errorf("boundary[%d] (%q) has empty Suffix", i, b.Comment)
		}
	}
}

func TestPrefixesForType_Integer(t *testing.T) {
	t.Parallel()
	prefixes := PrefixesForType(TypeInteger)
	if len(prefixes) == 0 {
		t.Fatal("PrefixesForType(TypeInteger) returned empty slice")
	}
	// Integer context should include "" (no prefix needed).
	found := false
	for _, p := range prefixes {
		if p == "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("PrefixesForType(TypeInteger) should include empty string prefix")
	}
}

func TestPrefixesForType_String(t *testing.T) {
	t.Parallel()
	prefixes := PrefixesForType(TypeString)
	if len(prefixes) == 0 {
		t.Fatal("PrefixesForType(TypeString) returned empty slice")
	}
	hasSingle := false
	hasDouble := false
	for _, p := range prefixes {
		if p == "'" {
			hasSingle = true
		}
		if p == "\"" {
			hasDouble = true
		}
	}
	if !hasSingle {
		t.Error("PrefixesForType(TypeString) should include single quote")
	}
	if !hasDouble {
		t.Error("PrefixesForType(TypeString) should include double quote")
	}
}

func TestSuffixesForDBMS_MySQL(t *testing.T) {
	t.Parallel()
	suffixes := SuffixesForDBMS("MySQL")
	if len(suffixes) == 0 {
		t.Fatal("SuffixesForDBMS(\"MySQL\") returned empty slice")
	}
	hasHash := false
	for _, s := range suffixes {
		if s == "#" {
			hasHash = true
			break
		}
	}
	if !hasHash {
		t.Error("MySQL suffixes should include '#'")
	}
}

func TestSuffixesForDBMS_PostgreSQL(t *testing.T) {
	t.Parallel()
	suffixes := SuffixesForDBMS("PostgreSQL")
	if len(suffixes) == 0 {
		t.Fatal("SuffixesForDBMS(\"PostgreSQL\") returned empty slice")
	}
	for _, s := range suffixes {
		if s == "#" {
			t.Error("PostgreSQL suffixes should NOT include '#'")
		}
	}
}

func TestSuffixesForDBMS_Generic(t *testing.T) {
	t.Parallel()
	suffixes := SuffixesForDBMS("")
	if len(suffixes) == 0 {
		t.Fatal("SuffixesForDBMS(\"\") returned empty slice")
	}
	// Generic should include common suffixes.
	has := map[string]bool{"-- -": false, "#": false, "/*": false}
	for _, s := range suffixes {
		if _, ok := has[s]; ok {
			has[s] = true
		}
	}
	for k, v := range has {
		if !v {
			t.Errorf("Generic suffixes should include %q", k)
		}
	}
}
