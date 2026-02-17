package cli

import (
	"testing"
)

func TestRootCommandExists(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}
	if rootCmd.Use != "sqleech" {
		t.Errorf("expected Use to be 'sqleech', got %q", rootCmd.Use)
	}
}

func TestVersionCommandExists(t *testing.T) {
	if versionCmd == nil {
		t.Fatal("versionCmd should not be nil")
	}
	if versionCmd.Use != "version" {
		t.Errorf("expected Use to be 'version', got %q", versionCmd.Use)
	}
}

func TestExecuteReturnsNoError(t *testing.T) {
	// Reset args for testing
	rootCmd.SetArgs([]string{"version"})
	if err := Execute(); err != nil {
		t.Errorf("Execute() returned error: %v", err)
	}
}
