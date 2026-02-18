package cli

import (
	"testing"
	"time"
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

func TestScanCommand_Exists(t *testing.T) {
	if scanCmd == nil {
		t.Fatal("scanCmd should not be nil")
	}
	if scanCmd.Use != "scan" {
		t.Errorf("expected Use to be 'scan', got %q", scanCmd.Use)
	}

	// Verify scan is registered as a subcommand of root
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "scan" {
			found = true
			break
		}
	}
	if !found {
		t.Error("scan subcommand not registered on rootCmd")
	}
}

func TestScanCommand_MissingURL(t *testing.T) {
	rootCmd.SetArgs([]string{"scan"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error when --url is not provided, got nil")
	}
	expected := "target URL is required (use --url or -u)"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

func TestGlobalFlags_Defaults(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		getVal   func() (interface{}, error)
		expected interface{}
	}{
		{
			name:     "url default is empty",
			flagName: "url",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("url")
			},
			expected: "",
		},
		{
			name:     "method default is GET",
			flagName: "method",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("method")
			},
			expected: "GET",
		},
		{
			name:     "data default is empty",
			flagName: "data",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("data")
			},
			expected: "",
		},
		{
			name:     "cookie default is empty",
			flagName: "cookie",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("cookie")
			},
			expected: "",
		},
		{
			name:     "proxy default is empty",
			flagName: "proxy",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("proxy")
			},
			expected: "",
		},
		{
			name:     "threads default is 10",
			flagName: "threads",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetInt("threads")
			},
			expected: 10,
		},
		{
			name:     "timeout default is 30s",
			flagName: "timeout",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetDuration("timeout")
			},
			expected: 30 * time.Second,
		},
		{
			name:     "verbose default is 0",
			flagName: "verbose",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetInt("verbose")
			},
			expected: 0,
		},
		{
			name:     "output default is empty",
			flagName: "output",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("output")
			},
			expected: "",
		},
		{
			name:     "format default is text",
			flagName: "format",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("format")
			},
			expected: "text",
		},
		{
			name:     "dbms default is empty",
			flagName: "dbms",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("dbms")
			},
			expected: "",
		},
		{
			name:     "technique default is empty",
			flagName: "technique",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetString("technique")
			},
			expected: "",
		},
		{
			name:     "force-ssl default is false",
			flagName: "force-ssl",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetBool("force-ssl")
			},
			expected: false,
		},
		{
			name:     "random-agent default is false",
			flagName: "random-agent",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetBool("random-agent")
			},
			expected: false,
		},
		{
			name:     "force-test default is false",
			flagName: "force-test",
			getVal: func() (interface{}, error) {
				return rootCmd.PersistentFlags().GetBool("force-test")
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := tt.getVal()
			if err != nil {
				t.Fatalf("error getting flag %q: %v", tt.flagName, err)
			}
			if val != tt.expected {
				t.Errorf("flag %q: expected %v (%T), got %v (%T)",
					tt.flagName, tt.expected, tt.expected, val, val)
			}
		})
	}
}

func TestGlobalFlags_URL(t *testing.T) {
	rootCmd.SetArgs([]string{"scan", "--url", "http://example.com/page?id=1"})
	// This will fail because we can't actually connect, but we verify the flag is parsed
	_ = rootCmd.Execute()

	val, err := rootCmd.PersistentFlags().GetString("url")
	if err != nil {
		t.Fatalf("error getting url flag: %v", err)
	}
	if val != "http://example.com/page?id=1" {
		t.Errorf("expected url to be 'http://example.com/page?id=1', got %q", val)
	}
}

func TestGlobalFlags_Method(t *testing.T) {
	rootCmd.SetArgs([]string{"scan", "--url", "http://example.com", "--method", "POST"})
	_ = rootCmd.Execute()

	val, err := rootCmd.PersistentFlags().GetString("method")
	if err != nil {
		t.Fatalf("error getting method flag: %v", err)
	}
	if val != "POST" {
		t.Errorf("expected method to be 'POST', got %q", val)
	}
}

func TestGlobalFlags_Threads(t *testing.T) {
	rootCmd.SetArgs([]string{"scan", "--url", "http://example.com", "--threads", "20"})
	_ = rootCmd.Execute()

	val, err := rootCmd.PersistentFlags().GetInt("threads")
	if err != nil {
		t.Fatalf("error getting threads flag: %v", err)
	}
	if val != 20 {
		t.Errorf("expected threads to be 20, got %d", val)
	}
}

func TestParseCookieString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:  "single cookie",
			input: "PHPSESSID=abc123",
			expected: map[string]string{
				"PHPSESSID": "abc123",
			},
		},
		{
			name:  "multiple cookies",
			input: "PHPSESSID=abc123; token=xyz789; user=admin",
			expected: map[string]string{
				"PHPSESSID": "abc123",
				"token":     "xyz789",
				"user":      "admin",
			},
		},
		{
			name:  "cookies with spaces",
			input: " name1 = val1 ; name2 = val2 ",
			expected: map[string]string{
				"name1": "val1",
				"name2": "val2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCookieString(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d cookies, got %d", len(tt.expected), len(result))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("cookie %q: expected %q, got %q", k, v, result[k])
				}
			}
		})
	}
}

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected map[string]string
	}{
		{
			name:     "empty headers",
			input:    nil,
			expected: map[string]string{},
		},
		{
			name:  "single header",
			input: []string{"X-Custom: value"},
			expected: map[string]string{
				"X-Custom": "value",
			},
		},
		{
			name:  "multiple headers",
			input: []string{"X-Custom: value", "Authorization: Bearer token123"},
			expected: map[string]string{
				"X-Custom":      "value",
				"Authorization": "Bearer token123",
			},
		},
		{
			name:  "header with colon in value",
			input: []string{"X-Forward: http://example.com:8080"},
			expected: map[string]string{
				"X-Forward": "http://example.com:8080",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHeaders(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d headers, got %d", len(tt.expected), len(result))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("header %q: expected %q, got %q", k, v, result[k])
				}
			}
		})
	}
}
