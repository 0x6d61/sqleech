package transport

import (
	"testing"
)

func TestRandomUserAgentNotEmpty(t *testing.T) {
	ua := RandomUserAgent()
	if ua == "" {
		t.Error("RandomUserAgent() returned empty string")
	}
}

func TestRandomUserAgentReturnsFromList(t *testing.T) {
	ua := RandomUserAgent()
	found := false
	for _, agent := range userAgents {
		if ua == agent {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RandomUserAgent() returned %q which is not in the userAgents list", ua)
	}
}

func TestUserAgentsListHasMinimumEntries(t *testing.T) {
	if len(userAgents) < 20 {
		t.Errorf("userAgents list has %d entries, want at least 20", len(userAgents))
	}
}

func TestRandomUserAgentVariation(t *testing.T) {
	// Call RandomUserAgent many times and check that we get at least 2 different values.
	// With 20+ entries, getting the same one 100 times in a row is astronomically unlikely.
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		seen[RandomUserAgent()] = true
	}
	if len(seen) < 2 {
		t.Errorf("RandomUserAgent() returned only %d unique value(s) in 100 calls; expected variation", len(seen))
	}
}

func TestUserAgentsArePlausible(t *testing.T) {
	for i, ua := range userAgents {
		if len(ua) < 10 {
			t.Errorf("userAgents[%d] = %q is suspiciously short", i, ua)
		}
	}
}
