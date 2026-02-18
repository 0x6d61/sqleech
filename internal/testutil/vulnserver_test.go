package testutil

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestVulnServer_ErrorMySQL_Normal(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/error-mysql?id=1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Product: Widget") {
		t.Errorf("body does not contain expected product text, got: %s", bodyStr)
	}
}

func TestVulnServer_ErrorMySQL_SQLError(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/error-mysql?id=1'")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "You have an error in your SQL syntax") {
		t.Errorf("body does not contain MySQL error, got: %s", bodyStr)
	}
}

func TestVulnServer_ErrorMySQL_Extractvalue(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/error-mysql?id=" + url.QueryEscape("1 AND extractvalue(1,concat(0x7e,(@@version)))-- "))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "XPATH syntax error") {
		t.Errorf("body does not contain XPATH error, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "~"+mockVersionMySQL+"~") {
		t.Errorf("body does not contain version %s, got: %s", mockVersionMySQL, bodyStr)
	}
}

func TestVulnServer_ErrorMySQL_Updatexml(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/error-mysql?id=" + url.QueryEscape("1 AND updatexml(1,concat(0x7e,(@@version)),1)-- "))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "XPATH syntax error") {
		t.Errorf("body does not contain XPATH error, got: %s", bodyStr)
	}
}

func TestVulnServer_ErrorPostgres_Normal(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/error-postgres?id=1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "User: admin") {
		t.Errorf("body does not contain expected user text, got: %s", bodyStr)
	}
}

func TestVulnServer_ErrorPostgres_CastError(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/error-postgres?id=" + url.QueryEscape("1 AND CAST((version()) AS INT)-- "))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "invalid input syntax for type integer") {
		t.Errorf("body does not contain PostgreSQL cast error, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, mockVersionPostgreSQL) {
		t.Errorf("body does not contain version %s, got: %s", mockVersionPostgreSQL, bodyStr)
	}
}

func TestVulnServer_Boolean_True(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/boolean?id=" + url.QueryEscape("1 AND 1=1"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Welcome! Your item: Widget") {
		t.Errorf("AND 1=1 should return normal page, got: %s", bodyStr)
	}
}

func TestVulnServer_Boolean_False(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/vuln/boolean?id=" + url.QueryEscape("1 AND 1=2"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "No items found") {
		t.Errorf("AND 1=2 should return false page, got: %s", bodyStr)
	}
}

func TestVulnServer_Boolean_ASCIISubstring(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	// '8' = ASCII 56. Check ASCII(SUBSTRING(x,1,1))>55 should be true (56>55)
	resp, err := http.Get(srv.URL + "/vuln/boolean?id=" + url.QueryEscape("1 AND ASCII(SUBSTRING((@@version),1,1))>55"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Welcome! Your item: Widget") {
		t.Errorf("ASCII 56 > 55 should return true page, got: %s", bodyStr)
	}

	// Check ASCII(SUBSTRING(x,1,1))>56 should be false (56 is not > 56)
	resp2, err := http.Get(srv.URL + "/vuln/boolean?id=" + url.QueryEscape("1 AND ASCII(SUBSTRING((@@version),1,1))>56"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	bodyStr2 := string(body2)

	if !strings.Contains(bodyStr2, "No items found") {
		t.Errorf("ASCII 56 > 56 should return false page, got: %s", bodyStr2)
	}
}

func TestVulnServer_Boolean_Length(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	// mockVersionMySQL is "8.0.32" which has length 6
	// LENGTH(x)>5 should be true (6>5)
	resp, err := http.Get(srv.URL + "/vuln/boolean?id=" + url.QueryEscape("1 AND LENGTH((@@version))>5"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Welcome! Your item: Widget") {
		t.Errorf("LENGTH 6 > 5 should return true page, got: %s", bodyStr)
	}

	// LENGTH(x)>6 should be false (6 is not > 6)
	resp2, err := http.Get(srv.URL + "/vuln/boolean?id=" + url.QueryEscape("1 AND LENGTH((@@version))>6"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	bodyStr2 := string(body2)

	if !strings.Contains(bodyStr2, "No items found") {
		t.Errorf("LENGTH 6 > 6 should return false page, got: %s", bodyStr2)
	}
}

func TestVulnServer_Safe(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	// Normal request
	resp1, err := http.Get(srv.URL + "/vuln/safe?id=1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)

	// Request with injection attempt
	resp2, err := http.Get(srv.URL + "/vuln/safe?id=" + url.QueryEscape("1' OR '1'='1"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	if string(body1) != string(body2) {
		t.Errorf("safe endpoint should return identical responses regardless of input\ngot1: %s\ngot2: %s", body1, body2)
	}

	if !strings.Contains(string(body1), "Product details for item 42") {
		t.Errorf("safe endpoint should contain product text, got: %s", body1)
	}
}

func TestVulnServer_Multi(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	// id is injectable - single quote should cause SQL error
	resp1, err := http.Get(srv.URL + "/vuln/multi?id=1'&name=test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)

	if !strings.Contains(string(body1), "You have an error in your SQL syntax") {
		t.Errorf("id should be injectable, got: %s", body1)
	}

	// name is NOT injectable - changing name should not affect response
	resp2, err := http.Get(srv.URL + "/vuln/multi?id=1&name=test")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)

	resp3, err := http.Get(srv.URL + "/vuln/multi?id=1&name=" + url.QueryEscape("test' OR '1'='1"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp3.Body.Close()
	body3, _ := io.ReadAll(resp3.Body)

	if string(body2) != string(body3) {
		t.Errorf("name parameter should not affect response\ngot2: %s\ngot3: %s", body2, body3)
	}
}

func TestVulnServer_Post_Normal(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/vuln/post", url.Values{
		"username": {"admin"},
		"password": {"secret"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Welcome back, admin!") {
		t.Errorf("normal POST should return welcome page, got: %s", bodyStr)
	}
}

func TestVulnServer_Post_BooleanTrue(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/vuln/post", url.Values{
		"username": {"admin AND 1=1"},
		"password": {"secret"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Welcome back, admin!") {
		t.Errorf("AND 1=1 should return normal page, got: %s", bodyStr)
	}
}

func TestVulnServer_Post_BooleanFalse(t *testing.T) {
	srv := NewVulnServer()
	defer srv.Close()

	resp, err := http.PostForm(srv.URL+"/vuln/post", url.Values{
		"username": {"admin AND 1=2"},
		"password": {"secret"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "Login failed") {
		t.Errorf("AND 1=2 should return false page, got: %s", bodyStr)
	}
}
