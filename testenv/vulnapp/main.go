// Intentionally vulnerable web application for testing sqleech.
// DO NOT deploy this in any production environment.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

var mysqlDB *sql.DB
var postgresDB *sql.DB

func main() {
	var err error

	mysqlDSN := os.Getenv("MYSQL_DSN")
	if mysqlDSN != "" {
		mysqlDB, err = sql.Open("mysql", mysqlDSN)
		if err != nil {
			log.Fatalf("MySQL connection failed: %v", err)
		}
		if err = mysqlDB.Ping(); err != nil {
			log.Fatalf("MySQL ping failed: %v", err)
		}
		log.Println("Connected to MySQL")
	}

	postgresDSN := os.Getenv("POSTGRES_DSN")
	if postgresDSN != "" {
		postgresDB, err = sql.Open("postgres", postgresDSN)
		if err != nil {
			log.Fatalf("PostgreSQL connection failed: %v", err)
		}
		if err = postgresDB.Ping(); err != nil {
			log.Fatalf("PostgreSQL ping failed: %v", err)
		}
		log.Println("Connected to PostgreSQL")
	}

	// MySQL vulnerable endpoints
	http.HandleFunc("/mysql/user", mysqlUserHandler)
	http.HandleFunc("/mysql/product", mysqlProductHandler)
	http.HandleFunc("/mysql/search", mysqlSearchHandler)
	http.HandleFunc("/mysql/login", mysqlLoginHandler)

	// PostgreSQL vulnerable endpoints
	http.HandleFunc("/pg/user", pgUserHandler)
	http.HandleFunc("/pg/product", pgProductHandler)
	http.HandleFunc("/pg/search", pgSearchHandler)
	http.HandleFunc("/pg/login", pgLoginHandler)

	// Safe endpoints (parameterized queries)
	http.HandleFunc("/safe/mysql/user", safeMysqlUserHandler)
	http.HandleFunc("/safe/pg/user", safePgUserHandler)

	// Time-based blind vulnerable endpoints
	http.HandleFunc("/mysql/sleep", mysqlSleepHandler)
	http.HandleFunc("/pg/sleep", pgSleepHandler)

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "OK")
	})

	// Index
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Vulnerable Test App</title></head>
<body>
<h1>sqleech Test Server</h1>
<p>WARNING: This is an intentionally vulnerable application for testing only.</p>
<h2>MySQL Endpoints (Vulnerable)</h2>
<ul>
<li><a href="/mysql/user?id=1">/mysql/user?id=1</a> - Get user by ID</li>
<li><a href="/mysql/product?id=1">/mysql/product?id=1</a> - Get product by ID</li>
<li><a href="/mysql/search?q=widget">/mysql/search?q=widget</a> - Search products</li>
<li>/mysql/login (POST: username, password)</li>
</ul>
<h2>PostgreSQL Endpoints (Vulnerable)</h2>
<ul>
<li><a href="/pg/user?id=1">/pg/user?id=1</a> - Get user by ID</li>
<li><a href="/pg/product?id=1">/pg/product?id=1</a> - Get product by ID</li>
<li><a href="/pg/search?q=widget">/pg/search?q=widget</a> - Search products</li>
<li>/pg/login (POST: username, password)</li>
</ul>
<h2>Safe Endpoints (Parameterized)</h2>
<ul>
<li><a href="/safe/mysql/user?id=1">/safe/mysql/user?id=1</a></li>
<li><a href="/safe/pg/user?id=1">/safe/pg/user?id=1</a></li>
</ul>
</body></html>`)
	})

	log.Println("Vulnerable test server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ==================== MySQL Vulnerable Handlers ====================

func mysqlUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	// VULNERABLE: Direct string concatenation
	query := fmt.Sprintf("SELECT id, username, email, role FROM users WHERE id = %s", id)
	log.Printf("[MySQL] Query: %s", query)

	rows, err := mysqlDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		// VULNERABLE: Error message exposed
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>User Profile</h1>")
	found := false
	for rows.Next() {
		var uid int
		var username, email, role string
		if err := rows.Scan(&uid, &username, &email, &role); err != nil {
			fmt.Fprintf(w, "<p>Error: %s</p>", err.Error())
			continue
		}
		found = true
		fmt.Fprintf(w, "<div class='user'><p>ID: %d</p><p>Username: %s</p><p>Email: %s</p><p>Role: %s</p></div>", uid, username, email, role)
	}
	if !found {
		fmt.Fprint(w, "<p>No user found.</p>")
	}
	fmt.Fprint(w, "</body></html>")
}

func mysqlProductHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	// VULNERABLE: Direct string concatenation
	query := fmt.Sprintf("SELECT id, name, description, price, category FROM products WHERE id = %s", id)
	log.Printf("[MySQL] Query: %s", query)

	rows, err := mysqlDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>Product Details</h1>")
	found := false
	for rows.Next() {
		var pid int
		var name, desc, category string
		var price float64
		if err := rows.Scan(&pid, &name, &desc, &price, &category); err != nil {
			fmt.Fprintf(w, "<p>Error: %s</p>", err.Error())
			continue
		}
		found = true
		fmt.Fprintf(w, "<div class='product'><p>ID: %d</p><p>Name: %s</p><p>Description: %s</p><p>Price: $%.2f</p><p>Category: %s</p></div>",
			pid, name, desc, price, category)
	}
	if !found {
		fmt.Fprint(w, "<p>No product found.</p>")
	}
	fmt.Fprint(w, "</body></html>")
}

func mysqlSearchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		http.Error(w, "Missing q parameter", 400)
		return
	}

	// VULNERABLE: String concatenation with quotes
	query := fmt.Sprintf("SELECT id, name, price FROM products WHERE name LIKE '%%%s%%'", q)
	log.Printf("[MySQL] Query: %s", query)

	rows, err := mysqlDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Search Results for '%s'</h1>", q)
	count := 0
	for rows.Next() {
		var pid int
		var name string
		var price float64
		if err := rows.Scan(&pid, &name, &price); err != nil {
			continue
		}
		count++
		fmt.Fprintf(w, "<div><p>%d. %s - $%.2f</p></div>", pid, name, price)
	}
	fmt.Fprintf(w, "<p>%d results found.</p></body></html>", count)
}

func mysqlLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Login</h1>
<form method="POST"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Login</button></form></body></html>`)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULNERABLE: Direct string concatenation in WHERE
	query := fmt.Sprintf("SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'", username, password)
	log.Printf("[MySQL] Query: %s", query)

	rows, err := mysqlDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	if rows.Next() {
		var uid int
		var uname, role string
		rows.Scan(&uid, &uname, &role)
		fmt.Fprintf(w, "<html><body><h1>Welcome %s!</h1><p>Role: %s</p></body></html>", uname, role)
	} else {
		fmt.Fprint(w, "<html><body><h1>Login Failed</h1><p>Invalid username or password.</p></body></html>")
	}
}

// ==================== PostgreSQL Vulnerable Handlers ====================

func pgUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	query := fmt.Sprintf("SELECT id, username, email, role FROM users WHERE id = %s", id)
	log.Printf("[PostgreSQL] Query: %s", query)

	rows, err := postgresDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>User Profile</h1>")
	found := false
	for rows.Next() {
		var uid int
		var username, email, role string
		if err := rows.Scan(&uid, &username, &email, &role); err != nil {
			fmt.Fprintf(w, "<p>Error: %s</p>", err.Error())
			continue
		}
		found = true
		fmt.Fprintf(w, "<div class='user'><p>ID: %d</p><p>Username: %s</p><p>Email: %s</p><p>Role: %s</p></div>", uid, username, email, role)
	}
	if !found {
		fmt.Fprint(w, "<p>No user found.</p>")
	}
	fmt.Fprint(w, "</body></html>")
}

func pgProductHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	query := fmt.Sprintf("SELECT id, name, description, price, category FROM products WHERE id = %s", id)
	log.Printf("[PostgreSQL] Query: %s", query)

	rows, err := postgresDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>Product Details</h1>")
	found := false
	for rows.Next() {
		var pid int
		var name, desc, category string
		var price float64
		if err := rows.Scan(&pid, &name, &desc, &price, &category); err != nil {
			continue
		}
		found = true
		fmt.Fprintf(w, "<div class='product'><p>ID: %d</p><p>Name: %s</p><p>Description: %s</p><p>Price: $%.2f</p><p>Category: %s</p></div>",
			pid, name, desc, price, category)
	}
	if !found {
		fmt.Fprint(w, "<p>No product found.</p>")
	}
	fmt.Fprint(w, "</body></html>")
}

func pgSearchHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		http.Error(w, "Missing q parameter", 400)
		return
	}

	query := fmt.Sprintf("SELECT id, name, price FROM products WHERE name ILIKE '%%%s%%'", q)
	log.Printf("[PostgreSQL] Query: %s", query)

	rows, err := postgresDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Search Results for '%s'</h1>", q)
	count := 0
	for rows.Next() {
		var pid int
		var name string
		var price float64
		if err := rows.Scan(&pid, &name, &price); err != nil {
			continue
		}
		count++
		fmt.Fprintf(w, "<div><p>%d. %s - $%.2f</p></div>", pid, name, price)
	}
	fmt.Fprintf(w, "<p>%d results found.</p></body></html>", count)
}

func pgLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Login</h1>
<form method="POST"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Login</button></form></body></html>`)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	query := fmt.Sprintf("SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'", username, password)
	log.Printf("[PostgreSQL] Query: %s", query)

	rows, err := postgresDB.Query(query)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Database Error</h1><p>%s</p></body></html>", err.Error())
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	if rows.Next() {
		var uid int
		var uname, role string
		rows.Scan(&uid, &uname, &role)
		fmt.Fprintf(w, "<html><body><h1>Welcome %s!</h1><p>Role: %s</p></body></html>", uname, role)
	} else {
		fmt.Fprint(w, "<html><body><h1>Login Failed</h1><p>Invalid username or password.</p></body></html>")
	}
}

// ==================== Safe Handlers (Parameterized) ====================

func safeMysqlUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	// SAFE: Parameterized query
	rows, err := mysqlDB.Query("SELECT id, username, email, role FROM users WHERE id = ?", id)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Error</h1><p>Internal server error</p></body></html>")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>User Profile</h1>")
	for rows.Next() {
		var uid int
		var username, email, role string
		rows.Scan(&uid, &username, &email, &role)
		fmt.Fprintf(w, "<div><p>ID: %d</p><p>Username: %s</p><p>Email: %s</p><p>Role: %s</p></div>", uid, username, email, role)
	}
	fmt.Fprint(w, "</body></html>")
}

func safePgUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	// SAFE: Parameterized query
	rows, err := postgresDB.Query("SELECT id, username, email, role FROM users WHERE id = $1", id)
	if err != nil {
		w.WriteHeader(500)
		fmt.Fprintf(w, "<html><body><h1>Error</h1><p>Internal server error</p></body></html>")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>User Profile</h1>")
	found := false
	for rows.Next() {
		var uid int
		var username, email, role string
		rows.Scan(&uid, &username, &email, &role)
		found = true
		fmt.Fprintf(w, "<div><p>ID: %d</p><p>Username: %s</p><p>Email: %s</p><p>Role: %s</p></div>", uid, username, email, role)
	}
	if !found {
		fmt.Fprint(w, "<p>No user found.</p>")
	}

	// Add some static content to make the page more realistic
	fmt.Fprint(w, "</body></html>")
	_ = strings.Contains(id, "'") // suppress unused import
}

// ==================== Time-based Blind Vulnerable Handlers ====================

// mysqlSleepHandler simulates a MySQL time-based blind injectable endpoint.
// The endpoint executes a real MySQL SLEEP(n) when the payload is injected.
// For sqleech testing: sqleech injects IF(1=1,SLEEP(n),0) into the id parameter.
//
// GET /mysql/sleep?id=1
func mysqlSleepHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	// VULNERABLE: Direct string concatenation — allows SLEEP injection
	query := fmt.Sprintf("SELECT id, username FROM users WHERE id = %s", id)
	log.Printf("[MySQL][timebased] Query: %s", query)

	rows, err := mysqlDB.Query(query)
	if err != nil {
		// Return 200 even on error so timing can be measured
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><body><p>No result.</p></body></html>")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><p>Result found.</p></body></html>")
}

// pgSleepHandler simulates a PostgreSQL time-based blind injectable endpoint.
// The endpoint executes a real pg_sleep(n) when the payload is injected.
//
// GET /pg/sleep?id=1
func pgSleepHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", 400)
		return
	}

	// VULNERABLE: Direct string concatenation — allows PG_SLEEP injection
	query := fmt.Sprintf("SELECT id, username FROM users WHERE id = %s", id)
	log.Printf("[PostgreSQL][timebased] Query: %s", query)

	rows, err := postgresDB.Query(query)
	if err != nil {
		w.WriteHeader(200)
		fmt.Fprint(w, "<html><body><p>No result.</p></body></html>")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><p>Result found.</p></body></html>")
}
