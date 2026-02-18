CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(200),
    role VARCHAR(50) DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS secret_data (
    id SERIAL PRIMARY KEY,
    flag VARCHAR(200) NOT NULL
);

INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@example.com', 'admin'),
('user1', 'pass123', 'user1@example.com', 'user'),
('user2', 'pass456', 'user2@example.com', 'user'),
('test', 'test123', 'test@example.com', 'user');

INSERT INTO products (name, description, price, category) VALUES
('Widget A', 'A standard widget', 19.99, 'widgets'),
('Widget B', 'A premium widget', 49.99, 'widgets'),
('Gadget X', 'An amazing gadget', 99.99, 'gadgets'),
('Tool Y', 'A useful tool', 29.99, 'tools');

INSERT INTO secret_data (flag) VALUES
('FLAG{sqleech_postgres_pwned}'),
('FLAG{cast_error_works}'),
('FLAG{pg_boolean_blind_works}');
