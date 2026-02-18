CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(200),
    role VARCHAR(50) DEFAULT 'user'
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    category VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS secret_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
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
('FLAG{sqleech_mysql_pwned}'),
('FLAG{error_based_works}'),
('FLAG{boolean_blind_works}');
