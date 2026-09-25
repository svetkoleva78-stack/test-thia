<?php
session_start();

// Database configuration
$host = 'localhost';
$db   = 'test_db';
$user = 'root';
$pass = '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    throw new \PDOException($e->getMessage(), (int)$e->getCode());
}

/**
 * Register a new user
 */
function registerUser($pdo, $username, $password) {
    // Hash the password
    $hash = password_hash($password, PASSWORD_DEFAULT);

    // Prepare statement to prevent SQL injection
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
    
    // Execute with parameters
    $stmt->execute([
        ':username' => $username,
        ':password' => $hash
    ]);

    return true;
}

/**
 * Login a user
 */
function loginUser($pdo, $username, $password) {
    // Prepare statement to fetch user by username
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username LIMIT 1");
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        // Regenerate session ID to prevent session fixation attacks
        session_regenerate_id(true);
        
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        
        return true;
    }

    // Log failed login attempt
    error_log('Failed login attempt for user: ' . $username . ' at ' . date('Y-m-d H:i:s'));

    return false;
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

/**
 * Logout the current user
 */
function logoutUser() {
    session_unset();
    session_destroy();
    header("Location: login.php");
    exit;
}
?>