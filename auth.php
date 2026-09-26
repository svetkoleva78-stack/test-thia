<?php
session_start();

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

// ========================
// Logging Configuration
// ========================
$logFile = __DIR__ . '/auth.log';

/**
 * Log a message to file with timestamp and level
 * @param string $level Log level (INFO, WARNING, ERROR)
 * @param string $message Message to log
 */
function logAuth($level, $message) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[$timestamp] [$level] $message" . PHP_EOL;
    
    try {
        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    } catch (\Exception $e) {
        // Fallback: attempt to log to error_log if file logging fails
        error_log("[$timestamp] [$level] $message");
    }
}

// ========================
// Database Connection
// ========================
try {
    $pdo = new PDO($dsn, $user, $pass, $options);
    logAuth('INFO', 'Database connection established successfully.');
} catch (\PDOException $e) {
    logAuth('ERROR', 'Database connection failed: ' . $e->getMessage());
    error_log('Auth: Critical - Database connection failed: ' . $e->getMessage());
    die('A system error occurred. Please try again later.');
}

// ========================
// Validation Helpers
// ========================

/**
 * Validate username format and length
 * @param string $username
 * @return bool
 */
function isValidUsername($username) {
    if (empty($username)) {
        return false;
    }
    if (strlen($username) < 3 || strlen($username) > 50) {
        return false;
    }
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        return false;
    }
    return true;
}

/**
 * Validate password strength
 * @param string $password
 * @return bool
 */
function isValidPassword($password) {
    if (empty($password)) {
        return false;
    }
    if (strlen($password) < 8) {
        return false;
    }
    return true;
}

/**
 * Sanitize input to prevent XSS
 * @param string $input
 * @return string
 */
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// ========================
// Authentication Functions
// ========================

/**
 * Register a new user
 * @param PDO $pdo
 * @param string $username
 * @param string $password
 * @return array ['success' => bool, 'message' => string]
 */
function registerUser($pdo, $username, $password) {
    try {
        // Validate inputs
        if (!isValidUsername($username)) {
            logAuth('WARNING', "Registration failed: Invalid username format.");
            return [
                'success' => false,
                'message' => 'Invalid username. Must be 3-50 characters, alphanumeric and underscores only.'
            ];
        }

        if (!isValidPassword($password)) {
            logAuth('WARNING', "Registration failed: Weak password.");
            return [
                'success' => false,
                'message' => 'Password must be at least 8 characters long.'
            ];
        }

        // Check if username already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username LIMIT 1");
        $stmt->execute([':username' => $username]);
        
        if ($stmt->fetch()) {
            logAuth('WARNING', "Registration failed: Username already taken - '$username'.");
            return [
                'success' => false,
                'message' => 'Username already exists. Please choose another.'
            ];
        }

        // Hash password and insert user
        $hash = password_hash($password, PASSWORD_DEFAULT);
        
        $insertStmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
        $insertStmt->execute([
            ':username' => $username,
            ':password' => $hash
        ]);

        logAuth('INFO', "New user registered successfully: '$username'.");
        return [
            'success' => true,
            'message' => 'Registration successful!'
        ];

    } catch (\PDOException $e) {
        logAuth('ERROR', "Registration database error for '$username': " . $e->getMessage());
        error_log('Auth: Registration database error: ' . $e->getMessage());
        return [
            'success' => false,
            'message' => 'A database error occurred. Please try again later.'
        ];
    } catch (\Exception $e) {
        logAuth('ERROR', "Registration unexpected error for '$username': " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'An unexpected error occurred. Please try again later.'
        ];
    }
}

/**
 * Login a user
 * @param PDO $pdo
 * @param string $username
 * @param string $password
 * @return array ['success' => bool, 'message' => string]
 */
function loginUser($pdo, $username, $password) {
    try {
        // Validate inputs
        if (empty($username) || empty($password)) {
            logAuth('WARNING', "Login failed: Empty username or password provided.");
            return [
                'success' => false,
                'message' => 'Please provide both username and password.'
            ];
        }

        $sanitizedUsername = sanitizeInput($username);

        // Fetch user by username
        $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = :username LIMIT 1");
        $stmt->execute([':username' => $sanitizedUsername]);
        $user = $stmt->fetch();

        if (!$user) {
            logAuth('WARNING', "Login failed: User not found - '$sanitizedUsername'.");
            return [
                'success' => false,
                'message' => 'Invalid username or password.'
            ];
        }

        // Verify password
        if (!password_verify($password, $user['password'])) {
            logAuth('WARNING', "Login failed: Incorrect password for user '$sanitizedUsername'.");
            return [
                'success' => false,
                'message' => 'Invalid username or password.'
            ];
        }

        // Password is correct — start a fresh session
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];

        logAuth('INFO', "User logged in successfully: '$sanitizedUsername' (ID: {$user['id']}).");
        return [
            'success' => true,
            'message' => 'Login successful!'
        ];

    } catch (\PDOException $e) {
        logAuth('ERROR', "Login database error for '$username': " . $e->getMessage());
        error_log('Auth: Login database error: ' . $e->getMessage());
        return [
            'success' => false,
            'message' => 'A database error occurred. Please try again later.'
        ];
    } catch (\Exception $e) {
        logAuth('ERROR', "Login unexpected error for '$username': " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'An unexpected error occurred. Please try again later.'
        ];
    }
}

/**
 * Check if a user is currently logged in
 * @return bool
 */
function isLoggedIn() {
    try {
        if (isset($_SESSION['user_id']) && !empty($_SESSION['user_id'])) {
            return true;
        }
        return false;
    } catch (\Exception $e) {
        logAuth('ERROR', "Session check error: " . $e->getMessage());
        return false;
    }
}

/**
 * Get the currently logged-in user's ID
 * @return int|null
 */
function getCurrentUserId() {
    try {
        if (isset($_SESSION['user_id'])) {
            return (int)$_SESSION['user_id'];
        }
        return null;
    } catch (\Exception $e) {
        logAuth('ERROR', "Error retrieving current user ID: " . $e->getMessage());
        return null;
    }
}

/**
 * Get the currently logged-in user's username
 * @return string|null
 */
function getCurrentUsername() {
    try {
        if (isset($_SESSION['username'])) {
            return sanitizeInput($_SESSION['username']);
        }
        return null;
    } catch (\Exception $e) {
        logAuth('ERROR', "Error retrieving current username: " . $e->getMessage());
        return null;
    }
}

/**
 * Logout the current user
 * @return void
 */
function logoutUser() {
    try {
        $username = isset($_SESSION['username']) ? sanitizeInput($_SESSION['username']) : 'unknown';
        
        session_unset();
        session_destroy();

        // Clear session cookie
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }

        logAuth('INFO', "User logged out successfully: '$username'.");
        header("Location: login.php");
        exit;

    } catch (\Exception $e) {
        logAuth('ERROR', "Logout error for '$username': " . $e->getMessage());
        error_log('Auth: Logout error: ' . $e->getMessage());
        header("Location: login.php");
        exit;
    }
}

/**
 * Require the user to be logged in, otherwise redirect to login page
 * @param string $redirectUrl URL to redirect to if not logged in
 * @return void
 */
function requireLogin($redirectUrl = 'login.php') {
    try {
        if (!isLoggedIn()) {
            logAuth('WARNING', "Unauthorized access attempt — redirecting to login.");
            header("Location: $redirectUrl");
            exit;
        }
    } catch (\Exception $e) {
        logAuth('ERROR', "Require login error: " . $e->getMessage());
        header("Location: $redirectUrl");
        exit;
    }
}

/**
 * Invalidate all sessions for a user (useful after password change)
 * @param PDO $pdo
 * @param int $userId
 * @return bool
 */
function invalidateUserSessions($pdo, $userId) {
    try {
        $stmt = $pdo->prepare("DELETE FROM sessions WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $userId]);
        
        logAuth('INFO', "All sessions invalidated for user ID: $userId.");
        return true;
    } catch (\PDOException $e) {
        logAuth('ERROR', "Error invalidating sessions for user ID $userId: " . $e->getMessage());
        return false;
    }
}

?>