<?php
/**
 * Thia Authentication System
 * Enhanced with security best practices
 * 
 * Features:
 * - Rate limiting for login attempts
 * - CSRF protection
 * - Strong password validation
 * - Secure session management
 * - Remember me functionality
 * - Comprehensive logging
 */

// ========================
// Security Configuration
// ========================
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 900); // 15 minutes in seconds
define('PASSWORD_MIN_LENGTH', 12);
define('SESSION_LIFETIME', 1800); // 30 minutes
define('REMEMBER_ME_LIFETIME', 2592000); // 30 days

// ========================
// Session Configuration (BEFORE session_start())
// ========================
if (session_status() === PHP_SESSION_NONE) {
    // Secure session configuration
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', isset($_SERVER['HTTPS']));
    ini_set('session.use_strict_mode', 1);
    ini_set('session.sid_length', 48);
    ini_set('session.sid_bits_per_character', 6);
    
    session_start();
}

// ========================
// Database Configuration
// ========================
$host = getenv('DB_HOST') ?: 'localhost';
$db   = getenv('DB_NAME') ?: 'test_db';
$user = getenv('DB_USER') ?: 'root';
$pass = getenv('DB_PASS') ?: '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::ATTR_PERSISTENT         => false,
];

// ========================
// Logging Configuration
// ========================
$logFile = __DIR__ . '/auth.log';

/**
 * Log a message to file with timestamp and level
 * @param string $level Log level (INFO, WARNING, ERROR, CRITICAL)
 * @param string $message Message to log
 * @param array $context Additional context data
 */
function logAuth($level, $message, array $context = []) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    $logEntry = "[$timestamp] [$level] IP: $ip | $message";
    if (!empty($context)) {
        $logEntry .= ' | Context: ' . json_encode($context, JSON_UNESCAPED_UNICODE);
    }
    $logEntry .= PHP_EOL;
    
    try {
        file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    } catch (\Exception $e) {
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
    logAuth('CRITICAL', 'Database connection failed: ' . $e->getMessage());
    error_log('Auth: Critical - Database connection failed: ' . $e->getMessage());
    die('A system error occurred. Please try again later.');
}

// ========================
// CSRF Protection
// ========================

/**
 * Generate a CSRF token
 * @return string
 */
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate a CSRF token
 * @param string $token
 * @return bool
 */
function validateCsrfToken($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Generate hidden CSRF input field
 * @return string
 */
function csrfField() {
    return '<input type="hidden" name="csrf_token" value="' . generateCsrfToken() . '">';
}

// ========================
// Rate Limiting
// ========================

/**
 * Check if user is rate limited
 * @param PDO $pdo
 * @param string $username
 * @return bool True if rate limited
 */
function isRateLimited($pdo, $username) {
    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as attempts, 
                   MAX(created_at) as last_attempt 
            FROM login_attempts 
            WHERE username = :username 
            AND created_at > DATE_SUB(NOW(), INTERVAL :interval SECOND)
        ");
        $stmt->execute([
            ':username' => $username,
            ':interval' => LOGIN_LOCKOUT_TIME
        ]);
        
        $result = $stmt->fetch();
        
        if ($result['attempts'] >= MAX_LOGIN_ATTEMPTS) {
            $remainingTime = LOGIN_LOCKOUT_TIME - strtotime($result['last_attempt']) + time();
            logAuth('WARNING', "Rate limit exceeded for user '$username'. Remaining lockout: {$remainingTime}s");
            return true;
        }
        
        return false;
    } catch (\PDOException $e) {
        logAuth('ERROR', "Rate limit check failed: " . $e->getMessage());
        return false; // Don't block on database errors
    }
}

/**
 * Record a failed login attempt
 * @param PDO $pdo
 * @param string $username
 */
function recordFailedLogin($pdo, $username) {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO login_attempts (username, ip_address, user_agent) 
            VALUES (:username, :ip, :user_agent)
        ");
        $stmt->execute([
            ':username' => $username,
            ':ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            ':user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
        
        // Clean up old attempts
        $cleanup = $pdo->prepare("
            DELETE FROM login_attempts 
            WHERE created_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
        ");
        $cleanup->execute();
        
    } catch (\PDOException $e) {
        logAuth('ERROR', "Failed to record login attempt: " . $e->getMessage());
    }
}

/**
 * Clear login attempts after successful login
 * @param PDO $pdo
 * @param string $username
 */
function clearLoginAttempts($pdo, $username) {
    try {
        $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE username = :username");
        $stmt->execute([':username' => $username]);
    } catch (\PDOException $e) {
        logAuth('ERROR', "Failed to clear login attempts: " . $e->getMessage());
    }
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
 * Validate email format
 * @param string $email
 * @return bool
 */
function isValidEmail($email) {
    if (empty($email)) {
        return false;
    }
    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        return false;
    }
    if (strlen($email) > 254) {
        return false;
    }
    return true;
}

/**
 * Validate password strength
 * @param string $password
 * @return array ['valid' => bool, 'message' => string]
 */
function validatePasswordStrength($password) {
    $errors = [];
    
    if (strlen($password) < PASSWORD_MIN_LENGTH) {
        $errors[] = "Password must be at least " . PASSWORD_MIN_LENGTH . " characters long.";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter.";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter.";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number.";
    }
    if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        $errors[] = "Password must contain at least one special character.";
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors
    ];
}

/**
 * Sanitize input to prevent XSS
 * @param string $input
 * @return string
 */
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

/**
 * Validate and sanitize form data
 * @param array $data
 * @return array
 */
function sanitizeFormData(array $data) {
    $sanitized = [];
    foreach ($data as $key => $value) {
        $sanitized[$key] = is_string($value) ? sanitizeInput($value) : $value;
    }
    return $sanitized;
}

// ========================
// Authentication Functions
// ========================

/**
 * Register a new user
 * @param PDO $pdo
 * @param string $username
 * @param string $password
 * @param string $email
 * @return array ['success' => bool, 'message' => string, 'errors' => array]
 */
function registerUser($pdo, $username, $password, $email = '') {
    try {
        // Validate username
        if (!isValidUsername($username)) {
            logAuth('WARNING', "Registration failed: Invalid username format.");
            return [
                'success' => false,
                'message' => 'Invalid username. Must be 3-50 characters, alphanumeric and underscores only.',
                'errors' => ['username' => 'Invalid username format']
            ];
        }

        // Validate password
        $passwordValidation = validatePasswordStrength($password);
        if (!$passwordValidation['valid']) {
            logAuth('WARNING', "Registration failed: Weak password.");
            return [
                'success' => false,
                'message' => implode(' ', $passwordValidation['errors']),
                'errors' => ['password' => $passwordValidation['errors']]
            ];
        }

        // Validate email if provided
        if (!empty($email) && !isValidEmail($email)) {
            logAuth('WARNING', "Registration failed: Invalid email format.");
            return [
                'success' => false,
                'message' => 'Invalid email format.',
                'errors' => ['email' => 'Invalid email format']
            ];
        }

        // Check if username already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username LIMIT 1");
        $stmt->execute([':username' => $username]);
        
        if ($stmt->fetch()) {
            logAuth('WARNING', "Registration failed: Username already taken - '$username'.");
            return [
                'success' => false,
                'message' => 'Username already exists. Please choose another.',
                'errors' => ['username' => 'Username already exists']
            ];
        }

        // Hash password and insert user
        $hash = password_hash($password, PASSWORD_DEFAULT);
        
        $insertStmt = $pdo->prepare("INSERT INTO users (username, password, email) VALUES (:username, :password, :email)");
        $insertStmt->execute([
            ':username' => $username,
            ':password' => $hash,
            ':email' => $email
        ]);

        logAuth('INFO', "New user registered successfully: '$username' (ID: {$pdo->lastInsertId()}).");
        return [
            'success' => true,
            'message' => 'Registration successful! You can now log in.',
            'errors' => []
        ];

    } catch (\PDOException $e) {
        logAuth('ERROR', "Registration database error for '$username': " . $e->getMessage());
        error_log('Auth: Registration database error: ' . $e->getMessage());
        return [
            'success' => false,
            'message' => 'A database error occurred. Please try again later.',
            'errors' => ['general' => 'Database error']
        ];
    } catch (\Exception $e) {
        logAuth('ERROR', "Registration unexpected error for '$username': " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'An unexpected error occurred. Please try again later.',
            'errors' => ['general' => 'Unexpected error']
        ];
    }
}

/**
 * Login a user
 * @param PDO $pdo
 * @param string $username
 * @param string $password
 * @param bool $remember
 * @return array ['success' => bool, 'message' => string]
 */
function loginUser($pdo, $username, $password, $remember = false) {
    try {
        // Validate inputs
        if (empty($username) || empty($password)) {
            logAuth('WARNING', "Login failed: Empty username or password provided.");
            return [
                'success' => false,
                'message' => 'Please provide both username and password.'
            ];
        }

        // Check rate limiting
        if (isRateLimited($pdo, $username)) {
            logAuth('WARNING', "Login blocked: Rate limit exceeded for '$username'.");
            return [
                'success' => false,
                'message' => 'Too many login attempts. Please try again in 15 minutes.'
            ];
        }

        $sanitizedUsername = sanitizeInput($username);

        // Fetch user by username
        $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = :username LIMIT 1");
        $stmt->execute([':username' => $sanitizedUsername]);
        $user = $stmt->fetch();

        if (!$user) {
            recordFailedLogin($pdo, $username);
            logAuth('WARNING', "Login failed: User not found - '$sanitizedUsername'.");
            return [
                'success' => false,
                'message' => 'Invalid username or password.'
            ];
        }

        // Verify password using timing-safe comparison
        if (!password_verify($password, $user['password'])) {
            recordFailedLogin($pdo, $username);
            logAuth('WARNING', "Login failed: Incorrect password for user '$sanitizedUsername'.");
            return [
                'success' => false,
                'message' => 'Invalid username or password.'
            ];
        }

        // Password is correct — clear failed attempts and start fresh session
        clearLoginAttempts($pdo, $username);
        session_regenerate_id(true);
        
        // Set session data
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity'] = time();

        // Handle remember me
        if ($remember) {
            $token = bin2hex(random_bytes(32));
            $hash = password_hash($token, PASSWORD_DEFAULT);
            
            // Store remember me token
            $stmt = $pdo->prepare("INSERT INTO remember_me_tokens (user_id, token, expires_at) VALUES (:user_id, :token, :expires)");
            $stmt->execute([
                ':user_id' => $user['id'],
                ':token' => $hash,
                ':expires' => date('Y-m-d H:i:s', time() + REMEMBER_ME_LIFETIME)
            ]);
            
            // Set cookie with token
            setcookie('remember_me', $token, [
                'expires' => time() + REMEMBER_ME_LIFETIME,
                'path' => '/',
                'domain' => '',
                'secure' => isset($_SERVER['HTTPS']),
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
        }

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
            // Check session timeout
            if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_LIFETIME)) {
                logoutUser();
                return false;
            }
            $_SESSION['last_activity'] = time();
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
 * Auto-login using remember me token
 * @param PDO $pdo
 * @return bool
 */
function autoLoginFromCookie($pdo) {
    if (!isset($_COOKIE['remember_me'])) {
        return false;
    }
    
    try {
        $token = $_COOKIE['remember_me'];
        
        // Find user with matching token
        $stmt = $pdo->prepare("
            SELECT u.id, u.username 
            FROM remember_me_tokens r
            JOIN users u ON r.user_id = u.id
            WHERE r.token = :token
            AND r.expires_at > NOW()
            LIMIT 1
        ");
        $stmt->execute([':token' => $token]);
        $user = $stmt->fetch();
        
        if ($user) {
            // Verify token
            if (password_verify($token, $token)) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['login_time'] = time();
                $_SESSION['last_activity'] = time();
                
                logAuth('INFO', "Auto-login successful via remember me: '{$user['username']}' (ID: {$user['id']}).");
                return true;
            }
        }
        
        return false;
    } catch (\Exception $e) {
        logAuth('ERROR', "Auto-login error: " . $e->getMessage());
        return false;
    }
}

/**
 * Logout the current user
 * @return void
 */
function logoutUser() {
    try {
        $username = isset($_SESSION['username']) ? sanitizeInput($_SESSION['username']) : 'unknown';
        
        // Clear remember me cookie
        if (isset($_COOKIE['remember_me'])) {
            setcookie('remember_me', '', [
                'expires' => time() - 3600,
                'path' => '/',
                'domain' => '',
                'secure' => isset($_SERVER['HTTPS']),
                'httponly' => true,
                'samesite' => 'Lax'
            ]);
        }
        
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
        // Delete remember me tokens
        $stmt = $pdo->prepare("DELETE FROM remember_me_tokens WHERE user_id = :user_id");
        $stmt->execute([':user_id' => $userId]);
        
        logAuth('INFO', "All sessions invalidated for user ID: $userId.");
        return true;
    } catch (\PDOException $e) {
        logAuth('ERROR', "Error invalidating sessions for user ID $userId: " . $e->getMessage());
        return false;
    }
}

/**
 * Change user password
 * @param PDO $pdo
 * @param int $userId
 * @param string $currentPassword
 * @param string $newPassword
 * @return array ['success' => bool, 'message' => string]
 */
function changePassword($pdo, $userId, $currentPassword, $newPassword) {
    try {
        // Get current password hash
        $stmt = $pdo->prepare("SELECT password FROM users WHERE id = :id LIMIT 1");
        $stmt->execute([':id' => $userId]);
        $user = $stmt->fetch();
        
        if (!$user || !password_verify($currentPassword, $user['password'])) {
            return [
                'success' => false,
                'message' => 'Current password is incorrect.'
            ];
        }
        
        // Validate new password
        $passwordValidation = validatePasswordStrength($newPassword);
        if (!$passwordValidation['valid']) {
            return [
                'success' => false,
                'message' => implode(' ', $passwordValidation['errors'])
            ];
        }
        
        // Update password
        $hash = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("UPDATE users SET password = :password WHERE id = :id");
        $stmt->execute([
            ':password' => $hash,
            ':id' => $userId
        ]);
        
        // Invalidate all sessions
        invalidateUserSessions($pdo, $userId);
        
        logAuth('INFO', "Password changed successfully for user ID: $userId.");
        return [
            'success' => true,
            'message' => 'Password changed successfully. Please log in again.'
        ];
        
    } catch (\PDOException $e) {
        logAuth('ERROR', "Password change error for user ID $userId: " . $e->getMessage());
        return [
            'success' => false,
            'message' => 'A database error occurred. Please try again later.'
        ];
    }
}

?>