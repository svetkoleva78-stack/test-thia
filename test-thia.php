<?php

/**
 * UserManager Class
 * 
 * Manages user operations with comprehensive error handling and logging.
 * All methods include try-catch blocks, input validation, and detailed logging.
 */
class UserManager {
    
    private $db;
    private $logFile;
    
    /**
     * Constructor
     * 
     * @param mysqli $db Database connection
     * @param string $logFile Path to log file (optional)
     */
    public function __construct($db, $logFile = null) {
        $this->db = $db;
        $this->logFile = $logFile ?: __DIR__ . '/user_manager.log';
        
        // Ensure session is started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
    
    /**
     * Centralized logging method
     * 
     * @param string $message Log message
     * @param string $level Log level (INFO, ERROR, WARNING, DEBUG)
     * @return bool Success status
     */
    private function logMessage($message, $level = 'INFO') {
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = "[$timestamp] [$level] $message" . PHP_EOL;
        
        try {
            return file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX) !== false;
        } catch (\Exception $e) {
            // Fallback to error_log if file logging fails
            error_log($logEntry);
            return false;
        }
    }
    
    /**
     * Validate email format
     * 
     * @param string $email Email to validate
     * @return bool True if valid
     */
    private function isValidEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    /**
     * Validate password strength
     * 
     * @param string $password Password to validate
     * @return array ['valid' => bool, 'message' => string]
     */
    private function validatePassword($password) {
        if (empty($password)) {
            return ['valid' => false, 'message' => 'Password cannot be empty'];
        }
        
        if (strlen($password) < 8) {
            return ['valid' => false, 'message' => 'Password must be at least 8 characters long'];
        }
        
        return ['valid' => true, 'message' => ''];
    }
    
    /**
     * Validate user data
     * 
     * @param string $email User email
     * @param string $password User password
     * @param string $name User name
     * @return array ['valid' => bool, 'message' => string]
     */
    private function validateUserData($email, $password, $name) {
        if (empty($email) || empty($password) || empty($name)) {
            return ['valid' => false, 'message' => 'All fields are required'];
        }
        
        if (!$this->isValidEmail($email)) {
            return ['valid' => false, 'message' => 'Invalid email format'];
        }
        
        $passwordValidation = $this->validatePassword($password);
        if (!$passwordValidation['valid']) {
            return $passwordValidation;
        }
        
        if (strlen($name) < 2 || strlen($name) > 100) {
            return ['valid' => false, 'message' => 'Name must be between 2 and 100 characters'];
        }
        
        return ['valid' => true, 'message' => ''];
    }
    
    /**
     * LOGIN — Secure login with password_verify and session regeneration
     * 
     * @param string $email User email
     * @param string $password User password
     * @return bool True if login successful
     * @throws \Exception On database error
     */
    public function loginUser($email, $password) {
        try {
            // Validate input
            if (empty($email) || empty($password)) {
                $this->logMessage('Login attempt with empty credentials', 'WARNING');
                return false;
            }
            
            if (!$this->isValidEmail($email)) {
                $this->logMessage("Invalid email format during login: $email", 'WARNING');
                return false;
            }
            
            $this->logMessage("Login attempt for email: $email", 'INFO');
            
            // Prepare statement
            $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ?");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                
                // Verify password using password_verify
                if (password_verify($password, $user['password'])) {
                    // Regenerate session ID to prevent session fixation
                    session_regenerate_id(true);
                    
                    // Set session variables
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_name'] = $user['name'] ?? '';
                    $_SESSION['login_time'] = time();
                    
                    $this->logMessage("Successful login for user ID: {$user['id']}, Email: $email", 'INFO');
                    
                    $stmt->close();
                    return true;
                } else {
                    $this->logMessage("Invalid password for email: $email", 'WARNING');
                }
            } else {
                $this->logMessage("User not found: $email", 'WARNING');
            }
            
            $stmt->close();
            return false;
            
        } catch (\Exception $e) {
            $this->logMessage("Login error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * REGISTER — Secure registration with password hashing
     * 
     * @param string $email User email
     * @param string $password User password
     * @param string $name User name
     * @return bool|int True on success, false on failure
     * @throws \Exception On database error
     */
    public function registerUser($email, $password, $name) {
        try {
            // Validate input
            $validation = $this->validateUserData($email, $password, $name);
            if (!$validation['valid']) {
                $this->logMessage("Registration validation failed: " . $validation['message'], 'WARNING');
                return false;
            }
            
            $this->logMessage("Registration attempt for email: $email", 'INFO');
            
            // Check if email already exists
            $stmt = $this->db->prepare("SELECT id FROM users WHERE email = ?");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $this->logMessage("Email already registered: $email", 'WARNING');
                $stmt->close();
                return false;
            }
            $stmt->close();
            
            // Hash password securely
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // Insert new user
            $stmt = $this->db->prepare("INSERT INTO users (email, password, name, created_at) VALUES (?, ?, ?, NOW())");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("sss", $email, $hashedPassword, $name);
            
            if ($stmt->execute()) {
                $userId = $this->db->insert_id;
                $this->logMessage("User registered successfully. ID: $userId, Email: $email", 'INFO');
                $stmt->close();
                return true;
            } else {
                throw new \Exception("Failed to execute insert: " . $stmt->error);
            }
            
        } catch (\Exception $e) {
            $this->logMessage("Registration error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Get user by ID
     * 
     * @param int $id User ID
     * @return array|null User data or null if not found
     * @throws \Exception On database error
     */
    public function getUser($id) {
        try {
            if (!is_numeric($id) || $id <= 0) {
                $this->logMessage("Invalid user ID provided: $id", 'WARNING');
                return null;
            }
            
            $this->logMessage("Fetching user by ID: $id", 'DEBUG');
            
            $stmt = $this->db->prepare("SELECT id, email, name, created_at FROM users WHERE id = ?");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $user = $result->fetch_assoc();
            
            if ($user) {
                $this->logMessage("User found: ID $id", 'DEBUG');
            } else {
                $this->logMessage("User not found: ID $id", 'WARNING');
            }
            
            $stmt->close();
            return $user;
            
        } catch (\Exception $e) {
            $this->logMessage("Get user error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Create user with validation
     * 
     * @param string $email User email
     * @param string $password User password
     * @param string $name User name
     * @return bool|int User ID on success, false on failure
     * @throws \Exception On database error
     */
    public function createUser($email, $password, $name) {
        try {
            // Validate input
            $validation = $this->validateUserData($email, $password, $name);
            if (!$validation['valid']) {
                $this->logMessage("Create user validation failed: " . $validation['message'], 'WARNING');
                return false;
            }
            
            $this->logMessage("Creating user with email: $email", 'INFO');
            
            // Check if email already exists
            $stmt = $this->db->prepare("SELECT id FROM users WHERE email = ?");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $this->logMessage("Email already exists: $email", 'WARNING');
                $stmt->close();
                return false;
            }
            $stmt->close();
            
            // Hash password securely
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // Insert new user
            $stmt = $this->db->prepare("INSERT INTO users (email, password, name, created_at) VALUES (?, ?, ?, NOW())");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("sss", $email, $hashedPassword, $name);
            
            if ($stmt->execute()) {
                $userId = $this->db->insert_id;
                $this->logMessage("User created successfully. ID: $userId, Email: $email", 'INFO');
                $stmt->close();
                return $userId;
            } else {
                throw new \Exception("Failed to execute insert: " . $stmt->error);
            }
            
        } catch (\Exception $e) {
            $this->logMessage("Create user error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Update user with validation
     * 
     * @param int $id User ID
     * @param array $data Data to update
     * @return bool True on success
     * @throws \Exception On database error
     */
    public function updateUser($id, $data) {
        try {
            if (!is_numeric($id) || $id <= 0) {
                $this->logMessage("Invalid user ID for update: $id", 'WARNING');
                return false;
            }
            
            if (empty($data) || !is_array($data)) {
                $this->logMessage("No data provided for update", 'WARNING');
                return false;
            }
            
            $this->logMessage("Updating user ID: $id with data: " . json_encode($data), 'INFO');
            
            // Check if user exists
            $existingUser = $this->getUser($id);
            if (!$existingUser) {
                $this->logMessage("User not found for update: ID $id", 'WARNING');
                return false;
            }
            
            // Allowed fields for update
            $allowedFields = ['email', 'name', 'password'];
            $updates = [];
            $types = '';
            $params = [];
            
            foreach ($data as $key => $value) {
                if (!in_array($key, $allowedFields)) {
                    $this->logMessage("Field '$key' is not allowed for update", 'WARNING');
                    continue;
                }
                
                // Validate email if being updated
                if ($key === 'email' && !$this->isValidEmail($value)) {
                    $this->logMessage("Invalid email format for update: $value", 'WARNING');
                    return false;
                }
                
                // Hash password if being updated
                if ($key === 'password') {
                    $passwordValidation = $this->validatePassword($value);
                    if (!$passwordValidation['valid']) {
                        $this->logMessage("Invalid password for update: " . $passwordValidation['message'], 'WARNING');
                        return false;
                    }
                    $value = password_hash($value, PASSWORD_DEFAULT);
                }
                
                $updates[] = "$key = ?";
                $types .= 's';
                $params[] = $value;
            }
            
            if (empty($updates)) {
                $this->logMessage("No valid fields to update for user ID: $id", 'WARNING');
                return false;
            }
            
            // Add ID to params
            $params[] = $id;
            $types .= 'i';
            
            // Execute update
            $stmt = $this->db->prepare("UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param($types, ...$params);
            
            if ($stmt->execute()) {
                if ($stmt->affected_rows > 0) {
                    $this->logMessage("User ID: $id updated successfully", 'INFO');
                } else {
                    $this->logMessage("No changes made for user ID: $id", 'DEBUG');
                }
                $stmt->close();
                return true;
            } else {
                throw new \Exception("Failed to execute update: " . $stmt->error);
            }
            
        } catch (\Exception $e) {
            $this->logMessage("Update user error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Delete user
     * 
     * @param int $id User ID
     * @return bool True on success
     * @throws \Exception On database error
     */
    public function deleteUser($id) {
        try {
            if (!is_numeric($id) || $id <= 0) {
                $this->logMessage("Invalid user ID for deletion: $id", 'WARNING');
                return false;
            }
            
            $this->logMessage("Attempting to delete user ID: $id", 'INFO');
            
            // Check if user exists
            $user = $this->getUser($id);
            if (!$user) {
                $this->logMessage("User not found for deletion: ID $id", 'WARNING');
                return false;
            }
            
            // Prevent self-deletion if user is logged in
            if (isset($_SESSION['user_id']) && $_SESSION['user_id'] == $id) {
                $this->logMessage("Attempted self-deletion blocked for user ID: $id", 'WARNING');
                return false;
            }
            
            // Delete user
            $stmt = $this->db->prepare("DELETE FROM users WHERE id = ?");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("i", $id);
            
            if ($stmt->execute()) {
                if ($stmt->affected_rows > 0) {
                    $this->logMessage("User ID: $id deleted successfully", 'INFO');
                } else {
                    $this->logMessage("User ID: $id not found or already deleted", 'WARNING');
                }
                $stmt->close();
                return true;
            } else {
                throw new \Exception("Failed to execute delete: " . $stmt->error);
            }
            
        } catch (\Exception $e) {
            $this->logMessage("Delete user error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Get all users
     * 
     * @return array Array of user data
     * @throws \Exception On database error
     */
    public function getAllUsers() {
        try {
            $this->logMessage("Fetching all users", 'DEBUG');
            
            $stmt = $this->db->prepare("SELECT id, email, name, created_at FROM users ORDER BY created_at DESC");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            $users = [];
            while ($row = $result->fetch_assoc()) {
                $users[] = $row;
            }
            
            $this->logMessage("Fetched " . count($users) . " users", 'DEBUG');
            
            $stmt->close();
            return $users;
            
        } catch (\Exception $e) {
            $this->logMessage("Get all users error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Search users by name or email
     * 
     * @param string $term Search term
     * @return array Array of matching users
     * @throws \Exception On database error
     */
    public function searchUsers($term) {
        try {
            if (empty($term)) {
                $this->logMessage("Empty search term provided", 'WARNING');
                return [];
            }
            
            // Sanitize search term
            $term = trim($term);
            if (strlen($term) < 2) {
                $this->logMessage("Search term too short: $term", 'WARNING');
                return [];
            }
            
            $this->logMessage("Searching users for term: $term", 'DEBUG');
            
            $searchTerm = "%$term%";
            $stmt = $this->db->prepare("SELECT id, email, name, created_at FROM users WHERE name LIKE ? OR email LIKE ? ORDER BY created_at DESC");
            if (!$stmt) {
                throw new \Exception("Failed to prepare statement: " . $this->db->error);
            }
            
            $stmt->bind_param("ss", $searchTerm, $searchTerm);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $users = $result->fetch_all(MYSQLI_ASSOC);
            
            $this->logMessage("Found " . count($users) . " users matching: $term", 'DEBUG');
            
            $stmt->close();
            return $users;
            
        } catch (\Exception $e) {
            $this->logMessage("Search users error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Check if user is logged in
     * 
     * @return bool True if logged in
     */
    public function isLoggedIn() {
        return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
    }
    
    /**
     * Get current user ID
     * 
     * @return int|null User ID or null if not logged in
     */
    public function getCurrentUserId() {
        return isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
    }
    
    /**
     * Logout user
     * 
     * @return bool True on success
     */
    public function logoutUser() {
        try {
            $this->logMessage("User logging out", 'INFO');
            
            // Clear session data
            $_SESSION = [];
            
            // Destroy session cookie
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
            
            // Destroy session
            session_destroy();
            
            $this->logMessage("User logged out successfully", 'INFO');
            return true;
            
        } catch (\Exception $e) {
            $this->logMessage("Logout error: " . $e->getMessage(), 'ERROR');
            throw $e;
        }
    }
    
    /**
     * Get log file path
     * 
     * @return string Log file path
     */
    public function getLogFile() {
        return $this->logFile;
    }
}
