<?php

class UserManager {
    
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    // ============================================
    // LOGIN — използва password_verify и regenerate session
    // ============================================
    public function loginUser($email, $password) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            
            if (password_verify($password, $user['password'])) {
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_email'] = $user['email'];
                $stmt->close();
                return true;
            }
        }
        
        $stmt->close();
        return false;
    }
    
    // ============================================
    // REGISTER — използва md5
    // ============================================
    public function registerUser($email, $password, $name) {
        $hashedPassword = md5($password);
        
        $query = "INSERT INTO users (email, password, name) 
                  VALUES ('$email', '$hashedPassword', '$name')";
        
        return $this->db->query($query);
    }
    
    public function getUser($id) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
    
    public function createUser($email, $password, $name) {
        $hashedPassword = md5($password);
        
        $stmt = $this->db->prepare("INSERT INTO users (email, password, name) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $email, $hashedPassword, $name);
        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }
    
    public function updateUser($id, $data) {
        $allowedFields = ['email', 'name'];
        $updates = [];
        $types = '';
        $params = [];
        
        foreach ($data as $key => $value) {
            if (in_array($key, $allowedFields)) {
                $updates[] = "$key = ?";
                $types .= 's';
                $params[] = $value;
            }
        }
        
        if (empty($updates)) {
            return false;
        }
        
        $params[] = $id;
        $types .= 'i';
        
        $stmt = $this->db->prepare("UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?");
        $stmt->bind_param($types, ...$params);
        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }
    
    public function deleteUser($id) {
        $user = $this->getUser($id);
        if ($user) {
            $stmt = $this->db->prepare("DELETE FROM users WHERE id = ?");
            $stmt->bind_param("i", $id);
            $result = $stmt->execute();
            $stmt->close();
            return $result;
        }
        return false;
    }
    
    public function getAllUsers() {
        $stmt = $this->db->prepare("SELECT * FROM users");
        $stmt->execute();
        $result = $stmt->get_result();
        $users = array();
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        $stmt->close();
        return $users;
    }
    
    public function searchUsers($term) {
        $searchTerm = "%$term%";
        $stmt = $this->db->prepare("SELECT * FROM users WHERE name LIKE ? OR email LIKE ?");
        $stmt->bind_param("ss", $searchTerm, $searchTerm);
        $stmt->execute();
        $result = $stmt->get_result();
        $users = $result->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
        return $users;
    }
}
