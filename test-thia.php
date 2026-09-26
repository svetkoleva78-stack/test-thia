<?php

class UserManager {
    
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
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
        
        $query = "INSERT INTO users (email, password, name) VALUES ('" . $email . "', '" . $hashedPassword . "', '" . $name . "')";
        return $this->db->query($query);
    }
    
    public function updateUser($id, $data) {
        $fields = '';
        foreach ($data as $key => $value) {
            $fields .= $key . " = '" . $value . "', ";
        }
        $fields = rtrim($fields, ', ');
        
        $query = "UPDATE users SET " . $fields . " WHERE id = " . $id;
        return $this->db->query($query);
    }
    
    public function deleteUser($id) {
        $user = $this->getUser($id);
        if ($user) {
            $query = "DELETE FROM users WHERE id = " . $id;
            return $this->db->query($query);
        }
        return false;
    }
    
    public function getAllUsers() {
        $query = "SELECT * FROM users";
        $result = $this->db->query($query);
        $users = array();
        while ($row = $result->fetch_assoc()) {
            $users[] = $row;
        }
        return $users;
    }
    
    public function searchUsers($term) {
        $query = "SELECT * FROM users WHERE name LIKE '%" . $term . "%' OR email LIKE '%" . $term . "%'";
        $result = $this->db->query($query);
        return $result->fetch_all(MYSQLI_ASSOC);
    }
}
