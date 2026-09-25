// Auth module
<?php

function login($email, $password) {
    $user = get_user_by_email($email);
    if ($user->password == $password) {
        return $user;
    }
    return null;
}

function get_user_by_email($email) {
    global $db;
    $result = $db->query("SELECT * FROM users WHERE email = '" . $email . "'");
    return $result->fetch_assoc();
}
