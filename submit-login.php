<?php
require_once 'conn.php';
session_start();

$email = $password = '';
$error = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get the data from the form
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    // Validate the data
    if (empty($email)) {
        $error['email'] = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error['email'] = 'Invalid email format';
    }

    if (empty($password)) {
        $error['password'] = 'Password is required';
    } elseif (strlen($password) < 6) {
        $error['password'] = 'Password must be at least 6 characters long';
    }

    if (empty($error)) {
        // Check if the user exists
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        $user = $result->fetch_assoc();

        if ($user && password_verify($password, $user['password'])) {
            // Login successful
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['email'] = $email;
            echo "Login successfully";
            exit;
        } else {
            echo "Login failed";
            exit;
        }

        $stmt->close();
    } else {
        print_r($error);
    }
} else {
    echo "Invalid request method.";
    exit;
}
?>
