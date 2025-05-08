<?php

$username = '';
$password = '';
$email = '';
$confirmPassword = '';
$error = [];

require_once 'conn.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get the form data
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirmPassword = trim($_POST['confirmPassword']);
    
    //validate the data
    if(empty($username)) {
        $error[] = "Username is required";
    } elseif (strlen($username) < 3) {
        $error[] = "Username must at least be 3 characters";
    }

    if(empty($email)) {
        $error[] = "Email is required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error[] = "Email is invalid format";
    }

    if(empty($password)) {
        $error[] = "Password is required";
    } elseif (strlen($password) < 8) {
        $error[] = "Password must be at least 8 characters long";
    }

    if($password !== $confirmPassword) {
        $error[] = "Passwords do not match";
    }

    //Prepare the query
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $result = $stmt->get_result();

    //fetch users
    $existingUser = $result->fetch_assoc();

    if($existingUser) {
        echo "User already exist";
        exit;
    }

    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    //Insert new users 
    $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param('sss', $username, $email, $hashedPassword);

    if($stmt->execute()) {
        header("Location: login.html?successful");
        exit;
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
}
?>