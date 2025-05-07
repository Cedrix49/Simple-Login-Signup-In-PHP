<?php

$username = '';
$password = '';
$email = '';
$confirmPassword = '';

require_once 'conn.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get the form data
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirmPassword = trim($_POST['confirmPassword']);

    //validate the form data
    if (!empty($username) && !empty($email) && !empty($password) && !empty($confirmPassword) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Check if the email already exists in the database
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            echo "User already exists!";
            exit;
        }
        $stmt->close(); 

        if ($confirmPassword !== $password) {
            echo "Password do not match";
            exit;
        } 
        
        //Hashed password   
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);    

        //Insert new user
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $hashedPassword);
        if ($stmt->execute()) {
            echo "Registration successful!";
            header("Location: login.html");
            exit;
        } else {
            echo "Error: ".$stmt->error;
        }
        $stmt->close();
    } else {
        echo "Please fill in all fields correctly!";
    }   
}
?>