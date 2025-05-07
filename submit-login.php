<?php

require_once 'conn.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    //Get the form data
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);

    //validate the form data
    if (!empty($email) && !empty($password) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        //Check if the email exists in the database
        $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        //Check if the user exists
        if ($stmt->num_rows > 0) {
            $stmt->bind_result($id, $hashedPassword);
            $stmt->fetch();
            //Verify the password
            if (password_verify($password, $hashedPassword)) {
                //Start the session
                session_start();
                $_SESSION['user_id'] = $id;
                $_SESSION['email'] = $email;
                echo "Login successful! Welcome back";
            } else {
                echo "Invalid password!";
            }
        } else {
            echo "No user found with that email!";
        } 

        $stmt->close();

    } else {
        echo "Please fill in all fields correctly!";
        exit;
    }
}
?>