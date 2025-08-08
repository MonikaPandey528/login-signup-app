<?php
session_start();
include "config/db.php";

$message = "";

// Handle Signup
if (isset($_POST['signup'])) {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    // Check if email or username exists
    $check = $conn->prepare("SELECT * FROM users WHERE email=? OR username=?");
    $check->bind_param("ss", $email, $username);
    $check->execute();
    $result = $check->get_result();

    if ($result->num_rows > 0) {
        $message = "<p class='error'>Username or Email already exists!</p>";
    } else {
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $password);
        if ($stmt->execute()) {
            $message = "<p class='success'>Signup successful! You can login now.</p>";
        } else {
            $message = "<p class='error'>Signup failed. Try again.</p>";
        }
    }
}

// Handle Login
if (isset($_POST['login'])) {
    $username_email = trim($_POST['username_email']);
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE email=? OR username=?");
    $stmt->bind_param("ss", $username_email, $username_email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user'] = $user['username'];
        header("Location: dashboard.php");
        exit();
    } else {
        $message = "<p class='error'>Invalid credentials!</p>";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login & Signup</title>
    <link rel="stylesheet" href="css/style.css">
    <script>
        function toggleForm(type) {
            document.getElementById('signupForm').style.display = (type === 'signup') ? 'flex' : 'none';
            document.getElementById('signupTitle').style.display = (type === 'signup') ? 'block' : 'none';
            document.getElementById('loginForm').style.display = (type === 'login') ? 'flex' : 'none';
            document.getElementById('loginTitle').style.display = (type === 'login') ? 'block' : 'none';

        }
    </script>
</head>
<body>

<div class="container">
    <h2 id='signupTitle' style="display:none">Sign UP</h2>
    <h2 id='loginTitle'>Login</h2>
    <?php echo $message; ?>

    <form id="signupForm" method="POST" style="display:none;">
      
        <input type="text" name="username" placeholder="Username" required>
        <input type="email" name="email" placeholder="Email" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" name="signup">Signup</button>
        <p class="toggle-link" onclick="toggleForm('login')">Already have an account? Login</p>
     
    </form>

    <form id="loginForm" method="POST">
     
        <input type="text" name="username_email" placeholder="Username or Email" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" name="login">Login</button>
        <p class="toggle-link" onclick="toggleForm('signup')">Don't have an account? Signup</p>
    
    </form>
</div>

</body>
</html>