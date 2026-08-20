<?php

require_once __DIR__ . '/database.php';

$name = 'Admin Monroe';
$email = 'admin@husikaevents.org';
$password = 'Admin@12345';
$role = 'admin';
$status = 'active';

try {

    $check = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $check->execute([$email]);

    if ($check->fetch()) {
        echo "<h2>Admin account already exists.</h2>";
        echo "<p>Email: $email</p>";
        echo "<p><a href='login.php'>Go to Login</a></p>";
        exit;
    }

    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $pdo->prepare("
        INSERT INTO users
        (name, email, password_hash, role, status)
        VALUES (?, ?, ?, ?, ?)
    ");

    $stmt->execute([
        $name,
        $email,
        $passwordHash,
        $role,
        $status
    ]);

    echo "<h2>Admin account created successfully!</h2>";
    echo "<p>Email: <strong>$email</strong></p>";
    echo "<p>Password: <strong>$password</strong></p>";
    echo "<p><a href='login.php'>Go to Login</a></p>";

} catch (PDOException $e) {
    echo "Error: " . htmlspecialchars($e->getMessage());
}
?>