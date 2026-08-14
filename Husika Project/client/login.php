<?php
session_start();

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        $error = 'Please enter your email and password.';
    } else {

        $database = __DIR__ . '/database/husika.db';

        try {
            $pdo = new PDO('sqlite:' . $database);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            $stmt = $pdo->prepare("
                SELECT id, email, password_hash, role, status
                FROM users
                WHERE email = :email
                LIMIT 1
            ");

            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                $error = 'Invalid email or password.';
            } elseif ($user['status'] !== 'active') {
                $error = 'Your account is not active. Please contact Husika Events.';
            } elseif (!password_verify($password, $user['password_hash'])) {
                $error = 'Invalid email or password.';
            } else {

                // Regenerate session ID after successful login
                session_regenerate_id(true);

                $_SESSION['user_id'] = $user['id'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['logged_in'] = true;

                // Redirect according to account role
                if ($user['role'] === 'admin') {
                    header('Location: admin.php');
                    exit;
                }

                header('Location: dashboard.php');
                exit;
            }

        } catch (PDOException $e) {
            $error = 'Unable to connect to the database.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login / Join | Husika Events</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=Source+Sans+3:wght@400;500;600&display=swap" rel="stylesheet">

    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Source Sans 3', sans-serif;
            background: #f5f5f2;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .login-container {
            width: 100%;
            max-width: 430px;
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 35px rgba(0,0,0,0.08);
        }

        .logo {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo h1 {
            font-family: 'Oswald', sans-serif;
            font-size: 36px;
            letter-spacing: 2px;
        }

        .logo p {
            margin-top: 6px;
            color: #666;
        }

        h2 {
            font-family: 'Oswald', sans-serif;
            margin-bottom: 25px;
            font-size: 28px;
        }

        .form-group {
            margin-bottom: 18px;
        }

        label {
            display: block;
            margin-bottom: 7px;
            font-weight: 600;
        }

        input {
            width: 100%;
            padding: 13px;
            border: 1px solid #ccc;
            border-radius: 6px;
            font-size: 16px;
        }

        input:focus {
            outline: none;
            border-color: #222;
        }

        .error {
            background: #ffe8e8;
            color: #a00000;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 18px;
        }

        button {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 6px;
            background: #111;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }

        button:hover {
            opacity: 0.9;
        }

        .forgot {
            text-align: right;
            margin-top: 12px;
        }

        .forgot a {
            color: #333;
            text-decoration: none;
        }

        .back {
            text-align: center;
            margin-top: 25px;
        }

        .back a {
            color: #333;
            text-decoration: none;
        }
    </style>
</head>

<body>

<div class="login-container">

    <div class="logo">
        <h1>HUSIKA EVENTS</h1>
        <p>Give Hope · Give Love · Give Back</p>
    </div>

    <h2>Member Login</h2>

    <?php if ($error): ?>
        <div class="error">
            <?= htmlspecialchars($error) ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="">

        <div class="form-group">
            <label for="email">Email Address</label>

            <input
                type="email"
                id="email"
                name="email"
                placeholder="you@email.com"
                value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                required
            >
        </div>

        <div class="form-group">
            <label for="password">Password</label>

            <input
                type="password"
                id="password"
                name="password"
                placeholder="••••••••"
                required
            >
        </div>

        <button type="submit">
            Log In
        </button>

    </form>

    <div class="forgot">
        <a href="forgot-password.php">Forgot password?</a>
    </div>

    <div class="back">
        <a href="index.php">← Back to Husika Events</a>
    </div>

</div>

</body>
</html>
