<?php

require_once 'database.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php#report');
    exit;
}

$incident_type = trim($_POST['incident_type'] ?? '');
$location = trim($_POST['location'] ?? '');
$description = trim($_POST['description'] ?? '');
$reporter_name = trim($_POST['reporter_name'] ?? '');
$phone = trim($_POST['phone'] ?? '');
$consent = isset($_POST['consent']);

if ($incident_type === '' || $description === '') {
    header('Location: index.php#report?error=required');
    exit;
}

if (!$consent) {
    header('Location: index.php#report?error=consent');
    exit;
}

try {

    $stmt = $pdo->prepare("
        INSERT INTO reports
        (
            incident_type,
            location,
            description,
            reporter_name,
            phone,
            status
        )
        VALUES (?, ?, ?, ?, ?, 'Open')
    ");

    $stmt->execute([
        $incident_type,
        $location,
        $description,
        $reporter_name,
        $phone
    ]);

    header('Location: index.php#report&success=1');
    exit;

} catch (PDOException $e) {

    header('Location: index.php#report?error=database');
    exit;
}