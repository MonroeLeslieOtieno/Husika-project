<?php
/* Husika Events - secure SQLite database bootstrap */
$dbDirectory = __DIR__ . '/database';
$dbFile = $dbDirectory . '/husika.db';
if (!is_dir($dbDirectory)) { mkdir($dbDirectory, 0750, true); }
try {
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', status TEXT NOT NULL DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, last_login DATETIME NULL,
        phone TEXT, profile_picture TEXT, must_reset_password INTEGER DEFAULT 0, two_factor_enabled INTEGER DEFAULT 0
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, group_name TEXT, season TEXT,
        schedule TEXT, location TEXT, description TEXT, status TEXT DEFAULT 'Active', created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        activity_date DATE, activity_time TIME, department TEXT, capacity INTEGER DEFAULT 0, registration_close DATETIME, allow_registration INTEGER DEFAULT 1
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, incident_type TEXT NOT NULL, location TEXT,
        description TEXT NOT NULL, reporter_name TEXT, phone TEXT, status TEXT DEFAULT 'Open', created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        report_number TEXT, priority TEXT DEFAULT 'Medium', assigned_officer TEXT, follow_up_date DATE, date_resolved DATETIME, admin_notes TEXT
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS gallery (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, filename TEXT, album TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        description TEXT, uploaded_by INTEGER, visibility TEXT DEFAULT 'public', approval_status TEXT DEFAULT 'approved'
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT, member_id INTEGER, member_name TEXT NOT NULL, activity_id INTEGER,
        activity_title TEXT, attendance_date DATE NOT NULL, status TEXT DEFAULT 'Present', notes TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    $pdo->exec("CREATE TABLE IF NOT EXISTS report_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER NOT NULL, action TEXT NOT NULL, old_status TEXT,
        new_status TEXT, notes TEXT, changed_by INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
} catch (Throwable $e) {
    error_log('Husika database error: ' . $e->getMessage());
    http_response_code(500);
    exit('The Husika Events service is temporarily unavailable.');
}
