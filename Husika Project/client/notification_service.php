<?php
/**
 * Husika Events notification service.
 *
 * Email uses PHP's configured mail transport when enabled.
 * WhatsApp uses the optional WhatsApp Cloud API when credentials are configured;
 * otherwise a click-to-WhatsApp URL can be generated for manual sending.
 */

function husika_notification_tables(PDO $pdo): void
{
    $pdo->exec("CREATE TABLE IF NOT EXISTS site_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT NOT NULL UNIQUE,
        setting_value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        used_at DATETIME NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
}

function husika_setting(PDO $pdo, string $key, string $default = ''): string
{
    $stmt = $pdo->prepare('SELECT setting_value FROM site_settings WHERE setting_key = ? LIMIT 1');
    $stmt->execute([$key]);
    $value = $stmt->fetchColumn();
    return $value === false ? $default : (string)$value;
}

function husika_set_setting(PDO $pdo, string $key, string $value): void
{
    $stmt = $pdo->prepare("INSERT INTO site_settings(setting_key, setting_value, updated_at)
        VALUES(?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, updated_at=CURRENT_TIMESTAMP");
    $stmt->execute([$key, $value]);
}

function husika_normalize_phone(string $phone): string
{
    $phone = preg_replace('/[^0-9+]/', '', trim($phone));
    if (str_starts_with($phone, '0')) {
        $phone = '+254' . substr($phone, 1);
    }
    return ltrim($phone, '+');
}

function husika_whatsapp_link(string $phone, string $message): string
{
    $number = husika_normalize_phone($phone);
    return 'https://wa.me/' . $number . '?text=' . rawurlencode($message);
}

function husika_send_email(PDO $pdo, string $to, string $subject, string $message): bool
{
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return false;
    if (husika_setting($pdo, 'email_notifications_enabled', '1') !== '1') return false;

    $from = husika_setting($pdo, 'notification_from_email', 'info@husikaevents.org');
    $name = husika_setting($pdo, 'website_name', 'Husika Events');
    $headers = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $headers .= 'From: ' . $name . ' <' . $from . ">\r\n";
    $headers .= 'Reply-To: ' . $from . "\r\n";

    return @mail($to, $subject, $message, $headers);
}

function husika_send_whatsapp(PDO $pdo, string $phone, string $message): bool
{
    if ($phone === '' || husika_setting($pdo, 'whatsapp_notifications_enabled', '0') !== '1') return false;

    $token = husika_setting($pdo, 'whatsapp_cloud_token', '');
    $phoneId = husika_setting($pdo, 'whatsapp_phone_number_id', '');
    if ($token === '' || $phoneId === '' || !function_exists('curl_init')) return false;

    $url = 'https://graph.facebook.com/v23.0/' . rawurlencode($phoneId) . '/messages';
    $payload = json_encode([
        'messaging_product' => 'whatsapp',
        'to' => husika_normalize_phone($phone),
        'type' => 'text',
        'text' => ['body' => $message]
    ], JSON_UNESCAPED_UNICODE);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $token,
            'Content-Type: application/json'
        ],
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_TIMEOUT => 12
    ]);
    $response = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return $response !== false && $http >= 200 && $http < 300;
}

function husika_create_notification(PDO $pdo, ?int $userId, string $type, string $title, string $message, ?string $email = null, ?string $phone = null): void
{
    $stmt = $pdo->prepare('INSERT INTO notifications(user_id,type,title,message) VALUES(?,?,?,?,?)');
    $stmt->execute([$userId, $type, $title, $message]);

    if ($email) {
        husika_send_email($pdo, $email, $title . ' | ' . husika_setting($pdo, 'website_name', 'Husika Events'), $message);
    }
    if ($phone) {
        husika_send_whatsapp($pdo, $phone, $message);
    }
}
