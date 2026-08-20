<?php
$secureCookie = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params([
    'lifetime' => 0, 'path' => '/', 'secure' => $secureCookie, 'httponly' => true, 'samesite' => 'Lax'
]);
session_start();

require_once 'database.php';

/*
|--------------------------------------------------------------------------
| ADMIN AUTHENTICATION
|--------------------------------------------------------------------------
*/

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    header('Location: dashboard.php');
    exit;
}

/* Invalidate sessions after a password/security reset. */
try {
    $sv=$pdo->prepare("SELECT session_version,status FROM users WHERE id=? AND role='admin'");
    $sv->execute([(int)($_SESSION['user_id']??0)]);$svr=$sv->fetch();
    if(!$svr || $svr['status']!=='active' || (int)($svr['session_version']??1)!==(int)($_SESSION['session_version']??1)) { session_unset(); session_destroy(); header('Location: login.php?logout=1'); exit; }
} catch(Throwable $e){ error_log('Session validation error: '.$e->getMessage()); }

$adminName  = $_SESSION['name'] ?? 'Admin Monroe';
$adminEmail = $_SESSION['email'] ?? 'admin@husikaevents.org';

/*
|--------------------------------------------------------------------------
| HELPER
|--------------------------------------------------------------------------
*/

function e($value)
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}


/*
|--------------------------------------------------------------------------
| SECURITY + DATABASE MIGRATION
|--------------------------------------------------------------------------
*/

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function csrf_token()
{
    return $_SESSION['csrf_token'];
}

function verify_csrf()
{
    $token = $_POST['csrf_token'] ?? '';
    if (!$token || !hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
        http_response_code(403);
        exit('Invalid security token. Please refresh the page and try again.');
    }
}

function admin_authorized()
{
    return isset($_SESSION['logged_in'], $_SESSION['role'])
        && $_SESSION['logged_in'] === true
        && $_SESSION['role'] === 'admin';
}

/* Add the case-management fields without deleting existing reports. */
try {
    $reportColumns = $pdo->query("PRAGMA table_info(reports)")->fetchAll();
    $existing = [];
    foreach ($reportColumns as $col) {
        $existing[$col['name']] = true;
    }

    $addColumns = [
        'report_number' => "TEXT",
        'priority' => "TEXT DEFAULT 'Medium'",
        'assigned_officer' => "TEXT",
        'follow_up_date' => "DATE",
        'date_resolved' => "DATETIME",
        'admin_notes' => "TEXT"
    ];

    foreach ($addColumns as $column => $definition) {
        if (!isset($existing[$column])) {
            $pdo->exec("ALTER TABLE reports ADD COLUMN {$column} {$definition}");
        }
    }

    $pdo->exec("CREATE TABLE IF NOT EXISTS report_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        old_status TEXT,
        new_status TEXT,
        notes TEXT,
        changed_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        member_id INTEGER,
        member_name TEXT NOT NULL,
        activity_id INTEGER,
        activity_title TEXT,
        attendance_date DATE NOT NULL,
        status TEXT DEFAULT 'Present',
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    /* Give older reports stable human-readable IDs. */
    $rows = $pdo->query("SELECT id FROM reports WHERE report_number IS NULL OR report_number = '' ORDER BY id ASC")->fetchAll(PDO::FETCH_COLUMN);
    foreach ($rows as $rid) {
        $number = 'HUS-' . str_pad((string)$rid, 6, '0', STR_PAD_LEFT);
        $u = $pdo->prepare("UPDATE reports SET report_number = ? WHERE id = ?");
        $u->execute([$number, $rid]);
    }
} catch (PDOException $e) {
    error_log('Husika admin migration error: ' . $e->getMessage());
}

/*
|--------------------------------------------------------------------------
| EXTENDED PLATFORM MIGRATION
|--------------------------------------------------------------------------
*/
try {
    $tableColumns = function($table) use ($pdo) {
        $cols = [];
        foreach ($pdo->query("PRAGMA table_info(" . $table . ")")->fetchAll() as $c) $cols[$c['name']] = true;
        return $cols;
    };
    foreach ([
        'users' => [
            'phone' => 'TEXT', 'profile_picture' => 'TEXT', 'must_reset_password' => 'INTEGER DEFAULT 0',
            'two_factor_enabled' => 'INTEGER DEFAULT 0', 'session_version' => 'INTEGER DEFAULT 1'
        ],
        'activities' => [
            'activity_date' => 'DATE', 'activity_time' => 'TIME', 'department' => 'TEXT',
            'capacity' => 'INTEGER DEFAULT 0', 'registration_close' => 'DATETIME', 'allow_registration' => 'INTEGER DEFAULT 1'
        ],
        'gallery' => [
            'description' => 'TEXT', 'uploaded_by' => 'INTEGER', 'visibility' => "TEXT DEFAULT 'public'",
            'approval_status' => "TEXT DEFAULT 'approved'"
        ]
    ] as $table => $defs) {
        $cols = $tableColumns($table);
        foreach ($defs as $col => $def) if (!isset($cols[$col])) $pdo->exec("ALTER TABLE {$table} ADD COLUMN {$col} {$def}");
    }
    $pdo->exec("CREATE TABLE IF NOT EXISTS site_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_by INTEGER)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, admin_name TEXT, action TEXT NOT NULL, module TEXT, record_id INTEGER, before_value TEXT, after_value TEXT, ip_address TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS login_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, email TEXT, success INTEGER DEFAULT 0, ip_address TEXT, user_agent TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, ip_address TEXT, attempts INTEGER DEFAULT 0, locked_until DATETIME, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, type TEXT, title TEXT, message TEXT, is_read INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS admin_permissions (admin_id INTEGER PRIMARY KEY, permissions TEXT NOT NULL DEFAULT '{}', updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS activity_registrations (id INTEGER PRIMARY KEY AUTOINCREMENT, activity_id INTEGER NOT NULL, member_id INTEGER NOT NULL, status TEXT DEFAULT 'Registered', registered_at DATETIME DEFAULT CURRENT_TIMESTAMP, UNIQUE(activity_id, member_id))");
    $pdo->exec("CREATE TABLE IF NOT EXISTS two_factor (user_id INTEGER PRIMARY KEY, secret TEXT NOT NULL, recovery_codes TEXT, enabled_at DATETIME, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS password_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, token_hash TEXT UNIQUE, expires_at DATETIME, used_at DATETIME, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS backup_history (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, path TEXT, size INTEGER, created_by INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
    $defaults = [
        'website_name'=>'Husika Events','whatsapp_number'=>'+254 721 110 572','email'=>'info@husikaevents.org','location'=>'Nairobi, Kenya','social_media'=>'@HusikaEvents','emergency_contact'=>'+254 721 110 572',
        'registration_enabled'=>'1','reporting_enabled'=>'1','gallery_enabled'=>'1','gallery_approval_required'=>'1','login_rate_limit'=>'5','login_lock_minutes'=>'15','maintenance_mode'=>'0',
        'smtp_host'=>'','smtp_port'=>'587','smtp_username'=>'','smtp_password'=>'','smtp_encryption'=>'tls','smtp_from_email'=>'','smtp_from_name'=>'Husika Events'
    ];
    $ins=$pdo->prepare("INSERT OR IGNORE INTO site_settings(setting_key,setting_value) VALUES(?,?)");
    foreach($defaults as $k=>$v) $ins->execute([$k,$v]);
} catch (PDOException $e) { error_log('Husika extended migration error: '.$e->getMessage()); }

function audit_log($action, $module='', $recordId=null, $before=null, $after=null) {
    global $pdo;
    try {
        $stmt=$pdo->prepare("INSERT INTO audit_log(admin_id,admin_name,action,module,record_id,before_value,after_value,ip_address) VALUES(?,?,?,?,?,?,?,?)");
        $stmt->execute([(int)($_SESSION['user_id']??0), $_SESSION['name']??'Admin', $action, $module, $recordId, $before===null?null:json_encode($before), $after===null?null:json_encode($after), $_SERVER['REMOTE_ADDR']??'unknown']);
    } catch(Throwable $e){ error_log('Audit log error: '.$e->getMessage()); }
}
function setting($key,$default='') { global $pdo; try{$s=$pdo->prepare("SELECT setting_value FROM site_settings WHERE setting_key=?");$s->execute([$key]);$v=$s->fetchColumn();return $v===false?$default:$v;}catch(Throwable $e){return $default;} }
function save_setting($key,$value) { global $pdo; $s=$pdo->prepare("INSERT INTO site_settings(setting_key,setting_value,updated_at,updated_by) VALUES(?,?,CURRENT_TIMESTAMP,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by");$s->execute([$key,(string)$value,(int)($_SESSION['user_id']??0)]); }
function password_strong($p) { return strlen($p)>=10 && preg_match('/[A-Z]/',$p) && preg_match('/[a-z]/',$p) && preg_match('/\d/',$p) && preg_match('/[^A-Za-z0-9]/',$p); }
function base32_encode_simple($data){$alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$bits='';foreach(str_split($data) as $c)$bits.=str_pad(decbin(ord($c)),8,'0',STR_PAD_LEFT);$out='';for($i=0;$i<strlen($bits);$i+=5){$chunk=substr($bits,$i,5);$chunk=str_pad($chunk,5,'0');$out.=$alphabet[bindec($chunk)];}return $out;}
function base32_decode_simple($s){$alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$bits='';foreach(str_split(strtoupper($s)) as $c){$p=strpos($alphabet,$c);if($p===false)continue;$bits.=str_pad(decbin($p),5,'0',STR_PAD_LEFT);} $out='';for($i=0;$i+8<=strlen($bits);$i+=8)$out.=chr(bindec(substr($bits,$i,8)));return $out;}
function totp_code($secret,$time=null){$time=$time??time();$key=base32_decode_simple($secret);$counter=pack('N*',0).pack('N*',intdiv($time,30));$hash=hash_hmac('sha1',$counter,$key,true);$offset=ord($hash[19])&15;$bin=((ord($hash[$offset])&127)<<24)|((ord($hash[$offset+1])&255)<<16)|((ord($hash[$offset+2])&255)<<8)|(ord($hash[$offset+3])&255);return str_pad((string)($bin%1000000),6,'0',STR_PAD_LEFT);}

/*
|--------------------------------------------------------------------------
| EXPORTS
|--------------------------------------------------------------------------
*/

$export = $_GET['export'] ?? '';
$allowedExports = ['reports_csv', 'reports_pdf', 'members_csv', 'activities_csv', 'attendance_csv', 'gallery_csv'];

if (in_array($export, $allowedExports, true)) {
    if (!admin_authorized()) {
        http_response_code(403);
        exit('Unauthorized');
    }

    $filename = 'husika_' . $export . '_' . date('Y-m-d') . '.' . ($export === 'reports_pdf' ? 'pdf' : 'csv');

    if ($export === 'reports_pdf') {
        $rows = $pdo->query("SELECT * FROM reports ORDER BY id DESC")->fetchAll();

        /* Small dependency-free PDF writer. For larger deployments, a maintained PDF package such as Dompdf is preferable. */
        $lines = ['HUSIKA EVENTS - INCIDENT REPORTS', 'Generated: ' . date('Y-m-d H:i:s'), ''];
        foreach ($rows as $r) {
            $lines[] = ($r['report_number'] ?? ('HUS-' . str_pad((string)$r['id'], 6, '0', STR_PAD_LEFT))) . ' | ' . ($r['incident_type'] ?? '') . ' | Priority: ' . ($r['priority'] ?? 'Medium') . ' | Status: ' . ($r['status'] ?? '');
            $lines[] = 'Location: ' . ($r['location'] ?? '') . ' | Assigned: ' . ($r['assigned_officer'] ?? 'Unassigned');
            $lines[] = 'Created: ' . ($r['created_at'] ?? '') . ' | Follow-up: ' . ($r['follow_up_date'] ?? '') . ' | Resolved: ' . ($r['date_resolved'] ?? '');
            $lines[] = 'Description: ' . preg_replace('/\s+/', ' ', (string)($r['description'] ?? ''));
            $lines[] = 'Admin notes: ' . preg_replace('/\s+/', ' ', (string)($r['admin_notes'] ?? ''));
            $lines[] = str_repeat('-', 100);
        }

        $escapePdf = function($text) {
            $text = iconv('UTF-8', 'windows-1252//TRANSLIT//IGNORE', (string)$text);
            return str_replace(['\\', '(', ')'], ['\\\\', '\\(', '\\)'], $text);
        };

        $pages = array_chunk($lines, 48);
        $objects = [];
        $objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
        $pageObjectIds = [];
        $contentObjectIds = [];
        $next = 4;
        foreach ($pages ?: [['No incident reports found.']] as $pi => $pageLines) {
            $pageObjectIds[] = $next++;
            $contentObjectIds[] = $next++;
        }
        $kids = implode(' ', array_map(fn($id) => $id . ' 0 R', $pageObjectIds));
        $objects[2] = '<< /Type /Pages /Kids [' . $kids . '] /Count ' . count($pageObjectIds) . ' >>';
        $objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
        foreach ($pages ?: [['No incident reports found.']] as $i => $pageLines) {
            $pageId = $pageObjectIds[$i];
            $contentId = $contentObjectIds[$i];
            $stream = "BT\n/F1 9 Tf\n40 760 Td\n12 TL\n";
            foreach ($pageLines as $line) {
                $stream .= '(' . $escapePdf(substr((string)$line, 0, 130)) . ") Tj\nT*\n";
            }
            $stream .= "ET";
            $objects[$pageId] = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ' . $contentId . ' 0 R >>';
            $objects[$contentId] = '<< /Length ' . strlen($stream) . " >>\nstream\n" . $stream . "\nendstream";
        }
        ksort($objects);
        $pdf = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
        $offsets = [0];
        $max = max(array_keys($objects));
        for ($i = 1; $i <= $max; $i++) {
            $offsets[$i] = strlen($pdf);
            $pdf .= $i . " 0 obj\n" . ($objects[$i] ?? '<<>>') . "\nendobj\n";
        }
        $xref = strlen($pdf);
        $pdf .= "xref\n0 " . ($max + 1) . "\n0000000000 65535 f \n";
        for ($i = 1; $i <= $max; $i++) $pdf .= sprintf('%010d 00000 n \n', $offsets[$i]);
        $pdf .= "trailer\n<< /Size " . ($max + 1) . " /Root 1 0 R >>\nstartxref\n" . $xref . "\n%%EOF";

        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        echo $pdf;
        exit;
    }

    $queries = [
        'reports_csv' => "SELECT id, report_number, incident_type, location, description, reporter_name, phone, priority, assigned_officer, status, admin_notes, follow_up_date, date_resolved, created_at FROM reports ORDER BY id DESC",
        'members_csv' => "SELECT id, name, email, role, status, created_at, last_login FROM users WHERE role = 'member' ORDER BY id DESC",
        'activities_csv' => "SELECT id, title, group_name, season, schedule, location, description, status, created_at FROM activities ORDER BY id DESC",
        'attendance_csv' => "SELECT id, member_id, member_name, activity_id, activity_title, attendance_date, status, notes, created_at FROM attendance ORDER BY attendance_date DESC, id DESC",
        'gallery_csv' => "SELECT id, title, filename, album, created_at FROM gallery ORDER BY id DESC"
    ];

    $stmt = $pdo->query($queries[$export]);
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output', 'w');
    $first = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($first) {
        fputcsv($out, array_keys($first));
        fputcsv($out, array_values($first));
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) fputcsv($out, array_values($row));
    }
    fclose($out);
    exit;
}

/*
|--------------------------------------------------------------------------
| HANDLE LOGOUT
|--------------------------------------------------------------------------
*/

if (isset($_GET['logout'])) {

    session_unset();
    session_destroy();

    header('Location: login.php');
    exit;
}

/*
|--------------------------------------------------------------------------
| HANDLE DELETE ACTIONS
|--------------------------------------------------------------------------
*/

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    verify_csrf();

    $action = $_POST['action'] ?? '';

    /*
    |--------------------------------------------------------------------------
    | ADMIN / SECURITY ACTIONS
    |--------------------------------------------------------------------------
    */
    if ($action === 'update_other_admin') {
        $id=(int)($_POST['id']??0);$name=trim($_POST['name']??'');$email=trim($_POST['email']??'');$password=$_POST['password']??'';
        if($id>0&&$id!=(int)$_SESSION['user_id']&&$name!==''&&filter_var($email,FILTER_VALIDATE_EMAIL)){
            $bq=$pdo->prepare("SELECT name,email FROM users WHERE id=? AND role='admin'");$bq->execute([$id]);$before=$bq->fetch();$check=$pdo->prepare("SELECT id FROM users WHERE email=? AND id!=?");$check->execute([$email,$id]);
            if(!$check->fetch()){$sql=$password!==''?"UPDATE users SET name=?,email=?,password_hash=? WHERE id=? AND role='admin'":"UPDATE users SET name=?,email=? WHERE id=? AND role='admin'";$q=$pdo->prepare($sql);$password!==''?$q->execute([$name,$email,password_hash($password,PASSWORD_DEFAULT),$id]):$q->execute([$name,$email,$id]);audit_log('Edited administrator profile','administrators',$id,$before,['name'=>$name,'email'=>$email]);}
        }
        header('Location: admin.php?panel=settings&success=Administrator profile updated');exit;
    }
    if ($action === 'toggle_admin') {
        $id=(int)($_POST['id']??0); if($id>0 && $id!=(int)$_SESSION['user_id']){
            $old=$pdo->prepare("SELECT status FROM users WHERE id=? AND role='admin'");$old->execute([$id]);$before=$old->fetchColumn();
            $new=$before==='active'?'suspended':'active';$q=$pdo->prepare("UPDATE users SET status=? WHERE id=? AND role='admin'");$q->execute([$new,$id]);audit_log("Changed administrator status to {$new}",'administrators',$id,['status'=>$before],['status'=>$new]);
        }
        header('Location: admin.php?panel=settings&success=Administrator status updated');exit;
    }
    if ($action === 'delete_admin') {
        $id=(int)($_POST['id']??0); if($id>0 && $id!=(int)$_SESSION['user_id']){$q=$pdo->prepare("DELETE FROM users WHERE id=? AND role='admin'");$q->execute([$id]);audit_log('Deleted administrator','administrators',$id);}
        header('Location: admin.php?panel=settings&success=Administrator deleted');exit;
    }
    if ($action === 'change_user_role') {
        $id=(int)($_POST['id']??0);$role=$_POST['role']??'member';if(in_array($role,['member','admin','social_worker','content_manager','moderator','staff'],true)&&$id>0){$before=$pdo->prepare("SELECT role FROM users WHERE id=?");$before->execute([$id]);$b=$before->fetchColumn();$q=$pdo->prepare("UPDATE users SET role=? WHERE id=?");$q->execute([$role,$id]);audit_log('Changed user role','members',$id,['role'=>$b],['role'=>$role]);}
        header('Location: admin.php?panel=members&success=Member role updated');exit;
    }
    if ($action === 'force_password_reset') {
        $id=(int)($_POST['id']??0);if($id>0){$q=$pdo->prepare("UPDATE users SET must_reset_password=1 WHERE id=?");$q->execute([$id]);audit_log('Forced password reset','members',$id);}
        header('Location: admin.php?panel=members&success=Password reset required at next login');exit;
    }
    if ($action === 'save_site_settings') {
        $keys=['website_name','whatsapp_number','email','location','social_media','emergency_contact','registration_enabled','reporting_enabled','gallery_enabled','gallery_approval_required','maintenance_mode','smtp_host','smtp_port','smtp_username','smtp_password','smtp_encryption','smtp_from_email','smtp_from_name','login_rate_limit','login_lock_minutes'];
        foreach($keys as $k) save_setting($k, $_POST[$k] ?? '0'); audit_log('Updated website/system settings','settings');header('Location: admin.php?panel=settings&success=Settings saved successfully');exit;
    }
    if ($action === 'save_permissions') {
        $id=(int)($_POST['admin_id']??0);$perms=$_POST['permissions']??[];if($id>0){$q=$pdo->prepare("INSERT INTO admin_permissions(admin_id,permissions,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(admin_id) DO UPDATE SET permissions=excluded.permissions,updated_at=CURRENT_TIMESTAMP");$q->execute([$id,json_encode(array_values($perms))]);audit_log('Updated administrator permissions','administrators',$id,null,$perms);}header('Location: admin.php?panel=settings&success=Permissions updated');exit;
    }
    if ($action === 'add_attendance') {
        $mid=(int)($_POST['member_id']??0);$aid=(int)($_POST['activity_id']??0);$date=$_POST['attendance_date']??date('Y-m-d');$status=$_POST['attendance_status']??'Present';$notes=trim($_POST['attendance_notes']??'');
        $m=$pdo->prepare("SELECT name FROM users WHERE id=?");$m->execute([$mid]);$mn=$m->fetchColumn();$a=$pdo->prepare("SELECT title FROM activities WHERE id=?");$a->execute([$aid]);$at=$a->fetchColumn();
        if($mn && $at){$q=$pdo->prepare("INSERT INTO attendance(member_id,member_name,activity_id,activity_title,attendance_date,status,notes) VALUES(?,?,?,?,?,?,?)");$q->execute([$mid,$mn,$aid,$at,$date,$status,$notes]);audit_log('Recorded attendance','attendance',$pdo->lastInsertId());}
        header('Location: admin.php?panel=attendance&success=Attendance recorded');exit;
    }
    if ($action === 'register_activity') {
        $aid=(int)($_POST['activity_id']??0);$mid=(int)($_POST['member_id']??0);if($aid>0&&$mid>0){try{$q=$pdo->prepare("INSERT INTO activity_registrations(activity_id,member_id) VALUES(?,?)");$q->execute([$aid,$mid]);audit_log('Registered member for activity','activities',$aid,null,['member_id'=>$mid]);}catch(Throwable $e){}}
        header('Location: admin.php?panel=activities&success=Registration processed');exit;
    }
    if ($action === 'create_backup') {
        $dbPath=__DIR__.'/database/husika.db';$dir=__DIR__.'/backups';if(!is_dir($dir))mkdir($dir,0750,true);$file=$dir.'/husika_backup_'.date('Y-m-d_H-i-s').'.db';if(file_exists($dbPath)&&copy($dbPath,$file)){ $q=$pdo->prepare("INSERT INTO backup_history(filename,path,size,created_by) VALUES(?,?,?,?)");$q->execute([basename($file),$file,filesize($file),(int)$_SESSION['user_id']]);audit_log('Created database backup','backup',$pdo->lastInsertId());header('Location: admin.php?panel=settings&success=Database backup created');}else header('Location: admin.php?panel=settings&success=Backup failed');exit;
    }
    if ($action === 'delete_backup') {
        $id=(int)($_POST['id']??0);$q=$pdo->prepare("SELECT path FROM backup_history WHERE id=?");$q->execute([$id]);$path=$q->fetchColumn();if($path&&is_file($path))@unlink($path);$pdo->prepare("DELETE FROM backup_history WHERE id=?")->execute([$id]);audit_log('Deleted database backup','backup',$id);header('Location: admin.php?panel=settings&success=Backup deleted');exit;
    }
    if ($action === 'enable_2fa') {
        $id=(int)$_SESSION['user_id'];$bytes=random_bytes(10);$secret=base32_encode_simple($bytes);$codes=[];for($i=0;$i<8;$i++)$codes[]=strtoupper(bin2hex(random_bytes(4)));$q=$pdo->prepare("INSERT INTO two_factor(user_id,secret,recovery_codes) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret,recovery_codes=excluded.recovery_codes");$q->execute([$id,$secret,json_encode($codes)]);$_SESSION['pending_2fa_secret']=$secret;header('Location: admin.php?panel=settings&success=2FA secret generated. Scan the QR and verify the code.');exit;
    }
    if ($action === 'verify_2fa') {
        $code=trim($_POST['code']??'');$secret=$_SESSION['pending_2fa_secret']??'';if($secret&&hash_equals(totp_code($secret),$code)){ $q=$pdo->prepare("UPDATE two_factor SET enabled_at=CURRENT_TIMESTAMP WHERE user_id=?");$q->execute([(int)$_SESSION['user_id']]);$pdo->prepare("UPDATE users SET two_factor_enabled=1 WHERE id=?")->execute([(int)$_SESSION['user_id']]);unset($_SESSION['pending_2fa_secret']);audit_log('Enabled two-factor authentication','security',(int)$_SESSION['user_id']);header('Location: admin.php?panel=settings&success=Two-factor authentication enabled');}else header('Location: admin.php?panel=settings&success=Invalid verification code');exit;
    }
    if ($action === 'disable_2fa') {
        $id=(int)$_SESSION['user_id'];$pdo->prepare("DELETE FROM two_factor WHERE user_id=?")->execute([$id]);$pdo->prepare("UPDATE users SET two_factor_enabled=0 WHERE id=?")->execute([$id]);audit_log('Disabled two-factor authentication','security',$id);header('Location: admin.php?panel=settings&success=Two-factor authentication disabled');exit;
    }
    if ($action === 'logout_all_sessions') {
        $id=(int)$_SESSION['user_id'];$pdo->prepare('UPDATE users SET session_version=COALESCE(session_version,1)+1 WHERE id=?')->execute([$id]);$_SESSION['session_version']=null;audit_log('Logged out all other sessions','security',$id);header('Location: admin.php?panel=settings&success=All other sessions have been invalidated');exit;
    }
    if ($action === 'mark_notification_read') { $id=(int)($_POST['id']??0);$pdo->prepare("UPDATE notifications SET is_read=1 WHERE id=?")->execute([$id]);header('Location: admin.php?panel=dashboard');exit; }

    /*
    |--------------------------------------------------------------------------
    | DELETE ACTIVITY
    |--------------------------------------------------------------------------
    */

    if ($action === 'delete_activity') {

        $id = (int)($_POST['id'] ?? 0);

        if ($id > 0) {

            $stmt = $pdo->prepare("DELETE FROM activities WHERE id = ?");
            $stmt->execute([$id]);

        }

        header('Location: admin.php?panel=activities&success=Activity deleted successfully');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | DELETE MEMBER
    |--------------------------------------------------------------------------
    */

    if ($action === 'delete_member') {

        $id = (int)($_POST['id'] ?? 0);

        if ($id > 0) {

            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ? AND role != 'admin'");
            $stmt->execute([$id]);

        }

        header('Location: admin.php?panel=members&success=Member deleted successfully');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | DELETE GALLERY IMAGE
    |--------------------------------------------------------------------------
    */

    if ($action === 'delete_gallery') {

        $id = (int)($_POST['id'] ?? 0);

        if ($id > 0) {

            $stmt = $pdo->prepare("SELECT filename FROM gallery WHERE id = ?");
            $stmt->execute([$id]);

            $image = $stmt->fetch();

            if ($image) {

                $filePath = __DIR__ . '/uploads/gallery/' . $image['filename'];

                if (
                    !empty($image['filename']) &&
                    file_exists($filePath)
                ) {
                    @unlink($filePath);
                }

                $delete = $pdo->prepare("DELETE FROM gallery WHERE id = ?");
                $delete->execute([$id]);
            }
        }

        header('Location: admin.php?panel=gallery&success=Image deleted successfully');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | ADD ACTIVITY
    |--------------------------------------------------------------------------
    */

    if ($action === 'add_activity') {

        $title = trim($_POST['title'] ?? '');
        $group = trim($_POST['group_name'] ?? '');
        $season = trim($_POST['season'] ?? '');
        $schedule = trim($_POST['schedule'] ?? '');
        $location = trim($_POST['location'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $status = trim($_POST['status'] ?? 'Active');

        if ($title !== '') {

            $stmt = $pdo->prepare("
                INSERT INTO activities
                (
                    title,
                    group_name,
                    season,
                    schedule,
                    location,
                    description,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");

            $stmt->execute([
                $title,
                $group,
                $season,
                $schedule,
                $location,
                $description,
                $status
            ]);
        }

        header('Location: admin.php?panel=activities&success=Activity added successfully');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | ADD MEMBER
    |--------------------------------------------------------------------------
    */

    if ($action === 'add_member') {

        $firstName = trim($_POST['first_name'] ?? '');
        $lastName = trim($_POST['last_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $phone = trim($_POST['phone'] ?? '');
        $group = trim($_POST['group_name'] ?? '');
        $status = trim($_POST['status'] ?? 'active');

        $name = trim($firstName . ' ' . $lastName);

        if ($name !== '') {

            /*
             * The current users table does not contain a phone/group column.
             * Therefore the member is stored in users using the available fields.
             *
             * A temporary generated password is used because password_hash
             * is required by the existing database structure.
             */

            $temporaryPassword = password_hash(
                bin2hex(random_bytes(8)),
                PASSWORD_DEFAULT
            );

            /*
             * Avoid duplicate email errors.
             */

            if ($email !== '') {

                $check = $pdo->prepare(
                    "SELECT id FROM users WHERE email = ? LIMIT 1"
                );

                $check->execute([$email]);

                if (!$check->fetch()) {

                    $stmt = $pdo->prepare("
                        INSERT INTO users
                        (
                            name,
                            email,
                            password_hash,
                            role,
                            status
                        )
                        VALUES (?, ?, ?, 'member', ?)
                    ");

                    $stmt->execute([
                        $name,
                        $email,
                        $temporaryPassword,
                        strtolower($status)
                    ]);
                }

            } else {

                /*
                 * Generate a unique email when none is supplied.
                 */

                $generatedEmail =
                    'member_' .
                    time() .
                    '_' .
                    random_int(100, 999) .
                    '@husikaevents.local';

                $stmt = $pdo->prepare("
                    INSERT INTO users
                    (
                        name,
                        email,
                        password_hash,
                        role,
                        status
                    )
                    VALUES (?, ?, ?, 'member', ?)
                ");

                $stmt->execute([
                    $name,
                    $generatedEmail,
                    $temporaryPassword,
                    strtolower($status)
                ]);
            }
        }

        header('Location: admin.php?panel=members&success=Member added successfully');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | UPDATE REPORT STATUS
    |--------------------------------------------------------------------------
    */

    if ($action === 'update_report_status') {

        $id = (int)($_POST['id'] ?? 0);
        $status = trim($_POST['status'] ?? '');
        $priority = trim($_POST['priority'] ?? '');
        $assigned = trim($_POST['assigned_officer'] ?? '');
        $notes = trim($_POST['admin_notes'] ?? '');
        $followUp = trim($_POST['follow_up_date'] ?? '');
        $dateResolved = trim($_POST['date_resolved'] ?? '');
        $historyNote = trim($_POST['history_note'] ?? '');

        $allowedStatuses = ['Open', 'Under Review', 'Investigating', 'Referred', 'Resolved', 'Closed'];
        $allowedPriorities = ['Low', 'Medium', 'High', 'Critical'];

        if ($id > 0 && in_array($status, $allowedStatuses, true) && in_array($priority, $allowedPriorities, true)) {
            $oldStmt = $pdo->prepare("SELECT status FROM reports WHERE id = ?");
            $oldStmt->execute([$id]);
            $oldStatus = $oldStmt->fetchColumn();

            if ($dateResolved === '' && $status === 'Resolved') $dateResolved = date('Y-m-d H:i:s');

            $stmt = $pdo->prepare("UPDATE reports SET status = ?, priority = ?, assigned_officer = ?, admin_notes = ?, follow_up_date = ?, date_resolved = ? WHERE id = ?");
            $stmt->execute([$status, $priority, $assigned, $notes, $followUp ?: null, $dateResolved ?: null, $id]);

            if ($oldStatus !== $status || $historyNote !== '') {
                $history = $pdo->prepare("INSERT INTO report_history (report_id, action, old_status, new_status, notes, changed_by) VALUES (?, ?, ?, ?, ?, ?)");
                $history->execute([$id, 'Case updated', $oldStatus, $status, $historyNote ?: 'Case details updated', (int)$_SESSION['user_id']]);
            }
        }

        header('Location: admin.php?panel=reports&success=Report updated successfully');
        exit;
    }

    if ($action === 'add_report_history') {
        $id = (int)($_POST['report_id'] ?? 0);
        $note = trim($_POST['history_note'] ?? '');
        if ($id > 0 && $note !== '') {
            $stmt = $pdo->prepare("INSERT INTO report_history (report_id, action, notes, changed_by) VALUES (?, 'Internal case note', ?, ?)");
            $stmt->execute([$id, $note, (int)$_SESSION['user_id']]);
        }
        header('Location: admin.php?panel=reports&success=Case history updated');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | UPDATE ADMIN PROFILE
    |--------------------------------------------------------------------------
    */
    if ($action === 'update_admin_profile') {

        $adminId = (int)($_SESSION['user_id'] ?? 0);
        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if ($adminId <= 0 || $name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            header('Location: admin.php?panel=settings&success=Please enter a valid name and email address');
            exit;
        }

        $check = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1");
        $check->execute([$email, $adminId]);

        if ($check->fetch()) {
            header('Location: admin.php?panel=settings&success=That email address is already in use');
            exit;
        }

        if ($newPassword !== '' && $newPassword !== $confirmPassword) {
            header('Location: admin.php?panel=settings&success=Passwords do not match');
            exit;
        }

        if ($newPassword !== '') {
            $stmt = $pdo->prepare("UPDATE users SET name = ?, email = ?, password_hash = ? WHERE id = ? AND role = 'admin'");
            $stmt->execute([$name, $email, password_hash($newPassword, PASSWORD_DEFAULT), $adminId]);
            $pdo->prepare('UPDATE users SET session_version=COALESCE(session_version,1)+1 WHERE id=?')->execute([$adminId]);
        } else {
            $stmt = $pdo->prepare("UPDATE users SET name = ?, email = ? WHERE id = ? AND role = 'admin'");
            $stmt->execute([$name, $email, $adminId]);
        }

        $_SESSION['name'] = $name;
        $_SESSION['email'] = $email;
        $svNow=$pdo->prepare('SELECT session_version FROM users WHERE id=?');$svNow->execute([$adminId]);$_SESSION['session_version']=(int)$svNow->fetchColumn();

        header('Location: admin.php?panel=settings&success=Profile updated successfully');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | ADD ADMINISTRATOR
    |--------------------------------------------------------------------------
    */
    if ($action === 'add_admin') {

        $name = trim($_POST['name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $status = strtolower(trim($_POST['status'] ?? 'active'));

        if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
            header('Location: admin.php?panel=settings&success=Enter a valid name, email, and password of at least 8 characters');
            exit;
        }

        if (!in_array($status, ['active', 'pending', 'suspended'], true)) {
            $status = 'active';
        }

        $check = $pdo->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
        $check->execute([$email]);

        if ($check->fetch()) {
            header('Location: admin.php?panel=settings&success=An account with that email already exists');
            exit;
        }

        $stmt = $pdo->prepare("INSERT INTO users (name, email, password_hash, role, status) VALUES (?, ?, ?, 'admin', ?)");
        $stmt->execute([$name, $email, password_hash($password, PASSWORD_DEFAULT), $status]);

        header('Location: admin.php?panel=settings&success=Administrator added successfully');
        exit;
    }

    /*
    |--------------------------------------------------------------------------
    | GALLERY UPLOAD
    |--------------------------------------------------------------------------
    */

    if ($action === 'upload_gallery') {

        $uploadDirectory = __DIR__ . '/uploads/gallery';

        if (!is_dir($uploadDirectory)) {
            mkdir($uploadDirectory, 0777, true);
        }

        if (
            isset($_FILES['gallery_images']) &&
            !empty($_FILES['gallery_images']['name'])
        ) {

            $files = $_FILES['gallery_images'];

            $allowedTypes = [
                'image/jpeg',
                'image/png',
                'image/webp',
                'image/gif'
            ];

            for ($i = 0; $i < count($files['name']); $i++) {

                if ($files['error'][$i] !== UPLOAD_ERR_OK) {
                    continue;
                }

                if ($files['size'][$i] > 10 * 1024 * 1024) {
                    continue;
                }

                $tmpName = $files['tmp_name'][$i];

                $mimeType = mime_content_type($tmpName);

                if (!in_array($mimeType, $allowedTypes, true)) {
                    continue;
                }

                $extensionMap = [
                    'image/jpeg' => 'jpg',
                    'image/png' => 'png',
                    'image/webp' => 'webp',
                    'image/gif' => 'gif'
                ];

                /* Never trust the uploaded filename extension. */
                $extension = $extensionMap[$mimeType] ?? '';
                if ($extension === '') {
                    continue;
                }

                $newFilename =
                    bin2hex(random_bytes(16)) .
                    '.' .
                    $extension;

                $destination =
                    $uploadDirectory .
                    '/' .
                    $newFilename;

                if (move_uploaded_file($tmpName, $destination)) {

                    $originalName =
                        pathinfo(
                            $files['name'][$i],
                            PATHINFO_FILENAME
                        );

                    $stmt = $pdo->prepare("
                        INSERT INTO gallery
                        (
                            title,
                            filename,
                            album
                        )
                        VALUES (?, ?, ?)
                    ");

                    $stmt->execute([
                        $originalName,
                        $newFilename,
                        'General'
                    ]);
                }
            }
        }

        header('Location: admin.php?panel=gallery&success=Images uploaded successfully');
        exit;
    }
}

/*
|--------------------------------------------------------------------------
| DASHBOARD CHART DATA
|--------------------------------------------------------------------------
*/
$totalAdmins = 0;
$totalReports = 0;
$resolvedReports = 0;
$membersThisMonth = 0;
$reportTypeLabels = []; $reportTypeValues = [];
$reportMonthLabels = []; $reportMonthValues = [];
$memberMonthLabels = []; $memberMonthValues = [];
$activityLabels = []; $activityParticipationValues = [];
try {
    $totalAdmins = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='admin'")->fetchColumn();
    $totalReports = (int)$pdo->query("SELECT COUNT(*) FROM reports")->fetchColumn();
    $resolvedReports = (int)$pdo->query("SELECT COUNT(*) FROM reports WHERE status='Resolved'")->fetchColumn();
    $membersThisMonth = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='member' AND created_at >= date('now','start of month')")->fetchColumn();
    foreach ($pdo->query("SELECT incident_type, COUNT(*) total FROM reports GROUP BY incident_type ORDER BY total DESC") as $r) { $reportTypeLabels[]=$r['incident_type']; $reportTypeValues[]=(int)$r['total']; }
    foreach ($pdo->query("SELECT strftime('%Y-%m',created_at) ym, COUNT(*) total FROM reports GROUP BY ym ORDER BY ym ASC LIMIT 12") as $r) { $reportMonthLabels[]=date('M Y',strtotime($r['ym'].'-01')); $reportMonthValues[]=(int)$r['total']; }
    foreach ($pdo->query("SELECT strftime('%Y-%m',created_at) ym, COUNT(*) total FROM users WHERE role='member' GROUP BY ym ORDER BY ym ASC LIMIT 12") as $r) { $memberMonthLabels[]=date('M Y',strtotime($r['ym'].'-01')); $memberMonthValues[]=(int)$r['total']; }
    foreach ($pdo->query("SELECT activity_title, COUNT(*) total FROM attendance GROUP BY activity_title ORDER BY total DESC LIMIT 8") as $r) { $activityLabels[]=$r['activity_title'] ?: 'Unnamed Activity'; $activityParticipationValues[]=(int)$r['total']; }
} catch (PDOException $e) { error_log('Husika chart data error: '.$e->getMessage()); }

/* Extra dynamic dashboard data */
$attendanceLabels=[];$attendanceValues=[];$resolutionLabels=['Resolved','Other'];$resolutionValues=[0,0];
try{
 foreach($pdo->query("SELECT activity_title, COUNT(*) total FROM attendance GROUP BY activity_title ORDER BY total DESC LIMIT 8") as $r){$attendanceLabels[]=$r['activity_title']?:'Unnamed';$attendanceValues[]=(int)$r['total'];}
 $resolutionValues[0]=(int)$pdo->query("SELECT COUNT(*) FROM reports WHERE status IN ('Resolved','Closed')")->fetchColumn();
 $resolutionValues[1]=max(0,$totalReports-$resolutionValues[0]);
}catch(Throwable $e){error_log('Chart extension error: '.$e->getMessage());}

/*
|--------------------------------------------------------------------------
| DATABASE STATISTICS
|--------------------------------------------------------------------------
*/

$totalMembers = 0;
$activeMembers = 0;
$totalActivities = 0;
$activeActivities = 0;
$openReports = 0;
$totalGallery = 0;

try {

    $totalMembers = (int)$pdo
        ->query("
            SELECT COUNT(*)
            FROM users
            WHERE role = 'member'
        ")
        ->fetchColumn();

    $activeMembers = (int)$pdo
        ->query("
            SELECT COUNT(*)
            FROM users
            WHERE role = 'member'
            AND status = 'active'
        ")
        ->fetchColumn();

    $totalActivities = (int)$pdo
        ->query("
            SELECT COUNT(*)
            FROM activities
        ")
        ->fetchColumn();

    $activeActivities = (int)$pdo
        ->query("
            SELECT COUNT(*)
            FROM activities
            WHERE status = 'Active'
        ")
        ->fetchColumn();

    $openReports = (int)$pdo
        ->query("
            SELECT COUNT(*)
            FROM reports
            WHERE status IN ('Open', 'Under Review', 'Investigating', 'Referred')
        ")
        ->fetchColumn();

    $totalGallery = (int)$pdo
        ->query("
            SELECT COUNT(*)
            FROM gallery
        ")
        ->fetchColumn();

} catch (PDOException $e) {

    /*
     * Keep dashboard running even if a statistic fails.
     */
}

/*
|--------------------------------------------------------------------------
| FETCH ACTIVITIES
|--------------------------------------------------------------------------
*/

$activities = [];

try {

    $stmt = $pdo->query("
        SELECT *
        FROM activities
        ORDER BY id DESC
    ");

    $activities = $stmt->fetchAll();

} catch (PDOException $e) {
    $activities = [];
}

/*
|--------------------------------------------------------------------------
| FETCH MEMBERS
|--------------------------------------------------------------------------
*/

$members = [];

try {

    $stmt = $pdo->query("
        SELECT id, name, email, role, status, created_at, last_login
        FROM users
        WHERE role != 'admin'
        ORDER BY id DESC
    ");

    $members = $stmt->fetchAll();

} catch (PDOException $e) {
    $members = [];
}

/*
|--------------------------------------------------------------------------
| FETCH REPORTS
|--------------------------------------------------------------------------
*/

$reports = [];

try {

    $stmt = $pdo->query("
        SELECT *
        FROM reports
        ORDER BY id DESC
    ");

    $reports = $stmt->fetchAll();

} catch (PDOException $e) {
    $reports = [];
}

/*
|--------------------------------------------------------------------------
| FETCH GALLERY
|--------------------------------------------------------------------------
*/

$gallery = [];

try {

    $stmt = $pdo->query("
        SELECT *
        FROM gallery
        ORDER BY id DESC
    ");

    $gallery = $stmt->fetchAll();

} catch (PDOException $e) {
    $gallery = [];
}

/*
|--------------------------------------------------------------------------
| FETCH ATTENDANCE
|--------------------------------------------------------------------------
*/
$attendance = [];
try {
    $attendance = $pdo->query("SELECT * FROM attendance ORDER BY attendance_date DESC, id DESC")->fetchAll();
} catch (PDOException $e) {
    $attendance = [];
}

/*
|--------------------------------------------------------------------------
| CURRENT PANEL
|--------------------------------------------------------------------------
*/

$currentPanel = $_GET['panel'] ?? 'dashboard';

$allowedPanels = [
    'dashboard',
    'activities',
    'gallery',
    'about',
    'reports',
    'members',
    'attendance',
    'settings',
    'search',
    'audit'
];

if (!in_array($currentPanel, $allowedPanels, true)) {
    $currentPanel = 'dashboard';
}

$successMessage = $_GET['success'] ?? '';

?>
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Husika Events — Admin Dashboard</title>

    <link
        rel="stylesheet"
        href="admin.css"
    >

    <link
        href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800;900&family=Playfair+Display:wght@700;900&display=swap"
        rel="stylesheet"
    >

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
</head>

<body>

<!-- =========================================================
     SIDEBAR
     ========================================================= -->

<aside class="sidebar" id="sidebar">

    <div class="sidebar-brand">

        <div class="brand-lock">

            <span class="brand-husika">
                Husika
            </span>

            <span class="brand-events">
                EVENTS
            </span>

        </div>

        <span class="admin-badge">
            Admin
        </span>

    </div>

    <nav class="sidebar-nav">

        <p class="nav-group-label">
            Overview
        </p>

        <a
            href="?panel=dashboard"
            class="sidebar-link <?= $currentPanel === 'dashboard' ? 'active' : '' ?>"
            data-panel="dashboard"
        >
            <span class="slink-icon">📊</span>
            Dashboard
        </a>


        <p class="nav-group-label">
            Content
        </p>

        <a
            href="?panel=activities"
            class="sidebar-link <?= $currentPanel === 'activities' ? 'active' : '' ?>"
            data-panel="activities"
        >
            <span class="slink-icon">📅</span>
            Activities
        </a>

        <a
            href="?panel=gallery"
            class="sidebar-link <?= $currentPanel === 'gallery' ? 'active' : '' ?>"
            data-panel="gallery"
        >
            <span class="slink-icon">🖼️</span>
            Gallery
        </a>

        <a
            href="?panel=about"
            class="sidebar-link <?= $currentPanel === 'about' ? 'active' : '' ?>"
            data-panel="about"
        >
            <span class="slink-icon">🏛️</span>
            Org. Info
        </a>


        <p class="nav-group-label">
            Community
        </p>

        <a
            href="?panel=reports"
            class="sidebar-link <?= $currentPanel === 'reports' ? 'active' : '' ?>"
            data-panel="reports"
        >
            <span class="slink-icon">🚨</span>
            Incident Reports

            <span class="sidebar-badge">
                <?= $openReports ?>
            </span>
        </a>

        <a
            href="?panel=members"
            class="sidebar-link <?= $currentPanel === 'members' ? 'active' : '' ?>"
            data-panel="members"
        >
            <span class="slink-icon">👥</span>
            Members
        </a>


        <p class="nav-group-label">
            System
        </p>

        <a
            href="?panel=attendance"
            class="sidebar-link <?= $currentPanel === 'attendance' ? 'active' : '' ?>"
            data-panel="attendance"
        >
            <span class="slink-icon">📝</span>
            Attendance
        </a>

        <a
            href="?panel=settings"
            class="sidebar-link <?= $currentPanel === 'settings' ? 'active' : '' ?>"
            data-panel="settings"
        >
            <span class="slink-icon">⚙️</span>
            Settings
        </a>

        <a href="?panel=search" class="sidebar-link <?= $currentPanel === 'search' ? 'active' : '' ?>"><span class="slink-icon">🔎</span> Global Search</a>
        <a href="?panel=audit" class="sidebar-link <?= $currentPanel === 'audit' ? 'active' : '' ?>"><span class="slink-icon">📝</span> Audit Log</a>

    </nav>


    <div class="sidebar-user">

        <div class="user-avatar">
            <?= strtoupper(substr($adminName, 0, 2)) ?>
        </div>

        <div class="user-info">

            <strong>
                <?= e($adminName) ?>
            </strong>

            <span>
                Super Admin
            </span>

        </div>

        <a
            href="?logout=1"
            class="logout-btn"
            title="Logout"
        >
            ↩
        </a>

    </div>

</aside>


<!-- =========================================================
     MAIN
     ========================================================= -->

<main class="main" id="main">

    <!-- TOP BAR -->

    <header class="topbar-admin">

        <button
            class="sidebar-toggle"
            id="sidebar-toggle"
            aria-label="Toggle sidebar"
        >
            ☰
        </button>

        <div
            class="topbar-title"
            id="topbar-title"
        >
            <?= ucfirst(str_replace('-', ' ', $currentPanel)) ?>
        </div>

        <div class="topbar-right">

            <span
                class="topbar-date"
                id="topbar-date"
            ></span>

            <a
                href="index.php"
                class="btn-visit"
            >
                ← Visit Site
            </a>

        </div>

    </header>


    <?php if ($successMessage): ?>

        <div
            style="
                margin:20px;
                padding:14px 18px;
                background:#E8F5EC;
                color:#1A5C2A;
                border-radius:8px;
                font-weight:700;
            "
        >
            <?= e($successMessage) ?>
        </div>

    <?php endif; ?>


    <!-- =====================================================
         DASHBOARD
         ===================================================== -->

    <section
        class="panel <?= $currentPanel === 'dashboard' ? 'active' : '' ?>"
        id="panel-dashboard"
    >

        <div class="panel-head">

            <h1>
                Welcome back, <?= e($adminName) ?>
            </h1>

            <p>
                Here's a snapshot of Husika Events today.
            </p>

        </div>


        <!-- COMPACT DASHBOARD STATS -->
        <div class="stats-row stats-row--compact">
            <div class="stat-card"><div class="stat-icon stat-icon--green">👥</div><div class="stat-body"><span class="stat-num"><?= $totalMembers ?></span><span class="stat-label">Registered Members</span></div><div class="stat-change up"><?= $activeMembers ?> active</div></div>
            <div class="stat-card"><div class="stat-icon stat-icon--teal">📅</div><div class="stat-body"><span class="stat-num"><?= $activeActivities ?></span><span class="stat-label">Active Activities</span></div><div class="stat-change up"><?= $totalActivities ?> total</div></div>
            <div class="stat-card"><div class="stat-icon stat-icon--red">🚨</div><div class="stat-body"><span class="stat-num"><?= $openReports ?></span><span class="stat-label">Open Reports</span></div><div class="stat-change down">Needs review</div></div>
            <div class="stat-card"><div class="stat-icon stat-icon--gold">🖼️</div><div class="stat-body"><span class="stat-num"><?= $totalGallery ?></span><span class="stat-label">Gallery Images</span></div><div class="stat-change up">Total uploaded</div></div>
            <div class="stat-card"><div class="stat-icon stat-icon--purple">👑</div><div class="stat-body"><span class="stat-num"><?= $totalAdmins ?></span><span class="stat-label">Total Administrators</span></div><div class="stat-change up">Admin accounts</div></div>
            <div class="stat-card"><div class="stat-icon stat-icon--blue">📋</div><div class="stat-body"><span class="stat-num"><?= $totalReports ?></span><span class="stat-label">Total Incident Reports</span></div><div class="stat-change up">All reports</div></div>
            <div class="stat-card"><div class="stat-icon stat-icon--green">✅</div><div class="stat-body"><span class="stat-num"><?= $resolvedReports ?></span><span class="stat-label">Resolved Reports</span></div><div class="stat-change up">Resolved</div></div>
            <div class="stat-card"><div class="stat-icon stat-icon--gold">📈</div><div class="stat-body"><span class="stat-num"><?= $membersThisMonth ?></span><span class="stat-label">Members This Month</span></div><div class="stat-change up">New registrations</div></div>
        </div>

        <div class="charts-grid">
            <div class="dash-card chart-card"><div class="dash-card-head"><h3>Reports by Incident Type</h3></div><div class="chart-wrap"><canvas id="reportTypeChart"></canvas></div></div>
            <div class="dash-card chart-card"><div class="dash-card-head"><h3>Reports by Month</h3></div><div class="chart-wrap"><canvas id="reportMonthChart"></canvas></div></div>
            <div class="dash-card chart-card"><div class="dash-card-head"><h3>Member Registrations</h3></div><div class="chart-wrap"><canvas id="memberChart"></canvas></div></div>
            <div class="dash-card chart-card"><div class="dash-card-head"><h3>Activity Participation</h3></div><div class="chart-wrap"><canvas id="activityChart"></canvas></div></div><div class="dash-card chart-card"><div class="dash-card-head"><h3>Attendance</h3></div><div class="chart-wrap"><canvas id="attendanceChart"></canvas></div></div><div class="dash-card chart-card"><div class="dash-card-head"><h3>Report Resolution Rate</h3></div><div class="chart-wrap"><canvas id="resolutionChart"></canvas></div></div>
        </div>

        <!-- DASHBOARD GRID -->

        <div class="dash-grid">


            <!-- RECENT REPORTS -->

            <div class="dash-card">

                <div class="dash-card-head">

                    <h3>
                        Latest Incident Reports
                    </h3>

                    <button
                        class="card-link"
                        onclick="switchPanel('reports')"
                    >
                        View all →
                    </button>

                </div>

                <table class="mini-table">

                    <thead>

                    <tr>
                        <th>Type</th>
                        <th>Location</th>
                        <th>Date</th>
                        <th>Status</th>
                    </tr>

                    </thead>

                    <tbody>

                    <?php

                    $recentReports = array_slice($reports, 0, 4);

                    foreach ($recentReports as $report):

                    ?>

                        <tr>

                            <td>
                                <span class="tag tag--red">
                                    <?= e($report['incident_type']) ?>
                                </span>
                            </td>

                            <td>
                                <?= e($report['location']) ?>
                            </td>

                            <td>
                                <?= date(
                                    'M d',
                                    strtotime($report['created_at'])
                                ) ?>
                            </td>

                            <td>

                                <?php
                                $statusClass = 'status--open';

                                if ($report['status'] === 'Closed') {
                                    $statusClass = 'status--closed';
                                } elseif ($report['status'] === 'In Review') {
                                    $statusClass = 'status--review';
                                }
                                ?>

                                <span class="status <?= $statusClass ?>">
                                    <?= e($report['status']) ?>
                                </span>

                            </td>

                        </tr>

                    <?php endforeach; ?>


                    <?php if (empty($recentReports)): ?>

                        <tr>
                            <td colspan="4">
                                No incident reports found.
                            </td>
                        </tr>

                    <?php endif; ?>

                    </tbody>

                </table>

            </div>


            <!-- RECENT MEMBERS -->

            <div class="dash-card">

                <div class="dash-card-head">

                    <h3>
                        New Members
                    </h3>

                    <button
                        class="card-link"
                        onclick="switchPanel('members')"
                    >
                        View all →
                    </button>

                </div>


                <ul class="member-list">

                <?php

                $recentMembers = array_slice($members, 0, 4);

                foreach ($recentMembers as $member):

                    $nameParts = preg_split(
                        '/\s+/',
                        trim($member['name'])
                    );

                    $initials = '';

                    foreach (array_slice($nameParts, 0, 2) as $part) {
                        $initials .= strtoupper(substr($part, 0, 1));
                    }

                ?>

                    <li>

                        <div
                            class="member-avatar"
                            style="background:#E8F5EC;color:#1A5C2A"
                        >
                            <?= e($initials) ?>
                        </div>

                        <div class="member-info">

                            <strong>
                                <?= e($member['name']) ?>
                            </strong>

                            <span>
                                <?= e(ucfirst($member['role'])) ?>
                            </span>

                        </div>

                        <span class="member-date">

                            <?= date(
                                'M d',
                                strtotime($member['created_at'])
                            ) ?>

                        </span>

                    </li>

                <?php endforeach; ?>


                <?php if (empty($recentMembers)): ?>

                    <li>
                        No members registered yet.
                    </li>

                <?php endif; ?>

                </ul>

            </div>


            <!-- ACTIVITY SUMMARY -->

            <div class="dash-card">

                <div class="dash-card-head">

                    <h3>
                        Activities This Month
                    </h3>

                    <button
                        class="card-link"
                        onclick="switchPanel('activities')"
                    >
                        Manage →
                    </button>

                </div>

                <div class="activity-bars">

                <?php

                $groupCounts = [
                    'Children' => 0,
                    'Youth' => 0,
                    'Families' => 0,
                    'Education' => 0
                ];

                foreach ($activities as $activity) {

                    $group = $activity['group_name'];

                    if (isset($groupCounts[$group])) {
                        $groupCounts[$group]++;
                    }
                }

                $maxCount = max(
                    1,
                    max($groupCounts)
                );

                ?>

                    <div class="abar-row">

                        <span>
                            Children's Workshops
                        </span>

                        <div class="abar-wrap">

                            <div
                                class="abar"
                                style="
                                    width:<?= ($groupCounts['Children'] / $maxCount) * 100 ?>%;
                                    background:var(--green-mid)
                                "
                            ></div>

                        </div>

                        <span>
                            <?= $groupCounts['Children'] ?>
                        </span>

                    </div>


                    <div class="abar-row">

                        <span>
                            Youth Sessions
                        </span>

                        <div class="abar-wrap">

                            <div
                                class="abar"
                                style="
                                    width:<?= ($groupCounts['Youth'] / $maxCount) * 100 ?>%;
                                    background:var(--teal)
                                "
                            ></div>

                        </div>

                        <span>
                            <?= $groupCounts['Youth'] ?>
                        </span>

                    </div>


                    <div class="abar-row">

                        <span>
                            Family Programmes
                        </span>

                        <div class="abar-wrap">

                            <div
                                class="abar"
                                style="
                                    width:<?= ($groupCounts['Families'] / $maxCount) * 100 ?>%;
                                    background:var(--gold-dark)
                                "
                            ></div>

                        </div>

                        <span>
                            <?= $groupCounts['Families'] ?>
                        </span>

                    </div>


                    <div class="abar-row">

                        <span>
                            School Outreach
                        </span>

                        <div class="abar-wrap">

                            <div
                                class="abar"
                                style="
                                    width:<?= ($groupCounts['Education'] / $maxCount) * 100 ?>%;
                                    background:var(--red)
                                "
                            ></div>

                        </div>

                        <span>
                            <?= $groupCounts['Education'] ?>
                        </span>

                    </div>

                </div>

            </div>


            <!-- QUICK ACTIONS -->

            <div class="dash-card">

                <div class="dash-card-head">

                    <h3>
                        Quick Actions
                    </h3>

                </div>

                <div class="quick-actions">

                    <button
                        class="qa-btn"
                        onclick="switchPanel('activities')"
                    >
                        <span class="qa-icon">➕</span>
                        <span>Add Activity</span>
                    </button>

                    <button
                        class="qa-btn"
                        onclick="switchPanel('gallery')"
                    >
                        <span class="qa-icon">📷</span>
                        <span>Upload Image</span>
                    </button>

                    <button
                        class="qa-btn"
                        onclick="switchPanel('reports')"
                    >
                        <span class="qa-icon">📋</span>
                        <span>View Reports</span>
                    </button>

                    <button
                        class="qa-btn"
                        onclick="switchPanel('members')"
                    >
                        <span class="qa-icon">👤</span>
                        <span>Add Member</span>
                    </button>

                    <button
                        class="qa-btn"
                        onclick="switchPanel('about')"
                    >
                        <span class="qa-icon">✏️</span>
                        <span>Edit Org Info</span>
                    </button>

                    <button
                        class="qa-btn"
                        onclick="switchPanel('settings')"
                    >
                        <span class="qa-icon">⚙️</span>
                        <span>Settings</span>
                    </button>

                </div>

            </div>

        </div>

    </section>


    <!-- =====================================================
         ACTIVITIES
         ===================================================== -->

    <section
        class="panel <?= $currentPanel === 'activities' ? 'active' : '' ?>"
        id="panel-activities"
    >

        <div class="panel-head between">

            <div>

                <h1>
                    Activities & Programmes
                </h1>

                <p>
                    Add, edit, or remove activities visible on the website.
                </p>

            </div>

            <button
                class="btn btn--primary"
                onclick="openModal('modal-add-activity')"
            >
                + Add Activity
            </button>

        </div>


        <div class="filter-row">

            <select
                id="act-filter-group"
                onchange="filterActivities()"
            >
                <option value="">
                    All Groups
                </option>

                <option>
                    Children
                </option>

                <option>
                    Youth
                </option>

                <option>
                    Families
                </option>

                <option>
                    Education
                </option>

            </select>


            <select
                id="act-filter-season"
                onchange="filterActivities()"
            >

                <option value="">
                    All Seasons
                </option>

                <option>
                    School Term
                </option>

                <option>
                    Holiday
                </option>

            </select>


            <input
                type="text"
                placeholder="Search activities..."
                id="act-search"
                oninput="filterActivities()"
            >

        </div>


        <div class="table-wrap">

            <table
                class="data-table"
                id="activities-table"
            >

                <thead>

                <tr>
                    <th>Activity</th>
                    <th>Group</th>
                    <th>Schedule</th>
                    <th>Location</th>
                    <th>Season</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>

                </thead>

                <tbody>

                <?php foreach ($activities as $activity): ?>

                    <tr
                        data-group="<?= e($activity['group_name']) ?>"
                        data-season="<?= e($activity['season']) ?>"
                    >

                        <td>
                            <strong>
                                <?= e($activity['title']) ?>
                            </strong>
                        </td>

                        <td>

                            <span class="tag tag--green">
                                <?= e($activity['group_name']) ?>
                            </span>

                        </td>

                        <td>
                            <?= e($activity['schedule']) ?>
                        </td>

                        <td>
                            <?= e($activity['location']) ?>
                        </td>

                        <td>
                            <?= e($activity['season']) ?>
                        </td>

                        <td>

                            <?php

                            $activityStatusClass =
                                strtolower($activity['status']) === 'active'
                                ? 'status--active'
                                : 'status--draft';

                            ?>

                            <span
                                class="status <?= $activityStatusClass ?>"
                            >
                                <?= e($activity['status']) ?>
                            </span>

                        </td>

                        <td class="actions-cell">

                            <button
                                class="act-btn act-btn--edit"
                                title="Edit"
                                onclick="showToast('Activity editing can be connected to the database next.')"
                            >
                                ✏️
                            </button>


                            <form
                                method="POST"
                                style="display:inline"
                                onsubmit="return confirm('Delete this activity?')"
                            >
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                                <input
                                    type="hidden"
                                    name="action"
                                    value="delete_activity"
                                >

                                <input
                                    type="hidden"
                                    name="id"
                                    value="<?= (int)$activity['id'] ?>"
                                >

                                <button
                                    type="submit"
                                    class="act-btn act-btn--del"
                                    title="Delete"
                                >
                                    🗑️
                                </button>

                            </form>

                        </td>

                    </tr>

                <?php endforeach; ?>


                <?php if (empty($activities)): ?>

                    <tr>

                        <td colspan="7">
                            No activities have been added yet.
                        </td>

                    </tr>

                <?php endif; ?>

                </tbody>

            </table>

        </div>

    </section>


    <!-- =====================================================
         GALLERY
         ===================================================== -->

    <section
        class="panel <?= $currentPanel === 'gallery' ? 'active' : '' ?>"
        id="panel-gallery"
    >

        <div class="panel-head between">

            <div>

                <h1>
                    Gallery Manager
                </h1>

                <p>
                    Upload, organise, and remove images from the website gallery.
                </p>

            </div>


            <form
                method="POST"
                enctype="multipart/form-data"
                id="gallery-upload-form"
            >
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                <input
                    type="hidden"
                    name="action"
                    value="upload_gallery"
                >

                <label
                    class="btn btn--primary"
                    style="cursor:pointer;"
                >

                    📷 Upload Images

                    <input
                        type="file"
                        id="gallery-file-input"
                        name="gallery_images[]"
                        accept="image/jpeg,image/png,image/webp,image/gif"
                        multiple
                        style="display:none"
                        onchange="this.form.submit()"
                    >

                </label>

            </form>

        </div>


        <div class="gallery-toolbar">

            <input
                type="text"
                placeholder="Search images..."
                style="max-width:280px"
            >

            <select>

                <option>
                    All Albums
                </option>

                <option>
                    Events 2024
                </option>

                <option>
                    Youth Programmes
                </option>

                <option>
                    Community Outreach
                </option>

                <option>
                    Campaigns
                </option>

            </select>

            <button
                class="btn btn--outline-dark"
                onclick="openModal('modal-add-album')"
            >
                + New Album
            </button>

        </div>


        <div
            class="gallery-admin-grid"
            id="gallery-grid"
        >

            <?php foreach ($gallery as $image): ?>

                <div class="gallery-admin-item">

                    <div class="gallery-img-wrap">

                        <?php
                        $imagePath =
                            'uploads/gallery/' .
                            $image['filename'];
                        ?>

                        <?php if (
                            !empty($image['filename']) &&
                            file_exists(
                                __DIR__ .
                                '/uploads/gallery/' .
                                $image['filename']
                            )
                        ): ?>

                            <img
                                src="<?= e($imagePath) ?>"
                                alt="<?= e($image['title']) ?>"
                                class="gallery-thumb"
                                style="
                                    width:100%;
                                    height:100%;
                                    object-fit:cover;
                                "
                            >

                        <?php else: ?>

                            <div class="gallery-thumb placeholder-thumb">
                                📸
                            </div>

                        <?php endif; ?>


                        <div class="gallery-item-overlay">

                            <form
                                method="POST"
                                onsubmit="return confirm('Delete this image?')"
                            >
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                                <input
                                    type="hidden"
                                    name="action"
                                    value="delete_gallery"
                                >

                                <input
                                    type="hidden"
                                    name="id"
                                    value="<?= (int)$image['id'] ?>"
                                >

                                <button
                                    type="submit"
                                    class="overlay-btn"
                                    title="Delete"
                                >
                                    🗑️
                                </button>

                            </form>

                        </div>

                    </div>


                    <div class="gallery-item-meta">

                        <span>
                            <?= e($image['title']) ?>
                        </span>

                        <span class="img-size">
                            <?= e($image['album']) ?>
                        </span>

                    </div>

                </div>

            <?php endforeach; ?>


            <?php if (empty($gallery)): ?>

                <div class="gallery-admin-item">

                    <div class="gallery-img-wrap">

                        <div class="gallery-thumb placeholder-thumb">
                            📸
                        </div>

                    </div>

                    <div class="gallery-item-meta">

                        <span>
                            No images uploaded yet
                        </span>

                    </div>

                </div>

            <?php endif; ?>


            <!-- UPLOAD DROP ZONE -->

            <div
                class="gallery-drop-zone"
                id="drop-zone"
                role="button"
                tabindex="0"
                aria-label="Drag and drop images here or click to select images"
            >

                <span style="font-size:36px">
                    ☁️
                </span>

                <p>
                    <strong>Drag & drop images here</strong>
                </p>

                <p>
                    or click here to browse
                </p>

                <p
                    style="
                        font-size:12px;
                        color:var(--text-muted)
                    "
                >
                    PNG, JPG, WEBP, GIF — max 10 MB each
                </p>

            </div>

        </div>

    </section>


    <!-- =====================================================
         ORGANISATIONAL INFO
         ===================================================== -->

    <section
        class="panel <?= $currentPanel === 'about' ? 'active' : '' ?>"
        id="panel-about"
    >

        <div class="panel-head">

            <h1>
                Organisational Information
            </h1>

            <p>
                Edit content that appears on the About page of the website.
            </p>

        </div>


        <div class="form-sections">


            <div class="form-section">

                <h3>
                    Organisation History
                </h3>

                <div class="form-group">

                    <label>
                        Organisation Name
                    </label>

                    <input
                        type="text"
                        value="Husika Events"
                    >

                </div>


                <div class="form-group">

                    <label>
                        Founded
                    </label>

                    <input
                        type="text"
                        value="2018"
                    >

                </div>


                <div class="form-group">

                    <label>
                        History / Background
                    </label>

                    <textarea rows="5">Husika Events was founded on a simple yet powerful belief: every child deserves to feel safe, every community member deserves dignity, and every voice deserves to be heard. Rooted in Kenyan communities, Husika brings together volunteers, professionals, and families...</textarea>

                </div>

            </div>


            <div class="form-section">

                <h3>
                    Mission & Vision
                </h3>

                <div class="form-group">

                    <label>
                        Mission Statement
                    </label>

                    <textarea rows="3">To empower communities to protect children, prevent abuse, and foster environments where every individual can thrive.</textarea>

                </div>


                <div class="form-group">

                    <label>
                        Vision Statement
                    </label>

                    <textarea rows="3">A Kenya where no child suffers in silence and every community has the tools to stand up for the vulnerable.</textarea>

                </div>

            </div>


            <div class="form-section">

                <h3>
                    Management Team
                </h3>

                <table class="data-table">

                    <thead>

                    <tr>
                        <th>Name</th>
                        <th>Role / Title</th>
                        <th>Department</th>
                        <th>Actions</th>
                    </tr>

                    </thead>

                    <tbody>

                    <tr>

                        <td>
                            Dr. Sarah Njeri
                        </td>

                        <td>
                            Executive Director
                        </td>

                        <td>
                            Leadership
                        </td>

                        <td class="actions-cell">

                            <button class="act-btn act-btn--edit">
                                ✏️
                            </button>

                            <button
                                class="act-btn act-btn--del"
                                onclick="confirmDelete(this)"
                            >
                                🗑️
                            </button>

                        </td>

                    </tr>


                    <tr>

                        <td>
                            Mr. John Maina
                        </td>

                        <td>
                            Programme Manager
                        </td>

                        <td>
                            Operations
                        </td>

                        <td class="actions-cell">

                            <button class="act-btn act-btn--edit">
                                ✏️
                            </button>

                            <button
                                class="act-btn act-btn--del"
                                onclick="confirmDelete(this)"
                            >
                                🗑️
                            </button>

                        </td>

                    </tr>


                    <tr>

                        <td>
                            Ms. Grace Achieng
                        </td>

                        <td>
                            Child Protection Officer
                        </td>

                        <td>
                            Welfare
                        </td>

                        <td class="actions-cell">

                            <button class="act-btn act-btn--edit">
                                ✏️
                            </button>

                            <button
                                class="act-btn act-btn--del"
                                onclick="confirmDelete(this)"
                            >
                                🗑️
                            </button>

                        </td>

                    </tr>

                    </tbody>

                </table>


                <button
                    class="btn btn--outline-dark"
                    style="margin-top:12px"
                >
                    + Add Team Member
                </button>

            </div>


            <div class="form-section">

                <h3>
                    Departments / Groups
                </h3>

                <table class="data-table">

                    <thead>

                    <tr>
                        <th>Group Name</th>
                        <th>Age Range</th>
                        <th>Description</th>
                        <th>Actions</th>
                    </tr>

                    </thead>

                    <tbody>

                    <tr>

                        <td>
                            Children's Group
                        </td>

                        <td>
                            5–12
                        </td>

                        <td>
                            Play-based learning and safety education
                        </td>

                        <td class="actions-cell">

                            <button class="act-btn act-btn--edit">
                                ✏️
                            </button>

                            <button
                                class="act-btn act-btn--del"
                                onclick="confirmDelete(this)"
                            >
                                🗑️
                            </button>

                        </td>

                    </tr>


                    <tr>

                        <td>
                            Youth Department
                        </td>

                        <td>
                            13–25
                        </td>

                        <td>
                            Leadership, mentorship, and life skills
                        </td>

                        <td class="actions-cell">

                            <button class="act-btn act-btn--edit">
                                ✏️
                            </button>

                            <button
                                class="act-btn act-btn--del"
                                onclick="confirmDelete(this)"
                            >
                                🗑️
                            </button>

                        </td>

                    </tr>


                    <tr>

                        <td>
                            Families & Parents
                        </td>

                        <td>
                            All Ages
                        </td>

                        <td>
                            Parenting support and counselling
                        </td>

                        <td class="actions-cell">

                            <button class="act-btn act-btn--edit">
                                ✏️
                            </button>

                            <button
                                class="act-btn act-btn--del"
                                onclick="confirmDelete(this)"
                            >
                                🗑️
                            </button>

                        </td>

                    </tr>

                    </tbody>

                </table>


                <button
                    class="btn btn--outline-dark"
                    style="margin-top:12px"
                >
                    + Add Group
                </button>

            </div>


            <div class="form-actions">

                <button
                    class="btn btn--primary"
                    onclick="showToast('Organisational information saved!')"
                >
                    Save All Changes
                </button>

                <button class="btn btn--outline-dark">
                    Discard
                </button>

            </div>

        </div>

    </section>


    <!-- =====================================================
         INCIDENT REPORTS
         ===================================================== -->
    <section class="panel <?= $currentPanel === 'reports' ? 'active' : '' ?>" id="panel-reports">
        <div class="panel-head between">
            <div>
                <h1>Incident Reports</h1>
                <p>Search, assign, track, update, print and export incident cases.</p>
                <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;">
                    <a class="btn btn--outline-dark btn--sm" href="?panel=reports&export=reports_pdf">⬇️ Export PDF</a>
                    <a class="btn btn--outline-dark btn--sm" href="?panel=reports&export=reports_csv">⬇️ Export CSV</a>
                    <a class="btn btn--outline-dark btn--sm" href="?panel=reports&export=members_csv">👥 Members CSV</a>
                    <a class="btn btn--outline-dark btn--sm" href="?panel=reports&export=activities_csv">📅 Activities CSV</a>
                    <a class="btn btn--outline-dark btn--sm" href="?panel=reports&export=attendance_csv">📝 Attendance CSV</a>
                    <a class="btn btn--outline-dark btn--sm" href="?panel=reports&export=gallery_csv">🖼️ Gallery CSV</a>
                </div>
            </div>
        </div>

        <div class="filter-row" style="display:flex;gap:10px;flex-wrap:wrap;margin:18px 0;">
            <input id="reportSearch" type="search" placeholder="Search report ID, type, location, officer..." oninput="filterReports()" style="flex:1;min-width:240px;">
            <select id="reportPriorityFilter" onchange="filterReports()">
                <option value="">All Priorities</option><option>Low</option><option>Medium</option><option>High</option><option>Critical</option>
            </select>
            <select id="reportStatusFilter" onchange="filterReports()">
                <option value="">All Statuses</option><option>Open</option><option>Under Review</option><option>Investigating</option><option>Referred</option><option>Resolved</option><option>Closed</option>
            </select>
        </div>

        <div class="reports-list" id="reportsList">
        <?php foreach ($reports as $report): ?>
            <?php
                $reportNumber = $report['report_number'] ?? ('HUS-' . str_pad((string)$report['id'], 6, '0', STR_PAD_LEFT));
                $priority = $report['priority'] ?? 'Medium';
                $status = $report['status'] ?? 'Open';
                $historyStmt = $pdo->prepare("SELECT h.*, u.name AS changed_by_name FROM report_history h LEFT JOIN users u ON u.id = h.changed_by WHERE h.report_id = ? ORDER BY h.id DESC LIMIT 20");
                $historyStmt->execute([(int)$report['id']]);
                $history = $historyStmt->fetchAll();
            ?>
            <div class="report-card" data-report-id="<?= (int)$report['id'] ?>" data-report-search="<?= e(strtolower($reportNumber.' '.$report['incident_type'].' '.$report['location'].' '.$report['assigned_officer'])) ?>" data-priority="<?= e($priority) ?>" data-status="<?= e($status) ?>" style="margin-bottom:18px;">
                <div class="report-card-head">
                    <div>
                        <span class="tag tag--red"><?= e($report['incident_type']) ?></span>
                        <strong style="margin-left:8px;"><?= e($reportNumber) ?></strong>
                    </div>
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                        <span class="status status--<?= strtolower(str_replace(' ', '-', e($status))) ?>"><?= e($status) ?></span>
                        <span class="tag <?= $priority === 'Critical' || $priority === 'High' ? 'tag--red' : ($priority === 'Low' ? 'tag--green' : 'tag--gold') ?>">Priority: <?= e($priority) ?></span>
                    </div>
                </div>

                <p class="report-desc"><?= e($report['description']) ?></p>
                <div class="report-meta" style="display:flex;gap:15px;flex-wrap:wrap;">
                    <span>📍 <?= e($report['location'] ?: 'Not provided') ?></span>
                    <span>👤 <?= e($report['reporter_name'] ?: 'Anonymous') ?></span>
                    <span>📅 <?= e($report['created_at']) ?></span>
                    <span>🧑‍💼 <?= e($report['assigned_officer'] ?: 'Unassigned') ?></span>
                    <span>🔎 Follow-up: <?= e($report['follow_up_date'] ?: 'Not set') ?></span>
                </div>

                <details style="margin-top:15px;">
                    <summary><strong>Manage case</strong></summary>
                    <form method="POST" style="margin-top:15px;display:grid;gap:12px;">
                        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="update_report_status">
                        <input type="hidden" name="id" value="<?= (int)$report['id'] ?>">
                        <div class="form-row">
                            <div class="form-group"><label>Report Number / ID</label><input value="<?= e($reportNumber) ?>" readonly></div>
                            <div class="form-group"><label>Priority</label><select name="priority"><?php foreach(['Low','Medium','High','Critical'] as $p): ?><option <?= $priority === $p ? 'selected' : '' ?>><?= $p ?></option><?php endforeach; ?></select></div>
                        </div>
                        <div class="form-row">
                            <div class="form-group"><label>Assigned Officer / Social Worker</label><input name="assigned_officer" value="<?= e($report['assigned_officer'] ?? '') ?>" placeholder="Officer / social worker"></div>
                            <div class="form-group"><label>Status</label><select name="status"><?php foreach(['Open','Under Review','Investigating','Referred','Resolved','Closed'] as $st): ?><option <?= $status === $st ? 'selected' : '' ?>><?= $st ?></option><?php endforeach; ?></select></div>
                        </div>
                        <div class="form-row">
                            <div class="form-group"><label>Follow-up date</label><input type="date" name="follow_up_date" value="<?= e($report['follow_up_date'] ?? '') ?>"></div>
                            <div class="form-group"><label>Date resolved</label><input type="datetime-local" name="date_resolved" value="<?= !empty($report['date_resolved']) ? e(date('Y-m-d\\TH:i', strtotime($report['date_resolved']))) : '' ?>"></div>
                        </div>
                        <div class="form-group"><label>Admin notes</label><textarea name="admin_notes" rows="3" placeholder="Internal notes..."> <?= e($report['admin_notes'] ?? '') ?></textarea></div>
                        <div class="form-group"><label>Internal case history note</label><textarea name="history_note" rows="2" placeholder="What action was taken or what changed?"></textarea></div>
                        <div style="display:flex;gap:8px;flex-wrap:wrap;">
                            <button type="submit" class="btn btn--primary btn--sm">Save Case</button>
                            <button type="button" class="btn btn--outline-dark btn--sm" onclick="printReport(<?= (int)$report['id'] ?>)">🖨️ Print Individual Report</button>
                        </div>
                    </form>
                </details>

                <details style="margin-top:12px;">
                    <summary><strong>Internal Case History (<?= count($history) ?>)</strong></summary>
                    <div style="margin-top:12px;">
                        <?php if ($history): foreach ($history as $h): ?>
                            <div style="padding:10px;border-left:3px solid #ccc;margin-bottom:8px;background:#fafafa;">
                                <strong><?= e($h['action']) ?></strong> — <?= e($h['created_at']) ?><br>
                                <small><?= e($h['changed_by_name'] ?: 'System') ?><?= $h['old_status'] || $h['new_status'] ? ' | '.e($h['old_status']).' → '.e($h['new_status']) : '' ?></small>
                                <div><?= nl2br(e($h['notes'])) ?></div>
                            </div>
                        <?php endforeach; else: ?><p>No internal history yet.</p><?php endif; ?>
                    </div>
                    <form method="POST" style="margin-top:10px;display:flex;gap:8px;">
                        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="add_report_history">
                        <input type="hidden" name="report_id" value="<?= (int)$report['id'] ?>">
                        <input type="text" name="history_note" placeholder="Add internal note..." style="flex:1" required>
                        <button class="btn btn--outline-dark btn--sm" type="submit">Add Note</button>
                    </form>
                </details>
            </div>
        <?php endforeach; ?>

        <?php if (empty($reports)): ?>
            <div class="report-card"><h3>No incident reports</h3><p class="report-desc">There are currently no incident reports in the system.</p></div>
        <?php endif; ?>
        </div>
    </section>

    <!-- =====================================================
         MEMBERS
         ===================================================== -->

    <section
        class="panel <?= $currentPanel === 'members' ? 'active' : '' ?>"
        id="panel-members"
    >

        <div class="panel-head between">

            <div>

                <h1>
                    Member Management
                </h1>

                <p>
                    View, search, and manage all registered members.
                </p>

            </div>

            <button
                class="btn btn--primary"
                onclick="openModal('modal-add-member')"
            >
                + Add Member
            </button>

        </div>


        <div class="filter-row">

            <input
                type="text"
                placeholder="Search by name or email..."
                style="flex:1"
                oninput="filterMembers(this.value)"
            >


            <select onchange="filterMembers()">

                <option value="">
                    All Groups
                </option>

                <option>
                    Children's Group
                </option>

                <option>
                    Youth Department
                </option>

                <option>
                    Families & Parents
                </option>

                <option>
                    Volunteer
                </option>

            </select>


            <select>

                <option value="">
                    All Statuses
                </option>

                <option>
                    Active
                </option>

                <option>
                    Pending
                </option>

                <option>
                    Suspended
                </option>

            </select>

        </div>


        <div class="table-wrap">

            <table
                class="data-table"
                id="members-table"
            >

                <thead>

                <tr>

                    <th>
                        Member
                    </th>

                    <th>
                        Group
                    </th>

                    <th>
                        Email
                    </th>

                    <th>
                        Joined
                    </th>

                    <th>
                        Status
                    </th>

                    <th>
                        Actions
                    </th>

                </tr>

                </thead>


                <tbody>

                <?php foreach ($members as $member): ?>

                    <?php

                    $nameParts = preg_split(
                        '/\s+/',
                        trim($member['name'])
                    );

                    $initials = '';

                    foreach (
                        array_slice(
                            $nameParts,
                            0,
                            2
                        ) as $part
                    ) {

                        $initials .= strtoupper(
                            substr(
                                $part,
                                0,
                                1
                            )
                        );
                    }

                    ?>

                    <tr>

                        <td>

                            <div class="member-cell">

                                <div
                                    class="member-avatar sm"
                                    style="
                                        background:#E8F5EC;
                                        color:#1A5C2A
                                    "
                                >
                                    <?= e($initials) ?>
                                </div>

                                <div>

                                    <strong>
                                        <?= e($member['name']) ?>
                                    </strong>

                                    <br>

                                    <span
                                        style="
                                            font-size:12px;
                                            color:var(--text-muted)
                                        "
                                    >
                                        <?= e($member['email']) ?>
                                    </span>

                                </div>

                            </div>

                        </td>


                        <td>

                            <span class="tag tag--green">
                                <?= e(
                                    ucfirst(
                                        $member['role']
                                    )
                                ) ?>
                            </span>

                        </td>


                        <td>
                            <?= e($member['email']) ?>
                        </td>


                        <td>

                            <?= date(
                                'M d, Y',
                                strtotime(
                                    $member['created_at']
                                )
                            ) ?>

                        </td>


                        <td>

                            <?php

                            $memberStatusClass =
                                strtolower($member['status']) === 'active'
                                ? 'status--active'
                                : 'status--pending';

                            ?>

                            <span
                                class="status <?= $memberStatusClass ?>"
                            >
                                <?= e(
                                    ucfirst(
                                        $member['status']
                                    )
                                ) ?>
                            </span>

                        </td>


                        <td class="actions-cell">

                            <button
                                class="act-btn act-btn--edit"
                                onclick="showToast('Member editing can be connected to the database next.')"
                            >
                                ✏️
                            </button>


                            <form
                                method="POST"
                                style="display:inline"
                                onsubmit="return confirm('Delete this member?')"
                            >
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                                <input
                                    type="hidden"
                                    name="action"
                                    value="delete_member"
                                >

                                <input
                                    type="hidden"
                                    name="id"
                                    value="<?= (int)$member['id'] ?>"
                                >

                                <button
                                    type="submit"
                                    class="act-btn act-btn--del"
                                >
                                    🗑️
                                </button>

                            </form>

                        </td>

                    </tr>

                <?php endforeach; ?>


                <?php if (empty($members)): ?>

                    <tr>

                        <td colspan="6">
                            No members registered yet.
                        </td>

                    </tr>

                <?php endif; ?>

                </tbody>

            </table>

        </div>

    </section>


    <!-- =====================================================
         ATTENDANCE
         ===================================================== -->
    <section class="panel <?= $currentPanel === 'attendance' ? 'active' : '' ?>" id="panel-attendance">
        <div class="panel-head between">
            <div><h1>Attendance</h1><p>Attendance records available for CSV export.</p></div>
            <a class="btn btn--primary" href="?panel=attendance&export=attendance_csv">⬇️ Export Attendance CSV</a>
        </div>
        <div class="table-wrap">
            <table class="data-table">
                <thead><tr><th>Member</th><th>Activity</th><th>Date</th><th>Status</th><th>Notes</th></tr></thead>
                <tbody>
                <?php foreach ($attendance as $a): ?>
                    <tr><td><?= e($a['member_name']) ?></td><td><?= e($a['activity_title']) ?></td><td><?= e($a['attendance_date']) ?></td><td><?= e($a['status']) ?></td><td><?= e($a['notes']) ?></td></tr>
                <?php endforeach; ?>
                <?php if (!$attendance): ?><tr><td colspan="5">No attendance records yet.</td></tr><?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>

    <!-- =====================================================
         SETTINGS
         ===================================================== -->

    <section
        class="panel <?= $currentPanel === 'settings' ? 'active' : '' ?>"
        id="panel-settings"
    >

        <div class="panel-head">

            <h1>
                Settings
            </h1>

            <p>
                Control website content, notifications, and admin access.
            </p>

        </div>


        <div class="form-sections">

            <div class="form-section">

                <h3>
                    My Admin Profile
                </h3>

                <?php
                $currentAdminId = (int)($_SESSION['user_id'] ?? 0);
                $currentAdmin = null;

                if ($currentAdminId > 0) {
                    $profileStmt = $pdo->prepare("SELECT id, name, email FROM users WHERE id = ? AND role = 'admin' LIMIT 1");
                    $profileStmt->execute([$currentAdminId]);
                    $currentAdmin = $profileStmt->fetch();
                }

                $profileName = $currentAdmin['name'] ?? $adminName;
                $profileEmail = $currentAdmin['email'] ?? $adminEmail;
                ?>

                <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="update_admin_profile">

                    <div class="form-row-2">
                        <div class="form-group">
                            <label for="admin-profile-name">Full Name</label>
                            <input type="text" id="admin-profile-name" name="name" value="<?= e($profileName) ?>" required>
                        </div>

                        <div class="form-group">
                            <label for="admin-profile-email">Email Address</label>
                            <input type="email" id="admin-profile-email" name="email" value="<?= e($profileEmail) ?>" required>
                        </div>
                    </div>

                    <div class="form-row-2">
                        <div class="form-group">
                            <label for="admin-new-password">New Password</label>
                            <input type="password" id="admin-new-password" name="new_password" placeholder="Leave blank to keep current password" minlength="8">
                        </div>

                        <div class="form-group">
                            <label for="admin-confirm-password">Confirm New Password</label>
                            <input type="password" id="admin-confirm-password" name="confirm_password" placeholder="Repeat new password" minlength="8">
                        </div>
                    </div>

                    <div class="form-actions">
                        <button type="submit" class="btn btn--primary">Save Profile</button>
                    </div>
                </form>

            </div>

            <div class="form-section">

                <h3>
                    Contact Information
                </h3>

                <div class="form-row-2">

                    <div class="form-group">

                        <label>
                            WhatsApp Number
                        </label>

                        <input
                            type="tel"
                            value="+254 750 620 620"
                        >

                    </div>


                    <div class="form-group">

                        <label>
                            Email Address
                        </label>

                        <input
                            type="email"
                            value="info@husikaevents.org"
                        >

                    </div>

                </div>


                <div class="form-group">

                    <label>
                        Physical Address
                    </label>

                    <input
                        type="text"
                        value="Nairobi, Kenya"
                    >

                </div>

            </div>


            <div class="form-section">

                <h3>
                    Admin Accounts
                </h3>

                <table class="data-table">

                    <thead>

                    <tr>

                        <th>
                            Name
                        </th>

                        <th>
                            Email
                        </th>

                        <th>
                            Role
                        </th>

                        <th>
                            Last Login
                        </th>

                        <th>
                            Actions
                        </th>

                    </tr>

                    </thead>


                    <tbody>

                    <?php

                    $admins = $pdo
                        ->query("
                            SELECT
                                id,
                                name,
                                email,
                                role,
                                last_login
                            FROM users
                            WHERE role = 'admin'
                            ORDER BY id ASC
                        ")
                        ->fetchAll();

                    ?>


                    <?php foreach ($admins as $administrator): ?>

                        <tr>

                            <td>
                                <?= e($administrator['name']) ?>
                            </td>

                            <td>
                                <?= e($administrator['email']) ?>
                            </td>

                            <td>

                                <span class="tag tag--red">
                                    <?= e(
                                        ucfirst(
                                            $administrator['role']
                                        )
                                    ) ?>
                                </span>

                            </td>

                            <td>

                                <?php if (
                                    !empty(
                                        $administrator['last_login']
                                    )
                                ): ?>

                                    <?= date(
                                        'M d, Y H:i',
                                        strtotime(
                                            $administrator['last_login']
                                        )
                                    ) ?>

                                <?php else: ?>

                                    Never

                                <?php endif; ?>

                            </td>

                            <td class="actions-cell">

                                <button
                                    class="act-btn act-btn--edit"
                                    onclick="document.getElementById('adminEditId').value='<?=e($administrator['id']??'')?>';document.getElementById('adminEditName').value='<?=e($administrator['name']??'')?>';document.getElementById('adminEditEmail').value='<?=e($administrator['email']??'')?>';document.getElementById('adminEditModal').classList.add('active')"
                                >
                                    ✏️
                                </button>

                            </td>

                        </tr>

                    <?php endforeach; ?>

                    </tbody>

                </table>


                <button
                    type="button"
                    class="btn btn--outline-dark"
                    style="margin-top:12px"
                    onclick="openModal('modal-add-admin')"
                >
                    + Add Admin
                </button>

            </div>


            <div class="form-section">

                <h3>
                    Website Toggles
                </h3>


                <div class="toggle-list">


                    <div class="toggle-row">

                        <div>

                            <strong>
                                Show Reporting Form
                            </strong>

                            <p>
                                Enables the incident reporting form on the public site.
                            </p>

                        </div>

                        <label class="toggle-switch">

                            <input
                                type="checkbox"
                                checked
                            >

                            <span class="toggle-slider"></span>

                        </label>

                    </div>


                    <div class="toggle-row">

                        <div>

                            <strong>
                                Member Registration Open
                            </strong>

                            <p>
                                Allow new users to register on the site.
                            </p>

                        </div>

                        <label class="toggle-switch">

                            <input
                                type="checkbox"
                                checked
                            >

                            <span class="toggle-slider"></span>

                        </label>

                    </div>


                    <div class="toggle-row">

                        <div>

                            <strong>
                                Gallery Public
                            </strong>

                            <p>
                                Make the gallery tab visible to the public.
                            </p>

                        </div>

                        <label class="toggle-switch">

                            <input
                                type="checkbox"
                                checked
                            >

                            <span class="toggle-slider"></span>

                        </label>

                    </div>


                    <div class="toggle-row">

                        <div>

                            <strong>
                                Maintenance Mode
                            </strong>

                            <p>
                                Show a maintenance notice on the public site.
                            </p>

                        </div>

                        <label class="toggle-switch">

                            <input
                                type="checkbox"
                            >

                            <span class="toggle-slider"></span>

                        </label>

                    </div>

                </div>

            </div>


            <div class="form-section">
                <h3>Website & System Configuration</h3>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="save_site_settings">
                    <div class="form-row-2"><div class="form-group"><label>Website name</label><input name="website_name" value="<?=e(setting('website_name','Husika Events'))?>"></div><div class="form-group"><label>WhatsApp number</label><input name="whatsapp_number" value="<?=e(setting('whatsapp_number'))?>"></div></div>
                    <div class="form-row-2"><div class="form-group"><label>Email</label><input type="email" name="email" value="<?=e(setting('email'))?>"></div><div class="form-group"><label>Location</label><input name="location" value="<?=e(setting('location'))?>"></div></div>
                    <div class="form-row-2"><div class="form-group"><label>Social media</label><input name="social_media" value="<?=e(setting('social_media'))?>"></div><div class="form-group"><label>Emergency contact</label><input name="emergency_contact" value="<?=e(setting('emergency_contact'))?>"></div></div>
                    <div class="form-row-2"><div class="form-group"><label>SMTP host</label><input name="smtp_host" value="<?=e(setting('smtp_host'))?>" placeholder="smtp.gmail.com"></div><div class="form-group"><label>SMTP port</label><input name="smtp_port" value="<?=e(setting('smtp_port','587'))?>"></div></div>
                    <div class="form-row-2"><div class="form-group"><label>SMTP username</label><input name="smtp_username" value="<?=e(setting('smtp_username'))?>"></div><div class="form-group"><label>SMTP password</label><input type="password" name="smtp_password" value="<?=e(setting('smtp_password'))?>"></div></div>
                    <div class="form-row-2"><div class="form-group"><label>SMTP encryption</label><select name="smtp_encryption"><option value="tls" <?=setting('smtp_encryption')==='tls'?'selected':''?>>TLS</option><option value="ssl" <?=setting('smtp_encryption')==='ssl'?'selected':''?>>SSL</option><option value="none" <?=setting('smtp_encryption')==='none'?'selected':''?>>None</option></select></div><div class="form-group"><label>From email</label><input type="email" name="smtp_from_email" value="<?=e(setting('smtp_from_email'))?>"></div></div>
                    <div class="form-group"><label>From name</label><input name="smtp_from_name" value="<?=e(setting('smtp_from_name','Husika Events'))?>"></div>
                    <div class="form-actions"><button class="btn btn--primary">Save Website/SMTP Settings</button></div>
                    <hr><h4>Controls</h4>
                    <div class="form-row-2"><label><input type="checkbox" name="registration_enabled" value="1" <?=setting('registration_enabled','1')==='1'?'checked':''?>> Enable registration</label><label><input type="checkbox" name="reporting_enabled" value="1" <?=setting('reporting_enabled','1')==='1'?'checked':''?>> Enable reporting</label><label><input type="checkbox" name="gallery_enabled" value="1" <?=setting('gallery_enabled','1')==='1'?'checked':''?>> Enable gallery</label><label><input type="checkbox" name="gallery_approval_required" value="1" <?=setting('gallery_approval_required','1')==='1'?'checked':''?>> Require gallery approval</label><label><input type="checkbox" name="maintenance_mode" value="1" <?=setting('maintenance_mode')==='1'?'checked':''?>> Maintenance mode</label></div>
                </form>
            </div>

            <div class="form-section">
                <h3>Security & Two-Factor Authentication</h3>
                <p class="platform-muted">Strong passwords, login history, temporary lockout and 2FA should be enabled before going live.</p>
                <?php $two=$pdo->prepare("SELECT secret,enabled_at,recovery_codes FROM two_factor WHERE user_id=?");$two->execute([(int)$_SESSION['user_id']]);$twoRow=$two->fetch();$pending=$_SESSION['pending_2fa_secret']??''; ?>
                <?php if($twoRow && $twoRow['enabled_at']): ?><p>✅ Two-factor authentication is enabled.</p><form method="POST"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="disable_2fa"><button class="btn btn--outline-dark">Disable 2FA</button></form>
                <?php else: ?><form method="POST"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="enable_2fa"><button class="btn btn--primary">Generate 2FA Secret</button></form><?php endif; ?>
                <form method="POST" style="margin-top:10px"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="logout_all_sessions"><button class="btn btn--outline-dark">Log out all other sessions</button></form>
                <?php if($pending): ?><div class="security-box"><p>Scan this QR using Google/Microsoft Authenticator, then enter the 6-digit code.</p><div id="husikaQr"></div><p class="mini-code">Secret: <?=e($pending)?></p><form method="POST"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="verify_2fa"><input name="code" inputmode="numeric" maxlength="6" placeholder="123456" required><button class="btn btn--primary">Verify & Enable</button></form><p><strong>Recovery codes:</strong> <?php $rc=json_decode($twoRow['recovery_codes']??'[]',true)?:[]; if($pending && !$rc){$rc=[];} echo e(implode(' · ',$rc)); ?></p></div><script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script><script>new QRCode(document.getElementById('husikaQr'),{text:<?=json_encode('otpauth://totp/Husika%20Events:'.rawurlencode($adminEmail).'?secret='.$pending.'&issuer=Husika%20Events')?>,width:160,height:160});</script><?php endif; ?>
            </div>

            <div class="form-section">
                <h3>Administrator Permissions</h3>
                <?php foreach($admins as $administrator): $perQ=$pdo->prepare("SELECT permissions FROM admin_permissions WHERE admin_id=?");$perQ->execute([(int)$administrator['id']]);$perms=json_decode($perQ->fetchColumn()?:'[]',true)?:[]; ?>
                <form method="POST" class="platform-card" style="margin-bottom:10px"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="save_permissions"><input type="hidden" name="admin_id" value="<?=$administrator['id']?>"><strong><?=e($administrator['name'])?></strong><div class="form-row-2"><label><input type="checkbox" name="permissions[]" value="dashboard" <?=in_array('dashboard',$perms,true)?'checked':''?>> Dashboard</label><label><input type="checkbox" name="permissions[]" value="reports" <?=in_array('reports',$perms,true)?'checked':''?>> Reports</label><label><input type="checkbox" name="permissions[]" value="members" <?=in_array('members',$perms,true)?'checked':''?>> Members</label><label><input type="checkbox" name="permissions[]" value="activities" <?=in_array('activities',$perms,true)?'checked':''?>> Activities</label><label><input type="checkbox" name="permissions[]" value="gallery" <?=in_array('gallery',$perms,true)?'checked':''?>> Gallery</label><label><input type="checkbox" name="permissions[]" value="settings" <?=in_array('settings',$perms,true)?'checked':''?>> Settings</label></div><button class="btn btn--primary btn--sm">Save Permissions</button></form><?php endforeach; ?>
            </div>

            <div class="form-section">
                <h3>Database Backup & Restore</h3><p class="platform-muted">Backups are stored in the local <code>backups/</code> folder. Download a backup and keep an off-site copy before deployment.</p><form method="POST"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="create_backup"><button class="btn btn--primary">💾 Create Backup Now</button></form><div class="data-table-wrap" style="margin-top:12px"><table class="data-table"><tr><th>File</th><th>Size</th><th>Date</th><th>Action</th></tr><?php try{$backs=$pdo->query("SELECT * FROM backup_history ORDER BY id DESC LIMIT 20")->fetchAll();}catch(Throwable $e){$backs=[];}foreach($backs as $b):?><tr><td><?=e($b['filename'])?></td><td><?=number_format(((int)$b['size'])/1024,1)?> KB</td><td><?=e($b['created_at'])?></td><td><a class="btn btn--outline-dark btn--sm" href="<?=e(str_replace(__DIR__,'', $b['path']))?>" download>Download</a><form method="POST" style="display:inline"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="delete_backup"><input type="hidden" name="id" value="<?=$b['id']?>"><button class="act-btn act-btn--delete" onclick="return confirm('Delete this backup?')">Delete</button></form></td></tr><?php endforeach;?></table></div></div>

            <div class="form-actions">

                <button
                    class="btn btn--primary"
                    onclick="showToast('Settings saved successfully!')"
                >
                    Save Settings
                </button>

                <button class="btn btn--outline-dark">
                    Discard
                </button>

            </div>

        </div>

    </section>

<!-- =========================================================
     GLOBAL SEARCH
     ========================================================= -->
<section class="panel <?= $currentPanel === 'search' ? 'active' : '' ?>" id="panel-search">
<div class="panel-head"><h1>Global Search</h1><p>Search members, reports, activities, gallery records and administrators.</p></div>
<?php $searchQ=trim($_GET['q']??''); $searchResults=[]; if($searchQ!==''){ $like='%'.$searchQ.'%';
 foreach([['Members','users','id,name,email,role,status,created_at','name LIKE ? OR email LIKE ?'],['Reports','reports','id,report_number,incident_type,location,status,created_at','report_number LIKE ? OR incident_type LIKE ? OR location LIKE ?'],['Activities','activities','id,title,location,status,created_at','title LIKE ? OR location LIKE ?'],['Gallery','gallery','id,title,album,filename','title LIKE ? OR album LIKE ? OR filename LIKE ?'],['Administrators','users','id,name,email,role,status','role IN (\'admin\',\'social_worker\',\'content_manager\',\'moderator\',\'staff\') AND (name LIKE ? OR email LIKE ?)']] as $cfg){try{$where=$cfg[3];$params=array_fill(0,substr_count($where,'?'),$like);$st=$pdo->prepare("SELECT {$cfg[2]} FROM {$cfg[1]} WHERE {$where} ORDER BY id DESC LIMIT 25");$st->execute($params);foreach($st as $row)$searchResults[]=['type'=>$cfg[0],'row'=>$row];}catch(Throwable $e){}}
} ?>
<form method="GET" class="form-row-2"><input type="hidden" name="panel" value="search"><input name="q" value="<?=e($searchQ)?>" placeholder="Search members, reports, activities, gallery..."><button class="btn btn--primary" type="submit">🔎 Search</button></form>
<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Type</th><th>Record</th><th>Status</th><th>Date</th></tr></thead><tbody>
<?php foreach($searchResults as $r): $row=$r['row']; ?><tr><td><?=e($r['type'])?></td><td><strong><?=e($row['name']??$row['title']??$row['report_number']??$row['incident_type']??$row['filename']??'Record #'.$row['id'])?></strong><br><small><?=e($row['email']??$row['location']??$row['album']??'')?></small></td><td><?=e($row['status']??'—')?></td><td><?=e($row['created_at']??'—')?></td></tr><?php endforeach; ?>
<?php if(!$searchResults): ?><tr><td colspan="4">Enter a search term to see results.</td></tr><?php endif; ?></tbody></table></div>
</section>

<!-- =========================================================
     AUDIT LOG
     ========================================================= -->
<section class="panel <?= $currentPanel === 'audit' ? 'active' : '' ?>" id="panel-audit">
<div class="panel-head"><h1>Audit Log</h1><p>See who changed what, when and from which IP address.</p></div>
<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Admin</th><th>Action</th><th>Module</th><th>Record</th><th>IP</th><th>Date</th></tr></thead><tbody>
<?php try{$auditRows=$pdo->query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")->fetchAll();}catch(Throwable $e){$auditRows=[];} foreach($auditRows as $a): ?><tr><td><?=e($a['admin_name'])?></td><td><?=e($a['action'])?></td><td><?=e($a['module'])?></td><td><?=e($a['record_id']??'—')?></td><td><?=e($a['ip_address'])?></td><td><?=e($a['created_at'])?></td></tr><?php endforeach; if(!$auditRows): ?><tr><td colspan="6">No audit entries yet.</td></tr><?php endif; ?></tbody></table></div>
</section>

</main>

<style>
/* Added platform controls */
.platform-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin:18px 0}.platform-card{padding:18px;border:1px solid #e5e7eb;border-radius:12px;background:#fff}.platform-card h3{margin:0 0 8px}.platform-muted{color:#667085;font-size:13px}.security-box{padding:16px;border:1px solid #ddd;border-radius:10px;background:#fafafa;margin-top:12px}.mini-code{font-family:monospace;letter-spacing:2px;word-break:break-all}.new-panel-note{padding:12px;border-radius:8px;background:#f4f8f5;margin-bottom:16px}
</style>

<!-- ADMIN EDIT MODAL -->
<div class="modal-overlay" id="adminEditModal"><div class="modal"><div class="modal-head"><h3>Edit Administrator</h3><button type="button" onclick="document.getElementById('adminEditModal').classList.remove('active')">×</button></div><form method="POST"><input type="hidden" name="csrf_token" value="<?=e(csrf_token())?>"><input type="hidden" name="action" value="update_other_admin"><input type="hidden" name="id" id="adminEditId"><div class="form-group"><label>Name</label><input name="name" id="adminEditName" required></div><div class="form-group"><label>Email</label><input type="email" name="email" id="adminEditEmail" required></div><div class="form-group"><label>New password (optional)</label><input type="password" name="password" minlength="10"></div><div class="form-actions"><button class="btn btn--primary">Save Administrator</button></div></form></div></div>

<!-- =========================================================
     MODAL: ADD ACTIVITY
     ========================================================= -->

<div
    class="modal-overlay"
    id="modal-add-activity"
>

    <div class="modal">

        <div class="modal-head">

            <h2>
                Add New Activity
            </h2>

            <button
                class="modal-close"
                onclick="closeModal('modal-add-activity')"
            >
                ✕
            </button>

        </div>


        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

            <input
                type="hidden"
                name="action"
                value="add_activity"
            >


            <div class="form-group">

                <label>
                    Activity Title *
                </label>

                <input
                    type="text"
                    name="title"
                    placeholder="e.g. Safe Touch Workshop"
                    required
                >

            </div>


            <div class="form-row-2">

                <div class="form-group">

                    <label>
                        Group *
                    </label>

                    <select
                        name="group_name"
                        required
                    >

                        <option value="">
                            Select group
                        </option>

                        <option>
                            Children
                        </option>

                        <option>
                            Youth
                        </option>

                        <option>
                            Families
                        </option>

                        <option>
                            Education
                        </option>

                    </select>

                </div>


                <div class="form-group">

                    <label>
                        Season
                    </label>

                    <select name="season">

                        <option>
                            School Term
                        </option>

                        <option>
                            Holiday
                        </option>

                        <option>
                            Year-round
                        </option>

                    </select>

                </div>

            </div>


            <div class="form-row-2">

                <div class="form-group">

                    <label>
                        Schedule
                    </label>

                    <input
                        type="text"
                        name="schedule"
                        placeholder="e.g. Every 2nd Saturday"
                    >

                </div>


                <div class="form-group">

                    <label>
                        Location
                    </label>

                    <input
                        type="text"
                        name="location"
                        placeholder="e.g. Nairobi Centre"
                    >

                </div>

            </div>


            <div class="form-group">

                <label>
                    Description
                </label>

                <textarea
                    rows="4"
                    name="description"
                    placeholder="Describe this activity..."
                ></textarea>

            </div>


            <div class="form-group">

                <label>
                    Status
                </label>

                <select name="status">

                    <option>
                        Active
                    </option>

                    <option>
                        Draft
                    </option>

                    <option>
                        Archived
                    </option>

                </select>

            </div>


            <div class="modal-foot">

                <button
                    type="button"
                    class="btn btn--outline-dark"
                    onclick="closeModal('modal-add-activity')"
                >
                    Cancel
                </button>

                <button
                    type="submit"
                    class="btn btn--primary"
                >
                    Save Activity
                </button>

            </div>

        </form>

    </div>

</div>


<!-- =========================================================
     MODAL: ADD MEMBER
     ========================================================= -->

<div
    class="modal-overlay"
    id="modal-add-member"
>

    <div class="modal">

        <div class="modal-head">

            <h2>
                Add New Member
            </h2>

            <button
                class="modal-close"
                onclick="closeModal('modal-add-member')"
            >
                ✕
            </button>

        </div>


        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

            <input
                type="hidden"
                name="action"
                value="add_member"
            >


            <div class="form-row-2">

                <div class="form-group">

                    <label>
                        First Name *
                    </label>

                    <input
                        type="text"
                        name="first_name"
                        placeholder="Jane"
                        required
                    >

                </div>


                <div class="form-group">

                    <label>
                        Last Name *
                    </label>

                    <input
                        type="text"
                        name="last_name"
                        placeholder="Wanjiku"
                        required
                    >

                </div>

            </div>


            <div class="form-group">

                <label>
                    Email Address
                </label>

                <input
                    type="email"
                    name="email"
                    placeholder="jane@email.com"
                >

            </div>


            <div class="form-group">

                <label>
                    WhatsApp / Phone *
                </label>

                <input
                    type="tel"
                    name="phone"
                    placeholder="+254 ..."
                    required
                >

            </div>


            <div class="form-row-2">

                <div class="form-group">

                    <label>
                        Group *
                    </label>

                    <select
                        name="group_name"
                        required
                    >

                        <option value="">
                            Select group
                        </option>

                        <option>
                            Children's Group (5–12)
                        </option>

                        <option>
                            Youth Department (13–25)
                        </option>

                        <option>
                            Families & Parents
                        </option>

                        <option>
                            Volunteer / Supporter
                        </option>

                    </select>

                </div>


                <div class="form-group">

                    <label>
                        Status
                    </label>

                    <select name="status">

                        <option value="active">
                            Active
                        </option>

                        <option value="pending">
                            Pending
                        </option>

                        <option value="suspended">
                            Suspended
                        </option>

                    </select>

                </div>

            </div>


            <div class="modal-foot">

                <button
                    type="button"
                    class="btn btn--outline-dark"
                    onclick="closeModal('modal-add-member')"
                >
                    Cancel
                </button>

                <button
                    type="submit"
                    class="btn btn--primary"
                >
                    Add Member
                </button>

            </div>

        </form>

    </div>

</div>


<!-- =========================================================
     MODAL: ADD ADMIN
     ========================================================= -->
<div
    class="modal-overlay"
    id="modal-add-admin"
>
    <div class="modal">
        <div class="modal-head">
            <h2>Add New Administrator</h2>
            <button type="button" class="modal-close" onclick="closeModal('modal-add-admin')">✕</button>
        </div>

        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="add_admin">

            <div class="form-group">
                <label for="new-admin-name">Full Name *</label>
                <input type="text" id="new-admin-name" name="name" placeholder="Administrator name" required>
            </div>

            <div class="form-group">
                <label for="new-admin-email">Email Address *</label>
                <input type="email" id="new-admin-email" name="email" placeholder="admin@example.com" required>
            </div>

            <div class="form-group">
                <label for="new-admin-password">Password *</label>
                <input type="password" id="new-admin-password" name="password" placeholder="Minimum 8 characters" minlength="8" required>
            </div>

            <div class="form-group">
                <label for="new-admin-status">Status</label>
                <select id="new-admin-status" name="status">
                    <option value="active">Active</option>
                    <option value="pending">Pending</option>
                    <option value="suspended">Suspended</option>
                </select>
            </div>

            <div class="modal-foot">
                <button type="button" class="btn btn--outline-dark" onclick="closeModal('modal-add-admin')">Cancel</button>
                <button type="submit" class="btn btn--primary">Add Administrator</button>
            </div>
        </form>
    </div>
</div>


<!-- =========================================================
     MODAL: ADD ALBUM
     ========================================================= -->

<div
    class="modal-overlay"
    id="modal-add-album"
>

    <div
        class="modal"
        style="max-width:420px"
    >

        <div class="modal-head">

            <h2>
                Create New Album
            </h2>

            <button
                class="modal-close"
                onclick="closeModal('modal-add-album')"
            >
                ✕
            </button>

        </div>


        <form
            onsubmit="submitAlbum(event)"
        >

            <div class="form-group">

                <label>
                    Album Name *
                </label>

                <input
                    type="text"
                    placeholder="e.g. Events 2025"
                    required
                >

            </div>


            <div class="form-group">

                <label>
                    Description
                </label>

                <textarea
                    rows="3"
                    placeholder="Brief description..."
                ></textarea>

            </div>


            <div class="modal-foot">

                <button
                    type="button"
                    class="btn btn--outline-dark"
                    onclick="closeModal('modal-add-album')"
                >
                    Cancel
                </button>

                <button
                    type="submit"
                    class="btn btn--primary"
                >
                    Create Album
                </button>

            </div>

        </form>

    </div>

</div>


<!-- =========================================================
     CONFIRM DELETE
     ========================================================= -->

<div
    class="modal-overlay"
    id="modal-confirm-delete"
>

    <div
        class="modal"
        style="
            max-width:400px;
            text-align:center
        "
    >

        <div
            style="
                font-size:48px;
                margin-bottom:12px
            "
        >
            🗑️
        </div>


        <h2
            style="
                margin-bottom:8px
            "
        >
            Delete this item?
        </h2>


        <p
            style="
                color:var(--text-muted);
                margin-bottom:24px
            "
        >
            This action cannot be undone.
        </p>


        <div
            style="
                display:flex;
                gap:12px;
                justify-content:center
            "
        >

            <button
                class="btn btn--outline-dark"
                onclick="closeModal('modal-confirm-delete')"
            >
                Cancel
            </button>

            <button
                class="btn"
                style="
                    background:var(--red);
                    color:#fff;
                    border-color:var(--red)
                "
                onclick="executeDelete()"
            >
                Yes, Delete
            </button>

        </div>

    </div>

</div>


<!-- TOAST -->

<div
    class="toast"
    id="toast"
></div>


<script src="admin.js"></script>


<script>

/*
|--------------------------------------------------------------------------
| DATE
|--------------------------------------------------------------------------
*/

document.addEventListener(
    'DOMContentLoaded',
    function () {

        const dateElement =
            document.getElementById('topbar-date');

        if (dateElement) {

            const now = new Date();

            dateElement.textContent =
                now.toLocaleDateString(
                    'en-KE',
                    {
                        weekday: 'long',
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    }
                );
        }

    }
);


/*
|--------------------------------------------------------------------------
| PANEL SWITCHING
|--------------------------------------------------------------------------
*/

function switchPanel(panel) {

    window.location.href =
        'admin.php?panel=' +
        encodeURIComponent(panel);
}


/*
|--------------------------------------------------------------------------
| MODALS
|--------------------------------------------------------------------------
*/

function openModal(id) {

    const modal =
        document.getElementById(id);

    if (modal) {
        modal.classList.add('active');
    }
}


function closeModal(id) {

    const modal =
        document.getElementById(id);

    if (modal) {
        modal.classList.remove('active');
    }
}


/*
|--------------------------------------------------------------------------
| TOAST
|--------------------------------------------------------------------------
*/

function showToast(message) {

    const toast =
        document.getElementById('toast');

    if (!toast) {
        return;
    }

    toast.textContent = message;

    toast.classList.add('show');

    setTimeout(
        function () {
            toast.classList.remove('show');
        },
        3000
    );
}


/*
|--------------------------------------------------------------------------
| ACTIVITY FILTER
|--------------------------------------------------------------------------
*/

function filterActivities() {

    const group =
        document.getElementById(
            'act-filter-group'
        )?.value.toLowerCase() || '';

    const season =
        document.getElementById(
            'act-filter-season'
        )?.value.toLowerCase() || '';

    const search =
        document.getElementById(
            'act-search'
        )?.value.toLowerCase() || '';

    const rows =
        document.querySelectorAll(
            '#activities-table tbody tr'
        );

    rows.forEach(
        function (row) {

            const rowGroup =
                (row.dataset.group || '')
                .toLowerCase();

            const rowSeason =
                (row.dataset.season || '')
                .toLowerCase();

            const text =
                row.textContent.toLowerCase();

            const groupMatch =
                !group ||
                rowGroup === group;

            const seasonMatch =
                !season ||
                rowSeason === season;

            const searchMatch =
                !search ||
                text.includes(search);

            row.style.display =
                groupMatch &&
                seasonMatch &&
                searchMatch
                    ? ''
                    : 'none';
        }
    );
}


/*
|--------------------------------------------------------------------------
| MEMBER SEARCH
|--------------------------------------------------------------------------
*/

function filterMembers(value = '') {

    value =
        value.toLowerCase();

    const rows =
        document.querySelectorAll(
            '#members-table tbody tr'
        );

    rows.forEach(
        function (row) {

            const text =
                row.textContent.toLowerCase();

            row.style.display =
                !value ||
                text.includes(value)
                    ? ''
                    : 'none';
        }
    );
}


/*
|--------------------------------------------------------------------------
| DELETE PLACEHOLDER
|--------------------------------------------------------------------------
*/

function confirmDelete(element) {

    window.deleteTarget =
        element;

    openModal(
        'modal-confirm-delete'
    );
}


function executeDelete() {

    if (
        window.deleteTarget &&
        window.deleteTarget.remove
    ) {

        window.deleteTarget.remove();

        showToast(
            'Item deleted.'
        );
    }

    closeModal(
        'modal-confirm-delete'
    );
}


/*
|--------------------------------------------------------------------------
| ALBUM
|--------------------------------------------------------------------------
*/

function submitAlbum(event) {

    event.preventDefault();

    closeModal(
        'modal-add-album'
    );

    showToast(
        'Album created successfully!'
    );
}


/*
|--------------------------------------------------------------------------
| SIDEBAR
|--------------------------------------------------------------------------
*/

const sidebarToggle =
    document.getElementById(
        'sidebar-toggle'
    );

const sidebar =
    document.getElementById(
        'sidebar'
    );

if (sidebarToggle && sidebar) {

    sidebarToggle.addEventListener(
        'click',
        function () {

            sidebar.classList.toggle(
                'open'
            );

        }
    );
}


/*
|--------------------------------------------------------------------------
| CLOSE MODALS WHEN CLICKING OUTSIDE
|--------------------------------------------------------------------------
*/

document.querySelectorAll(
    '.modal-overlay'
).forEach(
    function (overlay) {

        overlay.addEventListener(
            'click',
            function (event) {

                if (
                    event.target === overlay
                ) {

                    overlay.classList.remove(
                        'active'
                    );
                }

            }
        );

    }
);


/*
|--------------------------------------------------------------------------
| DRAG AND DROP GALLERY
|--------------------------------------------------------------------------
*/
const dropZone = document.getElementById('drop-zone');
const galleryFileInput = document.getElementById('gallery-file-input');
const galleryUploadForm = document.getElementById('gallery-upload-form');

if (dropZone && galleryFileInput && galleryUploadForm) {

    dropZone.addEventListener('click', function () {
        galleryFileInput.click();
    });

    dropZone.addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            galleryFileInput.click();
        }
    });

    ['dragenter', 'dragover'].forEach(function (eventName) {
        dropZone.addEventListener(eventName, function (event) {
            event.preventDefault();
            event.stopPropagation();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'dragend'].forEach(function (eventName) {
        dropZone.addEventListener(eventName, function (event) {
            event.preventDefault();
            event.stopPropagation();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', function (event) {
        event.preventDefault();
        event.stopPropagation();
        dropZone.classList.remove('dragover');

        const files = Array.from(event.dataTransfer.files || []);

        if (!files.length) return;

        const validFiles = files.filter(function (file) {
            const validType = [
                'image/jpeg',
                'image/png',
                'image/webp',
                'image/gif'
            ].includes(file.type);

            const validSize = file.size <= 10 * 1024 * 1024;
            return validType && validSize;
        });

        if (!validFiles.length) {
            showToast('Please drop valid image files. Maximum size is 10 MB per image.');
            return;
        }

        try {
            const dataTransfer = new DataTransfer();

            validFiles.forEach(function (file) {
                dataTransfer.items.add(file);
            });

            galleryFileInput.files = dataTransfer.files;
            galleryUploadForm.submit();
        } catch (error) {
            console.error('Gallery drag-and-drop upload error:', error);
            showToast('Unable to process the dropped files. Please use Upload Images.');
        }
    });
}


    function filterReports() {
        const q = (document.getElementById('reportSearch')?.value || '').toLowerCase();
        const priority = document.getElementById('reportPriorityFilter')?.value || '';
        const status = document.getElementById('reportStatusFilter')?.value || '';
        document.querySelectorAll('#reportsList .report-card').forEach(card => {
            const matchQ = !q || (card.dataset.reportSearch || '').includes(q);
            const matchP = !priority || card.dataset.priority === priority;
            const matchS = !status || card.dataset.status === status;
            card.style.display = matchQ && matchP && matchS ? '' : 'none';
        });
    }

    function printReport(id) {
        const card = document.querySelector('.report-card[data-report-id="' + id + '"]');
        if (!card) return window.print();
        const win = window.open('', '_blank', 'width=900,height=700');
        win.document.write('<html><head><title>Husika Incident Report</title><style>body{font-family:Arial;padding:30px}button,form,summary{display:none!important}.report-card{border:1px solid #ccc;padding:20px}.report-meta{margin:12px 0}</style></head><body>' + card.innerHTML + '</body></html>');
        win.document.close(); win.focus(); win.print();
    }
</script>

<script>
(function(){
 const d={types:{l:<?=json_encode($reportTypeLabels)?>,v:<?=json_encode($reportTypeValues)?>},months:{l:<?=json_encode($reportMonthLabels)?>,v:<?=json_encode($reportMonthValues)?>},members:{l:<?=json_encode($memberMonthLabels)?>,v:<?=json_encode($memberMonthValues)?>},activity:{l:<?=json_encode($activityLabels)?>,v:<?=json_encode($activityParticipationValues)?>}};
 const mk=(id,type,labels,values,opts={})=>{const el=document.getElementById(id);if(!el||typeof Chart==='undefined')return;new Chart(el,{type,data:{labels:labels.length?labels:['No data'],datasets:[{label:'',data:values.length?values:[0],tension:.35,fill:type==='line',borderWidth:1}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:type==='doughnut'?undefined:{y:{beginAtZero:true,ticks:{precision:0}}},...opts}})};
 mk('reportTypeChart','doughnut',d.types.l,d.types.v,{plugins:{legend:{position:'bottom'}}});
 mk('reportMonthChart','line',d.months.l,d.months.v);
 mk('memberChart','bar',d.members.l,d.members.v);
 mk('activityChart','bar',d.activity.l,d.activity.v,{indexAxis:'y'});
 const extra={l:<?=json_encode($attendanceLabels)?>,v:<?=json_encode($attendanceValues)?>}; const res={l:<?=json_encode($resolutionLabels)?>,v:<?=json_encode($resolutionValues)?>}; mk('attendanceChart','bar',extra.l,extra.v); mk('resolutionChart','doughnut',res.l,res.v,{plugins:{legend:{position:'bottom'}}});
})();
</script>
</body>
</html>