<?php
$secureCookie=!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off';
session_set_cookie_params(['lifetime'=>0,'path'=>'/','secure'=>$secureCookie,'httponly'=>true,'samesite'=>'Lax']);
session_start();
require_once 'database.php';

function h($v){return htmlspecialchars((string)$v,ENT_QUOTES,'UTF-8');}
function site_setting_login($key,$default=''){try{global $pdo;$q=$pdo->prepare('SELECT setting_value FROM site_settings WHERE setting_key=?');$q->execute([$key]);$v=$q->fetchColumn();return $v===false?$default:$v;}catch(Throwable $e){return $default;}}
function strong_password($p){return strlen($p)>=10&&preg_match('/[A-Z]/',$p)&&preg_match('/[a-z]/',$p)&&preg_match('/\d/',$p)&&preg_match('/[^A-Za-z0-9]/',$p);}
function b32d($s){$a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';$bits='';foreach(str_split(strtoupper($s)) as $c){$i=strpos($a,$c);if($i===false)continue;$bits.=str_pad(decbin($i),5,'0',STR_PAD_LEFT);} $o='';for($i=0;$i+8<=strlen($bits);$i+=8)$o.=chr(bindec(substr($bits,$i,8)));return $o;}
function totp($secret,$time=null){$key=b32d($secret);$counter=pack('N*',0).pack('N*',intdiv($time??time(),30));$h=hash_hmac('sha1',$counter,$key,true);$o=ord($h[19])&15;$b=((ord($h[$o])&127)<<24)|((ord($h[$o+1])&255)<<16)|((ord($h[$o+2])&255)<<8)|(ord($h[$o+3])&255);return str_pad((string)($b%1000000),6,'0',STR_PAD_LEFT);}

if(empty($_SESSION['csrf_token']))$_SESSION['csrf_token']=bin2hex(random_bytes(32));
$error='';$success='';
if(isset($_GET['logout'])){session_unset();session_destroy();header('Location: login.php');exit;}
if(isset($_GET['reset'])&&$_GET['reset']==='1')$success='If the account exists, password reset instructions have been sent.';

if($_SERVER['REQUEST_METHOD']==='POST' && ($_POST['form_type']??'')==='login'){
    if(!hash_equals($_SESSION['csrf_token']??'',$_POST['csrf_token']??'')){http_response_code(403);exit('Invalid security token.');}
    $email=strtolower(trim($_POST['email']??''));$password=$_POST['password']??'';$ip=$_SERVER['REMOTE_ADDR']??'unknown';
    $max=(int)site_setting_login('login_rate_limit','5');$lock=(int)site_setting_login('login_lock_minutes','15');
    $a=$pdo->prepare('SELECT * FROM login_attempts WHERE email=? AND ip_address=? LIMIT 1');$a->execute([$email,$ip]);$attempt=$a->fetch();
    if($attempt && !empty($attempt['locked_until']) && strtotime($attempt['locked_until'])>time())$error='Too many failed attempts. Please try again later.';
    else{
        $q=$pdo->prepare('SELECT * FROM users WHERE email=? LIMIT 1');$q->execute([$email]);$u=$q->fetch();$valid=$u&&$u['status']==='active'&&password_verify($password,$u['password_hash']);
        $pdo->prepare('INSERT INTO login_history(user_id,email,success,ip_address,user_agent) VALUES(?,?,?,?,?)')->execute([$u['id']??null,$email,$valid?1:0,$ip,$_SERVER['HTTP_USER_AGENT']??'']);
        if(!$valid){
            $count=($attempt['attempts']??0)+1;$locked=$count>=$max?date('Y-m-d H:i:s',time()+$lock*60):null;
            $pdo->prepare("INSERT INTO login_attempts(email,ip_address,attempts,locked_until,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(email,ip_address) DO UPDATE SET attempts=excluded.attempts,locked_until=excluded.locked_until,updated_at=CURRENT_TIMESTAMP")->execute([$email,$ip,$count,$locked]);
            $error=$locked?'Too many failed attempts. Account temporarily locked.':'Invalid email or password.';
        }else{
            $pdo->prepare('DELETE FROM login_attempts WHERE email=? AND ip_address=?')->execute([$email,$ip]);
            if(!empty($u['must_reset_password'])){$_SESSION['reset_user_id']=$u['id'];header('Location: reset-password.php?forced=1');exit;}
            session_regenerate_id(true);$_SESSION['user_id']=$u['id'];$_SESSION['name']=$u['name'];$_SESSION['email']=$u['email'];$_SESSION['role']=$u['role'];$_SESSION['session_version']=(int)($u['session_version']??1);$_SESSION['logged_in']=true;
            $pdo->prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?')->execute([$u['id']]);
            if(!empty($u['two_factor_enabled'])){$_SESSION['2fa_pending_user']=$u['id'];$_SESSION['2fa_pending_role']=$u['role'];$_SESSION['2fa_pending_name']=$u['name'];$_SESSION['logged_in']=false;header('Location: verify-2fa.php');exit;}
            header('Location: '.($u['role']==='admin'?'admin.php':'dashboard.php'));exit;
        }
    }
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login / Join | Husika Events"><link rel="stylesheet" href="styles.css"><style>.login-page{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f2;padding:20px}.login-card{width:100%;max-width:430px;background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 35px rgba(0,0,0,.08)}.login-card input{width:100%;padding:13px;border:1px solid #ccc;border-radius:6px;margin:7px 0 16px}.login-card button{width:100%;padding:14px;border:0;border-radius:6px;background:#111;color:#fff;font-weight:700}.error{background:#ffe8e8;color:#900;padding:12px;border-radius:6px;margin-bottom:16px}.success{background:#e8f5ec;color:#185b2a;padding:12px;border-radius:6px;margin-bottom:16px}</style></head><body><div class="login-page"><div class="login-card"><h1>Husika EVENTS</h1><p>Give Hope · Give Love · Give Back</p><h2>Member Login</h2><?php if($error):?><div class="error"><?=h($error)?></div><?php endif;?><?php if($success):?><div class="success"><?=h($success)?></div><?php endif;?><form method="POST"><input type="hidden" name="csrf_token" value="<?=h($_SESSION['csrf_token'])?>"><input type="hidden" name="form_type" value="login"><label>Email Address</label><input type="email" name="email" value="<?=h($_POST['email']??'')?>" required><label>Password</label><input type="password" name="password" required><button type="submit">Log In</button></form><p style="text-align:right;margin-top:12px"><a href="forgot-password.php">Forgot password?</a></p><p style="text-align:center"><a href="index.php">← Back to Husika Events</a></p></div></div></body></html>
