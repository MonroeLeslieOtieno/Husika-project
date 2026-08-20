<?php
/* Minimal authenticated SMTP sender for Husika Events. Configure SMTP in Admin > Settings. */
function smtp_setting($key,$default=''){ global $pdo; try{$q=$pdo->prepare('SELECT setting_value FROM site_settings WHERE setting_key=?');$q->execute([$key]);$v=$q->fetchColumn();return $v===false?$default:$v;}catch(Throwable $e){return $default;} }
function smtp_send($to,$subject,$body){
    $host=smtp_setting('smtp_host'); $port=(int)smtp_setting('smtp_port','587'); $user=smtp_setting('smtp_username'); $pass=smtp_setting('smtp_password'); $enc=smtp_setting('smtp_encryption','tls'); $from=smtp_setting('smtp_from_email',$user); $fromName=smtp_setting('smtp_from_name','Husika Events');
    if(!$host || !$from) return false;
    $transport=$enc==='ssl'?'ssl://'.$host:$host;
    $fp=@stream_socket_client($transport.':'.$port,$errno,$errstr,15,STREAM_CLIENT_CONNECT);
    if(!$fp) return false;
    stream_set_timeout($fp,15);
    $read=function()use($fp){$out='';while(($line=fgets($fp,515))!==false){$out.=$line;if(isset($line[3])&&$line[3]===' ')break;}return $out;};
    $write=function($cmd)use($fp,$read){fwrite($fp,$cmd."\r\n");$r=$read();return $r;};
    $read();$write('EHLO husikaevents.org');
    if($enc==='tls'){$r=$write('STARTTLS');if(strpos($r,'220')===false){fclose($fp);return false;}if(!stream_socket_enable_crypto($fp,true,STREAM_CRYPTO_METHOD_TLS_CLIENT)){fclose($fp);return false;}$write('EHLO husikaevents.org');}
    if($user){if(strpos($write('AUTH LOGIN'),'334')===false){fclose($fp);return false;}if(strpos($write(base64_encode($user)),'334')===false){fclose($fp);return false;}if(strpos($write(base64_encode($pass)),'235')===false){fclose($fp);return false;}}
    if(strpos($write('MAIL FROM:<'.$from.'>'),'250')===false){fclose($fp);return false;}
    if(strpos($write('RCPT TO:<'.$to.'>'),'250')===false){fclose($fp);return false;}
    if(strpos($write('DATA'),'354')===false){fclose($fp);return false;}
    $headers='From: '.mb_encode_mimeheader($fromName).' <'.$from.'>\r\nTo: <'.$to.'>\r\nSubject: '.mb_encode_mimeheader($subject).'\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n';
    fwrite($fp,$headers."\r\n".$body."\r\n.\r\n");$ok=strpos($read(),'250')!==false;$write('QUIT');fclose($fp);return $ok;
}
