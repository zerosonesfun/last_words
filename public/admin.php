<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/autoload.php';
require dirname(__DIR__) . '/src/Web.php';

use LastWords\Backup;
use LastWords\Keys;
use LastWords\Log;
use LastWords\UserError;

$app = require_app();
start_session();
$notice = '';
$error = '';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    require_secure_mutation();
    $action = (string) ($_POST['action'] ?? '');
    try {
        if ($action === 'login') {
            if (!$app->rates->allow('login:' . client_ip(), 5, 900)) {
                throw new UserError('Too many sign-in attempts. Wait and try again.');
            }
            $row = $app->storage->one('SELECT password_hash FROM admin_auth WHERE id = 1');
            $password = (string) ($_POST['password'] ?? '');
            if ($row === null || !password_verify($password, (string) $row['password_hash'])) {
                $app->messages->noteFailure('login', 'Rejected an admin sign-in.');
                throw new UserError('The password was not accepted.');
            }
            session_regenerate_id(true);
            $_SESSION['admin'] = 1;
            $_SESSION['csrf'] = bin2hex(random_bytes(16));
        } elseif ($action === 'reset') {
            if (!$app->rates->allow('reset:' . client_ip(), 5, 900)) {
                throw new UserError('Too many reset attempts. Wait and try again.');
            }
            $row = $app->storage->one('SELECT reset_hash FROM admin_auth WHERE id = 1');
            $token = (string) ($_POST['reset_token'] ?? '');
            if ($row === null || !password_verify($token, (string) $row['reset_hash'])) {
                throw new UserError('The reset token was not accepted.');
            }
            $password = Keys::token(10);
            $reset = Keys::token(10);
            $app->storage->run(
                'UPDATE admin_auth SET password_hash = ?, reset_hash = ? WHERE id = 1',
                [password_hash($password, PASSWORD_DEFAULT), password_hash($reset, PASSWORD_DEFAULT)]
            );
            $notice = "New admin password: {$password}\nNew reset token: {$reset}\nSave both. They will not be shown again.";
        } elseif ($action === 'logout') {
            $_SESSION = [];
            session_destroy();
        } else {
            if (empty($_SESSION['admin']) || !csrf_ok()) {
                throw new UserError('The form expired. Reload the page.');
            }
            if ($action === 'password') {
                $next = (string) ($_POST['new_password'] ?? '');
                if (strlen($next) < 12) {
                    throw new UserError('Use at least 12 characters.');
                }
                $app->storage->run('UPDATE admin_auth SET password_hash = ? WHERE id = 1', [password_hash($next, PASSWORD_DEFAULT)]);
                $notice = 'Password updated.';
            } elseif ($action === 'cron') {
                $config = $app->config;
                $config['cron_key'] = Keys::token(24);
                $app->writeConfig($config);
                $notice = "New cron key:\n" . $config['cron_key'] . "\n\ncurl -fsS -X POST -d \"key=" . $config['cron_key'] . '" ' . $config['public_url'] . "/cron.php";
            } elseif ($action === 'rotate') {
                $public = $app->rotateServiceKey();
                $notice = "New service public key:\n" . $public;
            } elseif ($action === 'peer') {
                $parsed = $app->network->trustPeer((string) ($_POST['endpoint'] ?? ''));
                $notice = 'Pinned peer ' . $parsed['endpoint'] . '.';
            } elseif ($action === 'backup') {
                $bytes = $app->backup((string) ($_POST['backup_password'] ?? ''));
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="last-words-backup.bin"');
                header('Cache-Control: no-store');
                header('X-Content-Type-Options: nosniff');
                echo $bytes;
                exit;
            } elseif ($action === 'restore') {
                if (($_POST['confirm'] ?? '') !== 'RESTORE') {
                    throw new UserError('Type RESTORE to confirm.');
                }
                $upload = $_FILES['archive'] ?? null;
                if (!is_array($upload) || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                    throw new UserError('Choose a backup file.');
                }
                if (($upload['size'] ?? 0) > 20000000) {
                    throw new UserError('That backup is too large.');
                }
                $archive = file_get_contents((string) $upload['tmp_name']);
                if ($archive === false) {
                    throw new UserError('Could not read the backup.');
                }
                Backup::restore($app->dataDir, (string) ($_POST['backup_password'] ?? ''), $archive);
                $notice = 'Restore finished. Reload this page so the service reads the restored files.';
            } else {
                throw new UserError('Unknown action.');
            }
        }
    } catch (UserError $caught) {
        $error = $caught->getMessage();
    } catch (Throwable $caught) {
        Log::error($app->dataDir, $caught);
        $error = 'Something went wrong.';
    }
}

if (empty($_SESSION['admin'])) {
    $body = '<h1>Admin</h1>';
    if ($error !== '') {
        $body .= '<p class="note">' . e($error) . '</p>';
    }
    if ($notice !== '') {
        $body .= '<pre>' . e($notice) . '</pre>';
    }
    $body .= '<form method="post"><input type="hidden" name="action" value="login">';
    $body .= '<label>Password<input type="password" name="password" required></label>';
    $body .= '<button type="submit">Sign in</button></form>';
    $body .= '<h2>Lost password</h2><form method="post"><input type="hidden" name="action" value="reset">';
    $body .= '<label>Reset token<input type="password" name="reset_token" required></label>';
    $body .= '<button type="submit">Create a new password</button></form>';
    render_page('Admin', $body);
    exit;
}

$status = $app->status();
$csrf = e(csrf_token());
$when = static function (?string $value): string {
    if ($value === null || $value === '') {
        return 'not yet';
    }
    return gmdate('j F Y, H:i', (int) $value) . ' UTC';
};
$body = '<h1>Service status</h1>';
if ($error !== '') {
    $body .= '<p class="note">' . e($error) . '</p>';
}
if ($notice !== '') {
    $body .= '<pre>' . e($notice) . '</pre>';
}
if ($status['last_cron_at'] === null) {
    $body .= '<p class="note">The hosting cron job has not run yet. Automatic publication is not confirmed until it does. Browser visits can run the same work, and that is only a backup.</p>';
}
$body .= '<table><tbody>';
$body .= '<tr><th>Version</th><td>' . e($status['version']) . ' (<a href="' . e($status['source_repository']) . '">updates</a>)</td></tr>';
$body .= '<tr><th>Public URL</th><td>' . e($status['public_url']) . '</td></tr>';
$body .= '<tr><th>Public key</th><td><code>' . e($status['sign_public']) . '</code></td></tr>';
$body .= '<tr><th>Pending unlock requests</th><td>' . (int) $status['pending_unlocks'] . '</td></tr>';
$body .= '<tr><th>Mail waiting</th><td>' . (int) $status['mail']['pending'] . '</td></tr>';
$body .= '<tr><th>Mail failed</th><td>' . (int) $status['mail']['failed'] . '</td></tr>';
$body .= '<tr><th>Last scheduler run</th><td>' . e($when($status['last_work_at'])) . '</td></tr>';
$body .= '<tr><th>Last cron run</th><td>' . e($when($status['last_cron_at'])) . '</td></tr>';
$body .= '<tr><th>Storage</th><td>' . (int) $status['storage_bytes'] . ' bytes</td></tr>';
$body .= '<tr><th>PHP</th><td>' . e($status['php']) . '</td></tr>';
$body .= '</tbody></table>';

$body .= '<h2>Pending requests</h2>';
$anyPending = false;
$body .= '<table><tbody>';
foreach ($app->messages->ids() as $id) {
    $state = $app->messages->reduce($id);
    if ($state->status !== 'pending' || $state->currentUnlock === null) {
        continue;
    }
    $anyPending = true;
    $body .= '<tr><td><code>' . e($id) . '</code></td><td>deadline ' . e(gmdate('j F Y, H:i', (int) $state->currentUnlock['deadline']) . ' UTC') . '</td></tr>';
}
if (!$anyPending) {
    $body .= '<tr><td>None</td></tr>';
}
$body .= '</tbody></table>';

$body .= '<h2>Peers</h2><table><tbody>';
if ($status['peers'] === []) {
    $body .= '<tr><td>No peers yet. Add a service you want to sync with.</td></tr>';
}
foreach ($status['peers'] as $peer) {
    $sync = $peer['last_sync_at'] ? gmdate('j F Y, H:i', (int) $peer['last_sync_at']) . ' UTC' : 'not yet';
    $problem = (string) ($peer['last_error'] ?? '');
    $body .= '<tr><td>' . e((string) $peer['endpoint']) . '</td><td>' . e($sync) . '</td><td>' . e($problem) . '</td></tr>';
}
$body .= '</tbody></table>';
$body .= '<form method="post"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="peer">';
$body .= '<label>Peer URL<input type="url" name="endpoint" required placeholder="https://example.com/last-words"></label>';
$body .= '<button type="submit">Add peer</button></form>';
$mentioned = $app->mentionedServices();
if ($mentioned !== []) {
    $body .= '<p class="muted">Services named by stored messages: ' . e(implode(', ', $mentioned)) . '</p>';
}

$body .= '<h2>Email</h2><table><tbody>';
foreach ($status['mail']['recent'] as $mail) {
    $state = $mail['sent_at'] ? 'sent' : 'waiting, attempt ' . (int) $mail['attempts'];
    $body .= '<tr><td>' . e((string) $mail['kind']) . '</td><td>' . e((string) $mail['to_address']) . '</td><td>' . e($state) . '</td><td>' . e((string) ($mail['last_error'] ?? '')) . '</td></tr>';
}
if ($status['mail']['recent'] === []) {
    $body .= '<tr><td>No mail yet.</td></tr>';
}
$body .= '</tbody></table>';

$body .= '<h2>Failed checks</h2><table><tbody>';
if ($status['failures'] === []) {
    $body .= '<tr><td>None recorded.</td></tr>';
}
foreach ($status['failures'] as $failure) {
    $body .= '<tr><td>' . e(gmdate('j F Y, H:i', (int) $failure['happened_at']) . ' UTC') . '</td><td>' . e((string) $failure['kind']) . '</td><td>' . e((string) $failure['detail']) . '</td></tr>';
}
$body .= '</tbody></table>';

$body .= '<h2>Maintenance</h2>';
$body .= '<form method="post"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="password">';
$body .= '<label>New password<input type="password" name="new_password" required></label><button type="submit">Change password</button></form>';
$body .= '<form method="post"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="cron"><button type="submit">Rotate cron key</button></form>';
$body .= '<form method="post"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="rotate"><button type="submit">Rotate service key</button></form>';
$body .= '<form method="post"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="backup">';
$body .= '<label>Backup password<input type="password" name="backup_password" required></label><button type="submit">Download encrypted backup</button></form>';
$body .= '<form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="restore">';
$body .= '<label>Backup file<input type="file" name="archive" required></label>';
$body .= '<label>Backup password<input type="password" name="backup_password" required></label>';
$body .= '<label>Type RESTORE<input type="text" name="confirm" required></label><button type="submit">Restore</button></form>';

$body .= '<h2>Recovery notes</h2>';
$body .= '<p>Keep the encrypted backup somewhere other than this server. To move hosts, install nothing over the data directory: restore the backup, point the new site at <code>public</code>, and update the public URL in <code>config.php</code> if the address changed. People who listed this service need the new address in their page.</p>';
$body .= '<p>Rotating the service key signs a handover from the old key. Clients that saved the old key can follow it. Removing this server does not delete other services\' copies.</p>';
$body .= '<form method="post"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="action" value="logout"><button type="submit">Sign out</button></form>';
render_page('Admin', $body);
