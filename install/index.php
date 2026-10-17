<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/autoload.php';
require dirname(__DIR__) . '/src/Web.php';

use LastWords\App;
use LastWords\Installer;
use LastWords\Log;
use LastWords\SmtpTransport;
use LastWords\UserError;

function install_data_dir(): string
{
    $posted = trim((string) ($_POST['data_dir'] ?? ''));
    if ($posted !== '') {
        return $posted;
    }
    $env = getenv('LASTWORDS_DATA_DIR');
    if (is_string($env) && $env !== '') {
        return $env;
    }
    return dirname(__DIR__) . '/data';
}

function install_env(string $dataDir): array
{
    $https = request_is_https();
    $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
    $extensions = array_map('strtolower', get_loaded_extensions());
    $env = [
        'php' => PHP_VERSION,
        'extensions' => $extensions,
        'random' => function_exists('random_bytes'),
        'https' => $https,
        'local' => request_is_local(),
        'outbound' => (bool) ini_get('allow_url_fopen') || function_exists('curl_init'),
        'document_root' => (string) ($_SERVER['DOCUMENT_ROOT'] ?? ''),
        'origin' => ($https ? 'https' : 'http') . '://' . $host,
        'fetch' => static function (string $url): array {
            try {
                return App::httpResponse($url);
            } catch (Throwable) {
                return ['status' => 0, 'body' => null];
            }
        },
        'data_dir' => $dataDir,
        'writable' => is_dir($dataDir) ? is_writable($dataDir) : is_writable(dirname($dataDir)),
        'private_ok' => false,
        'private_detail' => 'Not checked yet.',
    ];
    try {
        $env['private_detail'] = Installer::assertPrivate($dataDir, $env['document_root'], $env['origin'], $env['fetch']);
        $env['private_ok'] = true;
        $env['writable'] = is_writable($dataDir);
    } catch (UserError $error) {
        $env['private_detail'] = $error->getMessage();
    }
    return $env;
}

function install_page(string $body): void
{
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header("Content-Security-Policy: default-src 'self'; style-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
    echo "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
    echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Install Last Words</title>\n";
    echo "<link rel=\"stylesheet\" href=\"../assets/style.css\">\n</head>\n<body>\n<main>\n";
    echo $body;
    echo "\n</main>\n</body>\n</html>\n";
}

if (is_file(install_data_dir() . '/INSTALLED') || is_file(dirname(__DIR__) . '/data/INSTALLED')) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    echo "Not found.\n";
    exit;
}

$dataDir = install_data_dir();
$error = '';
$result = null;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    require_secure_mutation();
    start_session();
    if (!csrf_ok()) {
        $error = 'The form expired. Reload the page and try again.';
    } else {
        try {
            $env = install_env($dataDir);
            $transport = new SmtpTransport([
                'host' => trim((string) ($_POST['smtp_host'] ?? '')),
                'port' => (int) ($_POST['smtp_port'] ?? 587),
                'encryption' => (string) ($_POST['smtp_encryption'] ?? 'starttls'),
                'username' => (string) ($_POST['smtp_username'] ?? ''),
                'password' => (string) ($_POST['smtp_password'] ?? ''),
                'from_email' => trim((string) ($_POST['from_email'] ?? '')),
                'from_name' => 'Last Words',
            ]);
            $result = Installer::install($dataDir, [
                'public_url' => trim((string) ($_POST['public_url'] ?? '')),
                'operator_email' => trim((string) ($_POST['operator_email'] ?? '')),
                'service_name' => trim((string) ($_POST['service_name'] ?? 'Last Words')),
                'source_repository' => trim((string) ($_POST['source_repository'] ?? LastWords\Version::SOURCE_REPOSITORY)),
                'smtp_host' => trim((string) ($_POST['smtp_host'] ?? '')),
                'smtp_port' => (int) ($_POST['smtp_port'] ?? 587),
                'smtp_encryption' => (string) ($_POST['smtp_encryption'] ?? 'starttls'),
                'smtp_username' => (string) ($_POST['smtp_username'] ?? ''),
                'smtp_password' => (string) ($_POST['smtp_password'] ?? ''),
                'from_email' => trim((string) ($_POST['from_email'] ?? '')),
            ], $env, $transport);
            if ($dataDir !== dirname(__DIR__) . '/data') {
                $pathFile = dirname(__DIR__) . '/data_path.php';
                file_put_contents($pathFile, "<?php\nreturn " . var_export($dataDir, true) . ";\n");
            }
        } catch (UserError $caught) {
            $error = $caught->getMessage();
        } catch (Throwable $caught) {
            Log::error($dataDir, $caught);
            $error = 'Installation failed before it could finish.';
        }
    }
}

if (is_array($result)) {
    $cron = e($result['public_url'] . '/cron.php');
    $key = e($result['cron_key']);
    $card = "Last Words admin card\n\n"
        . 'URL: ' . $result['public_url'] . "\n"
        . 'Admin password: ' . $result['admin_password'] . "\n"
        . 'Reset token: ' . $result['reset_token'] . "\n"
        . 'Cron key: ' . $result['cron_key'] . "\n"
        . 'Public key: ' . $result['sign_public'] . "\n\n"
        . "Cron command:\n"
        . 'curl -fsS -X POST -d "key=' . $result['cron_key'] . '" ' . $result['public_url'] . "/cron.php\n";
    $body = '<h1>Installed</h1>';
    $body .= '<p>Save this page before you leave. The password and cron key are not shown again.</p>';
    $body .= '<pre>' . e($card) . '</pre>';
    $body .= '<p>In the hosting panel, schedule a POST to the cron address. A normal visit does not publish anything. If the host cannot POST on a schedule, do not treat automatic publication as guaranteed. Browsers can nudge the scheduler, and that is only a backup.</p>';
    $body .= '<p>Command:</p><pre>curl -fsS -X POST -d "key=' . $key . '" ' . $cron . '</pre>';
    $body .= '<p><a href="../admin.php">Open the admin page</a></p>';
    install_page($body);
    $stub = "<?php\nhttp_response_code(404);\nheader('Content-Type: text/plain; charset=UTF-8');\nheader('Cache-Control: no-store');\necho \"Not found.\\n\";\n";
    file_put_contents(__FILE__, $stub, LOCK_EX);
    exit;
}

$env = install_env($dataDir);
$checks = Installer::checks($env);
$rows = '';
foreach ($checks as $check) {
    $rows .= '<tr><td>' . e($check['ok'] ? 'Pass' : 'Stop') . '</td><td>' . e($check['name']) . '</td><td>' . e($check['detail']) . '</td></tr>';
}
$guess = e((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . rtrim(dirname(dirname($_SERVER['SCRIPT_NAME'] ?? '/install/index.php')), '/'));
$token = e(csrf_token());
$defaultData = e(dirname(__DIR__) . '/data');
$body = '<h1>Install Last Words</h1>';
$body .= '<p>The installer checks the host, sends a test email, then creates keys and the database. It will not continue if a required check fails.</p>';
if ($error !== '') {
    $body .= '<p class="note">' . e($error) . '</p>';
}
$body .= '<h2>Checks</h2><table><tbody>' . $rows . '</tbody></table>';
$body .= '<form method="post"><input type="hidden" name="csrf" value="' . $token . '">';
$body .= '<label>Public URL<input type="url" name="public_url" required value="' . $guess . '"></label>';
$body .= '<label>Service name<input type="text" name="service_name" value="Last Words"></label>';
$body .= '<label>Operator email<input type="email" name="operator_email" required></label>';
$body .= '<label>Source repository<input type="url" name="source_repository" value="https://github.com/zerosonesfun/last_words"></label>';
$body .= '<label>Private data directory<input type="text" name="data_dir" value="' . $defaultData . '"></label>';
$body .= '<p class="muted">The default folder sits next to the program and is blocked by .htaccess. Leave it unless you already have a directory outside the web root. The installer requests a test file. A refusal means .htaccess is working and the data is secure. Installation stops if that file comes back.</p>';
$body .= '<h2>Email</h2>';
$body .= '<label>SMTP host<input type="text" name="smtp_host" required></label>';
$body .= '<label>SMTP port<input type="number" name="smtp_port" value="587" required></label>';
$body .= '<label>Encryption<select name="smtp_encryption"><option value="starttls">STARTTLS</option><option value="tls">TLS</option><option value="none">None</option></select></label>';
$body .= '<label>SMTP username<input type="text" name="smtp_username"></label>';
$body .= '<label>SMTP password<input type="password" name="smtp_password"></label>';
$body .= '<label>From address<input type="email" name="from_email" required></label>';
$body .= '<button type="submit">Install</button></form>';
install_page($body);
