<?php

declare(strict_types=1);

use LastWords\App;
use LastWords\Log;
use LastWords\UserError;

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function request_is_local(): bool
{
    $host = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
    return str_starts_with($host, 'localhost') || str_starts_with($host, '127.0.0.1');
}

function request_is_https(): bool
{
    return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
}

function require_secure_mutation(): void
{
    if (request_is_local() || request_is_https()) {
        return;
    }
    http_response_code(400);
    exit('HTTPS is required.');
}

function client_ip(): string
{
    return substr((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 0, 64);
}

function security_headers(): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header("Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");
}

function start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $secure = request_is_https();
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => session_path(),
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function session_path(): string
{
    $dir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
    if ($dir === '/' || $dir === '.' || $dir === '') {
        return '/';
    }
    return rtrim($dir, '/');
}

function csrf_token(): string
{
    start_session();
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function csrf_ok(): bool
{
    start_session();
    $sent = (string) ($_POST['csrf'] ?? '');
    $saved = (string) ($_SESSION['csrf'] ?? '');
    return $sent !== '' && $saved !== '' && hash_equals($saved, $sent);
}

function render_page(string $title, string $body, array $scripts = []): void
{
    security_headers();
    header('Content-Type: text/html; charset=UTF-8');
    $titleText = e($title);
    echo "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
    echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
    echo "<title>{$titleText}</title>\n<link rel=\"stylesheet\" href=\"assets/style.css\">\n</head>\n<body>\n";
    echo "<header><p class=\"mark\"><a href=\"index.php\">Last Words</a></p><nav>";
    echo '<a href="guide.php">Create a page</a> <a href="become.php">Become a service</a> <a href="admin.php">Admin</a>';
    echo "</nav></header>\n<main>\n";
    echo $body;
    echo "\n</main>\n";
    foreach ($scripts as $script) {
        echo '<script src="' . e($script) . "\"></script>\n";
    }
    echo "<script src=\"assets/work.js\"></script>\n</body>\n</html>\n";
}

function open_installed_app(): ?App
{
    $dir = App::dataDir();
    if (!is_file($dir . '/INSTALLED')) {
        return null;
    }
    return App::open($dir);
}

function require_app(): App
{
    try {
        $app = open_installed_app();
    } catch (Throwable $error) {
        Log::error(App::dataDir(), $error);
        http_response_code(500);
        exit('Something went wrong.');
    }
    if ($app === null) {
        http_response_code(404);
        exit('This service is not installed.');
    }
    return $app;
}

function show_user_error(UserError $error): void
{
    http_response_code(400);
    echo e($error->getMessage());
}

function json_send(array $data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    header('Cache-Control: no-store');
    header('Access-Control-Allow-Origin: *');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

function json_error(string $message, int $code): void
{
    json_send(['error' => $message], $code);
}

function read_json(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > 200000) {
        json_error('Request is too large.', 400);
    }
    if ($raw === '') {
        return [];
    }
    try {
        $data = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        json_error('Request is not valid JSON.', 400);
    }
    if (!is_array($data)) {
        json_error('Request is not valid JSON.', 400);
    }
    return $data;
}

function api_cors(): void
{
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Max-Age: 600');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}
