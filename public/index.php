<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/autoload.php';
require dirname(__DIR__) . '/src/Web.php';

use LastWords\Log;

try {
    $app = open_installed_app();
} catch (Throwable $error) {
    Log::error(LastWords\App::dataDir(), $error);
    http_response_code(500);
    exit('Something went wrong.');
}

if ($app === null) {
    render_page('Last Words', '<h1>Last Words</h1><p>This copy is not installed yet.</p><p><a href="install/">Open the installer</a></p>');
    exit;
}

$status = $app->status();
$body = '<h1>' . e($status['service_name']) . '</h1>';
$body .= '<p>This is an independent Last Words service. It stores encrypted messages and signed records for people who choose it. It does not decide whether someone has died.</p>';
$body .= '<p>Public key</p><pre>' . e($status['sign_public']) . '</pre>';
$body .= '<p class="muted">Version ' . e($status['version']) . '. <a href="' . e($status['source_repository']) . '">Source code</a></p>';
$body .= '<h2>For message owners</h2><p><a href="guide.php">Create a Last Words page</a> on the website you already have.</p>';
$body .= '<h2>For operators</h2><p><a href="become.php">Run your own service</a>. No approval from this site is required.</p>';
render_page($status['service_name'], $body);
