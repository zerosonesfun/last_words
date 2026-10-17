<?php

declare(strict_types=1);

require __DIR__ . '/src/autoload.php';
require __DIR__ . '/src/Web.php';

use LastWords\Log;

// Hosting panels often fetch a URL. Publication still requires POST so a
// scanner that only GETs this address cannot change message state.
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    security_headers();
    header('Content-Type: text/plain; charset=UTF-8');
    echo "This address runs the scheduler only as a POST from the hosting panel.\n";
    exit;
}
require_secure_mutation();
$app = require_app();
$given = (string) ($_POST['key'] ?? '');
$expected = (string) ($app->config['cron_key'] ?? '');
if ($given === '' || $expected === '' || !hash_equals($expected, $given)) {
    http_response_code(404);
    echo "Not found.\n";
    exit;
}
try {
    $result = $app->scheduler->run(true);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'ok published=' . (int) $result['published'] . ' sent=' . (int) $result['sent'] . "\n";
} catch (Throwable $error) {
    Log::error($app->dataDir, $error);
    http_response_code(500);
    echo "Something went wrong.\n";
}
