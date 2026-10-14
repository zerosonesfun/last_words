<?php

declare(strict_types=1);

require __DIR__ . '/common.php';

use LastWords\Log;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    json_error('Method not allowed.', 405);
}
require_secure_mutation();
$app = api_app();
$last = (int) $app->storage->meta('last_work_at', '0');
if ($app->clock->now() - $last < 30) {
    json_send(['ok' => true, 'skipped' => true]);
}
try {
    $result = $app->scheduler->run(false);
    json_send(['ok' => true, 'published' => $result['published'], 'sent' => $result['sent']]);
} catch (Throwable $error) {
    Log::error($app->dataDir, $error);
    json_error('Something went wrong.', 500);
}
