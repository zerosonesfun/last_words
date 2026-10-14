<?php

declare(strict_types=1);

require __DIR__ . '/common.php';

use LastWords\Log;
use LastWords\UserError;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    json_error('Method not allowed.', 405);
}
require_secure_mutation();
$app = api_app();
if (!$app->rates->allow('event:' . client_ip(), 40, 600)) {
    json_error('Too many requests.', 429);
}
$input = read_json();
try {
    $result = $app->messages->submit($input);
    $app->mail->drain();
    json_send(['ok' => true, 'duplicate' => !empty($result['duplicate']), 'conflict' => !empty($result['conflict'])]);
} catch (UserError $error) {
    $app->messages->noteFailure('request', $error->getMessage());
    json_error($error->getMessage(), 400);
} catch (Throwable $error) {
    Log::error($app->dataDir, $error);
    json_error('Something went wrong.', 500);
}
