<?php

declare(strict_types=1);

require __DIR__ . '/common.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    json_error('Method not allowed.', 405);
}
json_send(api_app()->network->directoryDocument());
