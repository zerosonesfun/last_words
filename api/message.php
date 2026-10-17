<?php

declare(strict_types=1);

require __DIR__ . '/common.php';

use LastWords\UserError;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
    json_error('Method not allowed.', 405);
}
$id = (string) ($_GET['id'] ?? '');
try {
    json_send(api_app()->messages->view($id));
} catch (UserError $error) {
    json_error($error->getMessage(), 404);
} catch (Throwable $error) {
    LastWords\Log::error(LastWords\App::dataDir(), $error);
    json_error('Something went wrong.', 500);
}
