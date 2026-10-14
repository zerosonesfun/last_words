<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/src/autoload.php';
require dirname(__DIR__, 2) . '/src/Web.php';

use LastWords\Log;
use LastWords\UserError;

api_cors();

function api_app(): LastWords\App
{
    try {
        $app = open_installed_app();
    } catch (Throwable $error) {
        Log::error(LastWords\App::dataDir(), $error);
        json_error('Something went wrong.', 500);
    }
    if ($app === null) {
        json_error('This service is not installed.', 404);
    }
    return $app;
}
