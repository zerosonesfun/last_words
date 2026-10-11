<?php

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'LastWords\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $name = substr($class, strlen($prefix));
    $shared = [
        'SystemClock' => 'Clock.php',
        'FakeClock' => 'Clock.php',
        'MailTransport' => 'Mailer.php',
        'MemoryTransport' => 'Mailer.php',
        'SmtpTransport' => 'Mailer.php',
    ];
    $file = $shared[$name] ?? ($name . '.php');
    $path = __DIR__ . '/' . $file;
    if (is_file($path)) {
        require $path;
    }
});
