<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/autoload.php';
require __DIR__ . '/support.php';

$failed = 0;
$passed = 0;
$files = glob(__DIR__ . '/*_test.php') ?: [];
sort($files);
foreach ($files as $file) {
    require $file;
}
$functions = get_defined_functions()['user'];
foreach ($functions as $function) {
    if (!str_starts_with($function, 'test_')) {
        continue;
    }
    try {
        $function();
        $passed++;
        echo "ok  {$function}\n";
    } catch (Throwable $error) {
        $failed++;
        echo "FAIL {$function}\n{$error->getMessage()}\n{$error->getFile()}:{$error->getLine()}\n";
    }
}
echo "\n{$passed} passed, {$failed} failed\n";
exit($failed === 0 ? 0 : 1);
