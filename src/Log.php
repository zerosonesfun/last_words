<?php

declare(strict_types=1);

namespace LastWords;

final class Log
{
    public static function error(string $dataDir, \Throwable $error): void
    {
        $line = gmdate('c')
            . ' '
            . $error::class
            . ' '
            . self::safe($error->getMessage())
            . ' at '
            . basename($error->getFile())
            . ':'
            . $error->getLine()
            . "\n";
        $path = $dataDir . '/error.log';
        @file_put_contents($path, $line, FILE_APPEND | LOCK_EX);
    }

    // Failure rows are shown to the operator. Keep them dull and free of secrets.
    public static function safe(string $text): string
    {
        $text = str_replace(["\r", "\n"], ' ', $text);
        if (strlen($text) > 300) {
            $text = substr($text, 0, 300);
        }
        return $text;
    }
}
