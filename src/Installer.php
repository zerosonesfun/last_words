<?php

declare(strict_types=1);

namespace LastWords;

final class Installer
{
    public static function checks(array $env): array
    {
        $php = (string) ($env['php'] ?? PHP_VERSION);
        $extensions = $env['extensions'] ?? [];
        $rows = [];
        $rows[] = self::row('PHP 8.2 or newer', version_compare($php, '8.2.0', '>='), $php);
        foreach (['pdo_sqlite', 'sodium', 'openssl', 'json'] as $extension) {
            $ok = in_array($extension, $extensions, true);
            $rows[] = self::row($extension, $ok, $ok ? 'available' : 'missing');
        }
        $sodiumOk = function_exists('sodium_crypto_sign_keypair') && function_exists('sodium_crypto_secretbox');
        $rows[] = self::row('Sodium sign and secretbox', $sodiumOk, $sodiumOk ? 'available' : 'missing');
        $rows[] = self::row('random_bytes', !empty($env['random']), !empty($env['random']) ? 'available' : 'missing');
        $httpsOk = !empty($env['https']) || !empty($env['local']);
        $rows[] = self::row('HTTPS', $httpsOk, $httpsOk ? 'accepted' : 'HTTPS is required, except on localhost');
        $rows[] = self::row('Outbound HTTP', !empty($env['outbound']), 'allow_url_fopen or curl');
        $rows[] = self::row('Private storage', !empty($env['private_ok']), (string) ($env['private_detail'] ?? ''));
        $rows[] = self::row('Data directory writable', !empty($env['writable']), (string) ($env['data_dir'] ?? ''));
        return $rows;
    }

    public static function ready(array $checks): bool
    {
        foreach ($checks as $check) {
            if (empty($check['ok'])) {
                return false;
            }
        }
        return true;
    }

    public static function assertPrivate(string $dataDir, string $documentRoot, string $origin, callable $fetch): string
    {
        if (!is_dir($dataDir) && !mkdir($dataDir, 0700, true) && !is_dir($dataDir)) {
            throw new UserError('Could not create the data directory.');
        }
        @chmod($dataDir, 0700);
        $data = realpath($dataDir);
        $doc = realpath($documentRoot);
        if ($data === false || $doc === false) {
            throw new UserError('Could not resolve the data directory or the document root.');
        }
        self::writeDenyFiles($data);
        $inside = str_starts_with(rtrim($data, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR, rtrim($doc, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR);
        if (!$inside) {
            return 'The data directory is outside the document root.';
        }
        $token = bin2hex(random_bytes(16));
        $name = 'canary-' . $token . '.txt';
        $file = $data . DIRECTORY_SEPARATOR . $name;
        if (file_put_contents($file, $token) === false) {
            throw new UserError('Could not write a privacy test file.');
        }
        $rel = substr(rtrim($data, DIRECTORY_SEPARATOR), strlen(rtrim($doc, DIRECTORY_SEPARATOR)));
        $rel = str_replace(DIRECTORY_SEPARATOR, '/', $rel);
        $url = rtrim($origin, '/') . $rel . '/' . $name;
        try {
            $body = $fetch($url);
        } finally {
            @unlink($file);
        }
        if (!is_string($body)) {
            throw new UserError('Could not verify that the data directory is hidden. Move it outside the web root.');
        }
        if (str_contains($body, $token)) {
            throw new UserError('The data directory can be downloaded over HTTP. Installation stopped.');
        }
        return 'A direct request did not return the private test file.';
    }

    public static function install(string $dataDir, array $input, array $env, MailTransport $transport): array
    {
        if (is_file($dataDir . '/INSTALLED')) {
            throw new UserError('This service is already installed.');
        }
        if (!isset($env['fetch']) || !is_callable($env['fetch'])) {
            throw new UserError('Private storage could not be checked.');
        }
        $env['private_detail'] = self::assertPrivate(
            $dataDir,
            (string) ($env['document_root'] ?? ''),
            (string) ($env['origin'] ?? ''),
            $env['fetch']
        );
        $env['private_ok'] = true;
        $env['writable'] = is_writable($dataDir);
        $checks = self::checks($env);
        if (!self::ready($checks)) {
            throw new UserError('This host failed a required check. Installation stopped.');
        }
        $publicUrl = rtrim(trim((string) ($input['public_url'] ?? '')), '/');
        Protocol::checkUrl($publicUrl, true);
        $operator = trim((string) ($input['operator_email'] ?? ''));
        if (filter_var($operator, FILTER_VALIDATE_EMAIL) === false) {
            throw new UserError('Operator email address is not acceptable.');
        }
        $smtp = self::smtp($input);
        $name = trim((string) ($input['service_name'] ?? 'Last Words'));
        if ($name === '' || strlen($name) > 80 || str_contains($name, "\n")) {
            throw new UserError('Service name is not acceptable.');
        }
        $repository = trim((string) ($input['source_repository'] ?? Version::SOURCE_REPOSITORY));
        Protocol::checkUrl($repository, false);
        $transport->send($operator, 'Last Words test', "This is a test from your new Last Words service.\n\nIf you received it, outgoing mail works.\n");

        if (!is_dir($dataDir) && !mkdir($dataDir, 0700, true) && !is_dir($dataDir)) {
            throw new UserError('Could not create the data directory.');
        }
        self::writeDenyFiles($dataDir);
        $sign = Keys::signPair();
        $storageKey = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $cronKey = Keys::token(24);
        $config = [
            'public_url' => $publicUrl,
            'service_name' => $name,
            'smtp' => $smtp,
            'operator_email' => $operator,
            'source_repository' => $repository,
            'cron_key' => $cronKey,
            'installed_at' => time(),
            'version' => Version::VERSION,
        ];
        self::writeFile($dataDir . '/sign.public', $sign['public']);
        self::writeFile($dataDir . '/sign.secret', $sign['secret']);
        self::writeFile($dataDir . '/storage.key', $storageKey);
        self::writeFile($dataDir . '/config.php', "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($config, true) . ";\n");
        $db = Storage::open($dataDir . '/service.sqlite');
        @chmod($dataDir . '/service.sqlite', 0600);
        $db->migrate(dirname(__DIR__) . '/migrations');
        $password = self::groupedSecret();
        $reset = self::groupedSecret();
        $db->run(
            'INSERT INTO admin_auth (id, password_hash, reset_hash) VALUES (1, ?, ?)
             ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash, reset_hash = excluded.reset_hash',
            [password_hash($password, PASSWORD_DEFAULT), password_hash($reset, PASSWORD_DEFAULT)]
        );
        self::writeFile($dataDir . '/INSTALLED', Version::VERSION . ' ' . gmdate('c') . "\n");
        return [
            'admin_password' => $password,
            'reset_token' => $reset,
            'cron_key' => $cronKey,
            'sign_public' => Keys::b64($sign['public']),
            'public_url' => $publicUrl,
        ];
    }

    public static function groupedSecret(): string
    {
        $raw = bin2hex(random_bytes(10));
        return implode('-', str_split($raw, 5));
    }

    private static function smtp(array $input): array
    {
        $host = trim((string) ($input['smtp_host'] ?? ''));
        $port = (int) ($input['smtp_port'] ?? 0);
        $encryption = (string) ($input['smtp_encryption'] ?? 'starttls');
        $from = trim((string) ($input['from_email'] ?? ''));
        if ($host === '' || strlen($host) > 200 || $port < 1 || $port > 65535) {
            throw new UserError('SMTP host or port is not acceptable.');
        }
        if (!in_array($encryption, ['none', 'starttls', 'tls'], true)) {
            throw new UserError('SMTP encryption is not acceptable.');
        }
        if (filter_var($from, FILTER_VALIDATE_EMAIL) === false) {
            throw new UserError('From address is not acceptable.');
        }
        return [
            'host' => $host,
            'port' => $port,
            'encryption' => $encryption,
            'username' => (string) ($input['smtp_username'] ?? ''),
            'password' => (string) ($input['smtp_password'] ?? ''),
            'from_email' => $from,
            'from_name' => 'Last Words',
        ];
    }

    private static function writeDenyFiles(string $dataDir): void
    {
        $root = dirname(__DIR__) . '/resources/';
        @copy($root . 'deny.htaccess', $dataDir . '/.htaccess');
        @copy($root . 'web.config', $dataDir . '/web.config');
    }

    private static function writeFile(string $path, string $contents): void
    {
        if (file_put_contents($path, $contents, LOCK_EX) === false) {
            throw new UserError('Could not write a private file.');
        }
        @chmod($path, 0600);
    }

    private static function row(string $name, bool $ok, string $detail): array
    {
        return ['name' => $name, 'ok' => $ok, 'detail' => $detail];
    }
}
