<?php

declare(strict_types=1);

use LastWords\App;
use LastWords\Clock;
use LastWords\FakeClock;
use LastWords\Installer;
use LastWords\Keys;
use LastWords\MemoryTransport;
use LastWords\Protocol;
use LastWords\Shamir;

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function check_same(mixed $actual, mixed $expected, string $message): void
{
    if ($actual !== $expected) {
        throw new RuntimeException($message . "\n got: " . var_export($actual, true) . "\n want: " . var_export($expected, true));
    }
}

function temp_dir(): string
{
    $dir = sys_get_temp_dir() . '/lastwords-' . bin2hex(random_bytes(6));
    if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('Could not create a temp directory.');
    }
    return $dir;
}

function host_env(string $dataDir): array
{
    $doc = temp_dir();
    return [
        'php' => PHP_VERSION,
        'extensions' => ['pdo_sqlite', 'sodium', 'openssl', 'json'],
        'random' => true,
        'https' => false,
        'local' => true,
        'outbound' => true,
        'document_root' => $doc,
        'origin' => 'http://127.0.0.1',
        'fetch' => static fn (string $url): string => 'hidden',
        'data_dir' => $dataDir,
        'writable' => true,
        'private_ok' => true,
    ];
}

function install_input(string $url): array
{
    return [
        'public_url' => $url,
        'operator_email' => 'owner@example.com',
        'service_name' => 'Test service',
        'source_repository' => 'https://example.com/last-words',
        'smtp_host' => 'localhost',
        'smtp_port' => 25,
        'smtp_encryption' => 'none',
        'smtp_username' => '',
        'smtp_password' => '',
        'from_email' => 'mail@example.com',
    ];
}

function install_app(string $url, FakeClock $clock, MemoryTransport $mail): App
{
    $dir = temp_dir();
    Installer::install($dir, install_input($url), host_env($dir), $mail);
    return App::open($dir, $clock, $mail, static fn (string $url): string => '');
}

function sign_event(string $type, array $fields, string $secret, string $public): array
{
    $body = Protocol::build($type, $fields);
    return [
        'body' => $body,
        'signature' => Keys::b64(Keys::sign($body, $secret)),
        'signer_public' => Keys::b64($public),
    ];
}

function register_on(App $app, array $fields, string $recoverySecret, string $recoveryPublic, string $ciphertext, string $nonce, string $share, string $email = 'person@example.com'): void
{
    $event = sign_event('register', $fields, $recoverySecret, $recoveryPublic);
    $app->messages->submit($event + [
        'ciphertext' => Keys::b64($ciphertext),
        'nonce' => Keys::b64($nonce),
        'share' => Keys::b64($share),
        'owner_email' => $email,
    ]);
}

function make_message(array $apps, FakeClock $clock, string $title, string $bodyText, int $k): array
{
    $recovery = Keys::signPair();
    $trusted = Keys::signPair();
    $messageKey = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    $messageId = Keys::id();
    $n = count($apps);
    $shares = Shamir::split($messageKey, $k, $n);
    $urls = [];
    foreach ($apps as $app) {
        $urls[] = rtrim((string) $app->config['public_url'], '/');
    }
    $plain = Keys::encodeMessage($messageId, $title, $bodyText);
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = sodium_crypto_secretbox($plain, $nonce, $messageKey);
    $fields = [
        'message_id' => $messageId,
        'created_at' => (string) $clock->now(),
        'k' => (string) $k,
        'n' => (string) $n,
        'ciphertext_sha256' => hash('sha256', $nonce . $cipher),
        'nonce' => Keys::b64($nonce),
        'trusted_pubkey' => Keys::b64($trusted['public']),
        'recovery_pubkey' => Keys::b64($recovery['public']),
        'owner_page' => 'http://127.0.0.1/last-words',
        'services' => implode(' ', $urls),
        'share_commitments' => Protocol::commitments($shares),
    ];
    foreach ($apps as $index => $app) {
        register_on($app, $fields, $recovery['secret'], $recovery['public'], $cipher, $nonce, $shares[$index + 1]);
    }
    return [
        'id' => $messageId,
        'key' => $messageKey,
        'recovery' => $recovery,
        'trusted' => $trusted,
        'cipher' => $cipher,
        'nonce' => $nonce,
        'shares' => $shares,
        'fields' => $fields,
        'title' => $title,
        'body' => $bodyText,
    ];
}

function request_unlock(App $app, array $message, FakeClock $clock, int $seq, int $seen): array
{
    $cancel = Keys::signPair();
    $requested = $clock->now();
    $fields = [
        'message_id' => $message['id'],
        'request_id' => Keys::id(),
        'trusted_seq' => (string) $seq,
        'seen_recovery_seq' => (string) $seen,
        'requested_at' => (string) $requested,
        'deadline' => (string) ($requested + Protocol::UNLOCK_WINDOW),
        'cancel_pubkey' => Keys::b64($cancel['public']),
    ];
    $event = sign_event('unlock_request', $fields, $message['trusted']['secret'], $message['trusted']['public']);
    $app->messages->submit($event + [
        'cancel_secret' => Keys::b64($cancel['secret']),
        'trusted_email' => 'friend@example.com',
    ]);
    return ['fields' => $fields, 'cancel' => $cancel, 'event' => $event];
}

function link_apps(App $left, App $right): void
{
    $router = static function (string $url) use ($left, $right): string {
        $target = str_starts_with($url, rtrim((string) $left->config['public_url'], '/')) ? $left : $right;
        if (!str_starts_with($url, rtrim((string) $target->config['public_url'], '/'))) {
            // The closure captured both. Pick by prefix.
        }
        if (str_starts_with($url, rtrim((string) $left->config['public_url'], '/'))) {
            $target = $left;
        } elseif (str_starts_with($url, rtrim((string) $right->config['public_url'], '/'))) {
            $target = $right;
        } else {
            throw new RuntimeException('Unexpected URL ' . $url);
        }
        if (str_contains($url, '/api/directory.php')) {
            return json_encode($target->network->directoryDocument(), JSON_THROW_ON_ERROR);
        }
        if (str_contains($url, '/api/sync.php')) {
            return json_encode($target->network->export(), JSON_THROW_ON_ERROR);
        }
        throw new RuntimeException('Unexpected URL ' . $url);
    };
    $rewrite = static function (App $app, App $other) use ($router): void {
        $network = new LastWords\Network(
            $app->storage,
            $app->messages,
            $app->clock,
            $app->signPublic,
            $app->signSecret,
            rtrim((string) $app->config['public_url'], '/'),
            $router
        );
        $app->network = $network;
        $app->scheduler = new LastWords\Scheduler($app->storage, $app->clock, $network, $app->messages, $app->mail, $app->dataDir);
        $network->trustPeer((string) $other->config['public_url']);
    };
    $rewrite($left, $right);
    $rewrite($right, $left);
}
