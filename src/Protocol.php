<?php

declare(strict_types=1);

namespace LastWords;

// Signed records use a line format instead of JSON so PHP and the browser
// cannot drift on whitespace, key order, or unicode escapes.
final class Protocol
{
    public const UNLOCK_WINDOW = 2592000;
    public const ACCEPT_SKEW = 600;
    public const MAX_TITLE_BYTES = 200;
    public const MAX_BODY_BYTES = 65536;
    public const MAX_SERVICES = 15;

    private const FIELDS = [
        'register' => [
            'message_id', 'created_at', 'k', 'n', 'ciphertext_sha256', 'nonce',
            'trusted_pubkey', 'recovery_pubkey', 'owner_page', 'services', 'share_commitments',
        ],
        'unlock_request' => [
            'message_id', 'request_id', 'trusted_seq', 'seen_recovery_seq',
            'requested_at', 'deadline', 'cancel_pubkey',
        ],
        'cancel' => ['message_id', 'request_id', 'cancelled_at'],
        'relock' => ['message_id', 'recovery_seq', 'relocked_at'],
        'rotate_trusted' => ['message_id', 'recovery_seq', 'trusted_pubkey', 'rotated_at'],
        'rotate_recovery' => ['message_id', 'recovery_seq', 'new_recovery_pubkey', 'rotated_at'],
        'revise' => ['message_id', 'recovery_seq', 'revised_at', 'ciphertext_sha256', 'nonce'],
    ];

    public static function build(string $type, array $fields): string
    {
        if (!isset(self::FIELDS[$type])) {
            throw new UserError('Unknown event type.');
        }
        $lines = ['lastwords.event.v1', 'type=' . $type];
        foreach (self::FIELDS[$type] as $name) {
            if (!array_key_exists($name, $fields)) {
                throw new UserError('Event is missing a field.');
            }
            $value = (string) $fields[$name];
            self::checkValue($type, $name, $value);
            $lines[] = $name . '=' . $value;
        }
        return implode("\n", $lines) . "\n";
    }

    public static function parse(string $body): array
    {
        if (!str_ends_with($body, "\n") || str_contains($body, "\r")) {
            throw new UserError('Event is malformed.');
        }
        $lines = explode("\n", substr($body, 0, -1));
        if (count($lines) < 2 || $lines[0] !== 'lastwords.event.v1' || !str_starts_with($lines[1], 'type=')) {
            throw new UserError('Event is malformed.');
        }
        $type = substr($lines[1], 5);
        if (!isset(self::FIELDS[$type])) {
            throw new UserError('Unknown event type.');
        }
        $expected = self::FIELDS[$type];
        if (count($lines) !== 2 + count($expected)) {
            throw new UserError('Event is malformed.');
        }
        $fields = [];
        foreach ($expected as $index => $name) {
            $prefix = $name . '=';
            $line = $lines[$index + 2];
            if (!str_starts_with($line, $prefix)) {
                throw new UserError('Event is malformed.');
            }
            $value = substr($line, strlen($prefix));
            self::checkValue($type, $name, $value);
            $fields[$name] = $value;
        }
        if ($type === 'register') {
            if ((int) $fields['k'] > (int) $fields['n']) {
                throw new UserError('Share threshold is not acceptable.');
            }
            $services = self::serviceList($fields['services']);
            if (count($services) !== (int) $fields['n']) {
                throw new UserError('Service list does not match the share count.');
            }
            self::parseCommitments($fields['share_commitments'], (int) $fields['n']);
        }
        if ($type === 'unlock_request') {
            $requested = (int) $fields['requested_at'];
            if ((int) $fields['deadline'] !== $requested + self::UNLOCK_WINDOW) {
                throw new UserError('The deadline in the request is not 30 days.');
            }
        }
        return ['type' => $type, 'fields' => $fields];
    }

    public static function serviceList(string $value): array
    {
        if ($value === '' || strlen($value) > 4000 || str_contains($value, "\n")) {
            throw new UserError('Service list is malformed.');
        }
        $parts = explode(' ', $value);
        if (count($parts) < 1 || count($parts) > self::MAX_SERVICES) {
            throw new UserError('Service list is malformed.');
        }
        $seen = [];
        foreach ($parts as $url) {
            self::checkUrl($url, true);
            if (isset($seen[$url])) {
                throw new UserError('Service list repeats an address.');
            }
            $seen[$url] = true;
        }
        return $parts;
    }

    public static function directory(string $endpoint, string $signPubkey, string $version): string
    {
        self::checkUrl($endpoint, true);
        self::checkKey($signPubkey);
        if (!preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+\z/', $version)) {
            throw new UserError('Version is malformed.');
        }
        return "lastwords.directory.v1\nendpoint={$endpoint}\nsign_pubkey={$signPubkey}\nversion={$version}\n";
    }

    public static function parseDirectory(string $body): array
    {
        $lines = self::exactLines($body, 'lastwords.directory.v1', ['endpoint', 'sign_pubkey', 'version']);
        self::checkUrl($lines['endpoint'], true);
        self::checkKey($lines['sign_pubkey']);
        if (!preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+\z/', $lines['version'])) {
            throw new UserError('Directory is malformed.');
        }
        return $lines;
    }

    public static function rotation(string $oldKey, string $newKey, int $rotatedAt): string
    {
        self::checkKey($oldKey);
        self::checkKey($newKey);
        self::checkInt((string) $rotatedAt, 0, 4000000000);
        return "lastwords.rotation.v1\nold_sign_pubkey={$oldKey}\nnew_sign_pubkey={$newKey}\nrotated_at={$rotatedAt}\n";
    }

    public static function parseRotation(string $body): array
    {
        $lines = self::exactLines($body, 'lastwords.rotation.v1', ['old_sign_pubkey', 'new_sign_pubkey', 'rotated_at']);
        self::checkKey($lines['old_sign_pubkey']);
        self::checkKey($lines['new_sign_pubkey']);
        self::checkInt($lines['rotated_at'], 0, 4000000000);
        return $lines;
    }

    public static function commitments(array $sharesByIndex): string
    {
        ksort($sharesByIndex);
        $parts = [];
        $expect = 1;
        foreach ($sharesByIndex as $index => $share) {
            if ((int) $index !== $expect) {
                throw new UserError('Share list is malformed.');
            }
            $parts[] = $expect . ':' . hash('sha256', $share);
            $expect++;
        }
        return implode(',', $parts);
    }

    public static function parseCommitments(string $text, int $n): array
    {
        $parts = $text === '' ? [] : explode(',', $text);
        if (count($parts) !== $n) {
            throw new UserError('Share commitments do not match the service count.');
        }
        $out = [];
        foreach ($parts as $i => $part) {
            $index = $i + 1;
            $prefix = $index . ':';
            if (!str_starts_with($part, $prefix) || !preg_match('/\A[0-9]+:[a-f0-9]{64}\z/', $part)) {
                throw new UserError('Share commitments are malformed.');
            }
            $out[$index] = substr($part, strlen($prefix));
        }
        return $out;
    }

    private static function exactLines(string $body, string $header, array $names): array
    {
        if (!str_ends_with($body, "\n") || str_contains($body, "\r")) {
            throw new UserError('Record is malformed.');
        }
        $lines = explode("\n", substr($body, 0, -1));
        if (count($lines) !== 1 + count($names) || $lines[0] !== $header) {
            throw new UserError('Record is malformed.');
        }
        $out = [];
        foreach ($names as $i => $name) {
            $prefix = $name . '=';
            if (!str_starts_with($lines[$i + 1], $prefix)) {
                throw new UserError('Record is malformed.');
            }
            $out[$name] = substr($lines[$i + 1], strlen($prefix));
        }
        return $out;
    }

    private static function checkValue(string $type, string $name, string $value): void
    {
        if ($value === '' || str_contains($value, "\n") || str_contains($value, "\r")) {
            throw new UserError('Event is malformed.');
        }
        if (in_array($name, ['message_id', 'request_id'], true)) {
            if (!preg_match('/\A[a-f0-9]{32}\z/', $value)) {
                throw new UserError('Event is malformed.');
            }
            return;
        }
        if (in_array($name, ['trusted_pubkey', 'recovery_pubkey', 'cancel_pubkey', 'new_recovery_pubkey'], true)) {
            self::checkKey($value);
            return;
        }
        if ($name === 'nonce') {
            $raw = Keys::b64decode($value);
            if ($raw === null || strlen($raw) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
                throw new UserError('Event is malformed.');
            }
            return;
        }
        if ($name === 'ciphertext_sha256') {
            if (!preg_match('/\A[a-f0-9]{64}\z/', $value)) {
                throw new UserError('Event is malformed.');
            }
            return;
        }
        if ($name === 'owner_page') {
            self::checkUrl($value, true);
            return;
        }
        if ($name === 'services') {
            self::serviceList($value);
            return;
        }
        if ($name === 'share_commitments') {
            if (strlen($value) > 2000) {
                throw new UserError('Event is malformed.');
            }
            return;
        }
        if (in_array($name, ['created_at', 'requested_at', 'deadline', 'cancelled_at', 'relocked_at', 'rotated_at', 'revised_at'], true)) {
            self::checkInt($value, 0, 4000000000);
            return;
        }
        if (in_array($name, ['trusted_seq', 'recovery_seq', 'seen_recovery_seq'], true)) {
            self::checkInt($value, 0, 1000000);
            return;
        }
        if ($name === 'k' || $name === 'n') {
            self::checkInt($value, 1, self::MAX_SERVICES);
            return;
        }
        throw new UserError('Event is malformed.');
    }

    public static function checkKey(string $value): void
    {
        $raw = Keys::b64decode($value);
        if ($raw === null || strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new UserError('A public key is malformed.');
        }
    }

    public static function checkUrl(string $url, bool $allowLocalHttp): void
    {
        if (strlen($url) > 300 || str_contains($url, ' ') || str_contains($url, '@')) {
            throw new UserError('A URL is not acceptable.');
        }
        $parts = parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            throw new UserError('A URL is not acceptable.');
        }
        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        $local = $host === 'localhost' || $host === '127.0.0.1';
        if ($scheme === 'https' || ($allowLocalHttp && $scheme === 'http' && $local)) {
            return;
        }
        throw new UserError('A URL is not acceptable.');
    }

    private static function checkInt(string $value, int $min, int $max): void
    {
        if (!preg_match('/\A(0|[1-9][0-9]*)\z/', $value)) {
            throw new UserError('Event is malformed.');
        }
        $number = (int) $value;
        if ((string) $number !== $value || $number < $min || $number > $max) {
            throw new UserError('Event is malformed.');
        }
    }
}
