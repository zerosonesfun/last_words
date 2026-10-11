<?php

declare(strict_types=1);

namespace LastWords;

final class Keys
{
    public static function signPair(): array
    {
        $pair = sodium_crypto_sign_keypair();
        return [
            'public' => sodium_crypto_sign_publickey($pair),
            'secret' => sodium_crypto_sign_secretkey($pair),
        ];
    }

    public static function sign(string $message, string $secret): string
    {
        if (strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new UserError('Signing key is malformed.');
        }
        return sodium_crypto_sign_detached($message, $secret);
    }

    public static function verify(string $message, string $signature, string $public): bool
    {
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        if (strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($signature, $message, $public);
        } catch (\SodiumException) {
            return false;
        }
    }

    // Libsodium and TweetNaCl both store an Ed25519 secret as seed plus public key.
    public static function publicFromSecret(string $secret): ?string
    {
        if (strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            return null;
        }
        return substr($secret, 32);
    }

    public static function same(string $left, string $right): bool
    {
        if (strlen($left) !== strlen($right)) {
            return false;
        }
        return sodium_memcmp($left, $right) === 0;
    }

    public static function b64(string $raw): string
    {
        return base64_encode($raw);
    }

    public static function b64decode(string $text): ?string
    {
        if ($text === '' || preg_match('/[^A-Za-z0-9+\/=]/', $text) === 1) {
            return null;
        }
        $raw = base64_decode($text, true);
        if ($raw === false) {
            return null;
        }
        if (base64_encode($raw) !== $text) {
            return null;
        }
        return $raw;
    }

    public static function id(): string
    {
        return bin2hex(random_bytes(16));
    }

    public static function token(int $bytes = 16): string
    {
        return bin2hex(random_bytes($bytes));
    }

    public static function box(string $plain, string $key): array
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox($plain, $nonce, $key);
        return [$nonce, $cipher];
    }

    public static function unbox(string $cipher, string $nonce, string $key): ?string
    {
        if (strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            return null;
        }
        try {
            $plain = sodium_crypto_secretbox_open($cipher, $nonce, $key);
        } catch (\SodiumException) {
            return null;
        }
        return $plain === false ? null : $plain;
    }

    public static function encodeMessage(string $messageId, string $title, string $body): string
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/', $messageId)) {
            throw new UserError('Message id is malformed.');
        }
        if ($title === '' && $body === '') {
            throw new UserError('The message is empty.');
        }
        if (strlen($title) > Protocol::MAX_TITLE_BYTES || strlen($body) > Protocol::MAX_BODY_BYTES) {
            throw new UserError('The message is too long.');
        }
        return 'LWMSG1' . $messageId . pack('N', strlen($title)) . $title . pack('N', strlen($body)) . $body;
    }

    public static function decodeMessage(string $plain, string $expectedId): ?array
    {
        if (!str_starts_with($plain, 'LWMSG1') || strlen($plain) < 6 + 32 + 8) {
            return null;
        }
        $id = substr($plain, 6, 32);
        if (!self::same($id, $expectedId)) {
            return null;
        }
        $offset = 38;
        $titleLen = self::u32($plain, $offset);
        if ($titleLen === null || $titleLen > Protocol::MAX_TITLE_BYTES) {
            return null;
        }
        $offset += 4;
        if (strlen($plain) < $offset + $titleLen + 4) {
            return null;
        }
        $title = substr($plain, $offset, $titleLen);
        $offset += $titleLen;
        $bodyLen = self::u32($plain, $offset);
        if ($bodyLen === null || $bodyLen > Protocol::MAX_BODY_BYTES) {
            return null;
        }
        $offset += 4;
        if (strlen($plain) !== $offset + $bodyLen) {
            return null;
        }
        return ['title' => $title, 'body' => substr($plain, $offset, $bodyLen)];
    }

    private static function u32(string $data, int $offset): ?int
    {
        if (strlen($data) < $offset + 4) {
            return null;
        }
        $unpacked = unpack('N', substr($data, $offset, 4));
        if (!is_array($unpacked)) {
            return null;
        }
        return (int) $unpacked[1];
    }
}
