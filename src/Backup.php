<?php

declare(strict_types=1);

namespace LastWords;

final class Backup
{
    public static function create(string $dataDir, string $password): string
    {
        if (strlen($password) < 8) {
            throw new UserError('Choose a backup password of at least 8 characters.');
        }
        $names = ['config.php', 'service.sqlite', 'sign.public', 'sign.secret', 'storage.key', 'INSTALLED'];
        $payload = '';
        $count = 0;
        foreach ($names as $name) {
            $path = $dataDir . '/' . $name;
            if (!is_file($path)) {
                continue;
            }
            $bytes = file_get_contents($path);
            if ($bytes === false) {
                throw new UserError('Could not read a file for the backup.');
            }
            $payload .= pack('n', strlen($name)) . $name . pack('N', strlen($bytes)) . $bytes;
            $count++;
        }
        $payload = pack('N', $count) . $payload;
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $key = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox($payload, $nonce, $key);
        sodium_memzero($key);
        return "LWBACKUP1\n" . $salt . $nonce . $cipher;
    }

    public static function restore(string $dataDir, string $password, string $archive): void
    {
        if (!str_starts_with($archive, "LWBACKUP1\n")) {
            throw new UserError('Backup file is not recognized.');
        }
        $offset = strlen("LWBACKUP1\n");
        $saltLen = SODIUM_CRYPTO_PWHASH_SALTBYTES;
        $nonceLen = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
        if (strlen($archive) < $offset + $saltLen + $nonceLen + 16) {
            throw new UserError('Backup file is not recognized.');
        }
        $salt = substr($archive, $offset, $saltLen);
        $nonce = substr($archive, $offset + $saltLen, $nonceLen);
        $cipher = substr($archive, $offset + $saltLen + $nonceLen);
        $key = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        $plain = Keys::unbox($cipher, $nonce, $key);
        sodium_memzero($key);
        if ($plain === null) {
            throw new UserError('Backup password was not accepted.');
        }
        $countData = unpack('N', substr($plain, 0, 4));
        if (!is_array($countData)) {
            throw new UserError('Backup file is not recognized.');
        }
        $count = (int) $countData[1];
        if ($count < 1 || $count > 20) {
            throw new UserError('Backup file is not recognized.');
        }
        $offset = 4;
        $files = [];
        for ($i = 0; $i < $count; $i++) {
            $nameLenData = unpack('n', substr($plain, $offset, 2));
            $offset += 2;
            if (!is_array($nameLenData)) {
                throw new UserError('Backup file is not recognized.');
            }
            $nameLen = (int) $nameLenData[1];
            $name = substr($plain, $offset, $nameLen);
            $offset += $nameLen;
            $sizeData = unpack('N', substr($plain, $offset, 4));
            $offset += 4;
            if (!is_array($sizeData) || !preg_match('/\A[A-Za-z0-9._-]+\z/', $name)) {
                throw new UserError('Backup file is not recognized.');
            }
            $size = (int) $sizeData[1];
            if ($size < 0 || $offset + $size > strlen($plain)) {
                throw new UserError('Backup file is not recognized.');
            }
            $files[$name] = substr($plain, $offset, $size);
            $offset += $size;
        }
        if (!is_dir($dataDir) && !mkdir($dataDir, 0700, true) && !is_dir($dataDir)) {
            throw new UserError('Could not create the data directory.');
        }
        foreach ($files as $name => $bytes) {
            $path = $dataDir . '/' . $name;
            if (file_put_contents($path, $bytes, LOCK_EX) === false) {
                throw new UserError('Could not restore a file.');
            }
            @chmod($path, 0600);
        }
    }
}
