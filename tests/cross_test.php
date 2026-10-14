<?php

declare(strict_types=1);

use LastWords\Keys;
use LastWords\Protocol;
use LastWords\Shamir;

function test_browser_code_matches_the_php_service(): void
{
    $node = trim((string) shell_exec('command -v node'));
    if ($node === '') {
        throw new RuntimeException('node is required for the browser compatibility test');
    }
    $recovery = Keys::signPair();
    $trusted = Keys::signPair();
    $cancel = Keys::signPair();
    $id = Keys::id();
    $key = random_bytes(32);
    $shares = Shamir::split($key, 2, 2);
    $nonce = random_bytes(24);
    $plain = Keys::encodeMessage($id, 'Note', 'the silver locket');
    $cipher = sodium_crypto_secretbox($plain, $nonce, $key);
    $registerFields = [
        'message_id' => $id,
        'created_at' => '1700000000',
        'k' => '2',
        'n' => '2',
        'ciphertext_sha256' => hash('sha256', $nonce . $cipher),
        'nonce' => Keys::b64($nonce),
        'trusted_pubkey' => Keys::b64($trusted['public']),
        'recovery_pubkey' => Keys::b64($recovery['public']),
        'owner_page' => 'https://example.com/words',
        'services' => 'https://example.com/a https://example.com/b',
        'share_commitments' => Protocol::commitments($shares),
    ];
    $register = sign_event('register', $registerFields, $recovery['secret'], $recovery['public']);
    $unlock = sign_event('unlock_request', [
        'message_id' => $id,
        'request_id' => Keys::id(),
        'trusted_seq' => '1',
        'seen_recovery_seq' => '0',
        'requested_at' => '1700000000',
        'deadline' => (string) (1700000000 + Protocol::UNLOCK_WINDOW),
        'cancel_pubkey' => Keys::b64($cancel['public']),
    ], $trusted['secret'], $trusted['public']);
    $relock = sign_event('relock', [
        'message_id' => $id,
        'recovery_seq' => '1',
        'relocked_at' => '1700000500',
    ], $recovery['secret'], $recovery['public']);
    $base = [
        'public' => Keys::b64($recovery['public']),
        'secret' => Keys::b64($recovery['secret']),
        'signature' => $register['signature'],
        'body' => $register['body'],
        'ciphertext' => Keys::b64($cipher),
        'nonce' => Keys::b64($nonce),
        'key' => Keys::b64($key),
        'message_id' => $id,
        'title' => 'Note',
        'plain' => 'the silver locket',
        'shares' => [Keys::b64($shares[1]), Keys::b64($shares[2])],
    ];
    $fixture = [
        'sign_body' => "lastwords.event.v1\ntype=relock\nmessage_id={$id}\nrecovery_seq=1\nrelocked_at=1700000500\n",
        'sign_secret' => Keys::b64($recovery['secret']),
        'cases' => [
            $base + ['events' => [$register], 'now' => 1700000000, 'expect' => 'locked'],
            $base + ['events' => [$register, $unlock], 'now' => 1700000100, 'expect' => 'pending'],
            $base + ['events' => [$register, $unlock], 'now' => 1700000000 + Protocol::UNLOCK_WINDOW, 'expect' => 'published'],
            $base + ['events' => [$register, $unlock, $relock], 'now' => 1700000000 + Protocol::UNLOCK_WINDOW, 'expect' => 'relocked'],
        ],
    ];
    $dir = temp_dir();
    $in = $dir . '/fixture.json';
    $out = $dir . '/result.json';
    file_put_contents($in, json_encode($fixture, JSON_THROW_ON_ERROR));
    $root = dirname(__DIR__);
    $command = escapeshellarg($node) . ' '
        . escapeshellarg($root . '/tests/js/check.js') . ' '
        . escapeshellarg($root . '/client/vendor/nacl.js') . ' '
        . escapeshellarg($root . '/client/protocol.js') . ' '
        . escapeshellarg($in) . ' '
        . escapeshellarg($out);
    $stdout = shell_exec($command . ' 2>&1');
    check(is_file($out), 'browser check failed: ' . $stdout);
    $result = json_decode((string) file_get_contents($out), true);
    check(is_array($result) && !empty($result['ok']), 'browser check did not return ok');
    $sig = Keys::b64decode((string) $result['signature']);
    check($sig !== null && Keys::verify($fixture['sign_body'], $sig, $recovery['public']), 'php rejected a browser signature');
    $protocol = file_get_contents($root . '/client/protocol.js');
    $copy = file_get_contents($root . '/public/assets/protocol.js');
    check($protocol !== false && $protocol === $copy, 'the service copy of protocol.js has drifted');
    $nacl = file_get_contents($root . '/client/vendor/nacl.js');
    $naclCopy = file_get_contents($root . '/public/assets/nacl.js');
    check($nacl !== false && $nacl === $naclCopy, 'the service copy of nacl.js has drifted');
}
