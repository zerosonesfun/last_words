<?php

declare(strict_types=1);

use LastWords\Keys;
use LastWords\Protocol;
use LastWords\Shamir;
use LastWords\State;

function test_shamir_roundtrip_and_threshold(): void
{
    check_same(Shamir::mul(0x57, 0x83), 0xc1, 'GF multiply test vector');
    $secret = random_bytes(32);
    $shares = Shamir::split($secret, 3, 5);
    check_same(strlen($shares[1]), 36, 'share size');
    $subsets = [
        [1, 2, 3],
        [1, 4, 5],
        [2, 3, 5],
        [1, 2, 3, 4],
    ];
    foreach ($subsets as $indexes) {
        $picked = [];
        foreach ($indexes as $index) {
            $picked[] = $shares[$index];
        }
        check_same(Shamir::join($picked), $secret, 'subset should rebuild the key');
    }
    $tooFew = false;
    try {
        Shamir::join([$shares[1], $shares[2]]);
    } catch (Throwable) {
        $tooFew = true;
    }
    check($tooFew, 'two shares must not satisfy a threshold of three');
    $single = Shamir::split($secret, 1, 1);
    check_same(Shamir::join([$single[1]]), $secret, 'a single share is the degraded case');
}

function test_secretbox_binds_message_id(): void
{
    $id = Keys::id();
    $key = random_bytes(32);
    $plain = Keys::encodeMessage($id, 'Note', 'the silver locket');
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = sodium_crypto_secretbox($plain, $nonce, $key);
    $opened = sodium_crypto_secretbox_open($cipher, $nonce, $key);
    $decoded = Keys::decodeMessage($opened, $id);
    check($decoded !== null && $decoded['body'] === 'the silver locket', 'decrypts to the original text');
    check(Keys::decodeMessage($opened, Keys::id()) === null, 'a swapped message id is rejected');
}

function test_bad_signature_does_not_change_state(): void
{
    $recovery = Keys::signPair();
    $trusted = Keys::signPair();
    $body = Protocol::build('register', [
        'message_id' => Keys::id(),
        'created_at' => '1700000000',
        'k' => '1',
        'n' => '1',
        'ciphertext_sha256' => str_repeat('ab', 32),
        'nonce' => Keys::b64(random_bytes(24)),
        'trusted_pubkey' => Keys::b64($trusted['public']),
        'recovery_pubkey' => Keys::b64($recovery['public']),
        'owner_page' => 'https://example.com/words',
        'services' => 'https://example.com/service',
        'share_commitments' => '1:' . str_repeat('cd', 32),
    ]);
    $state = State::reduce([
        [
            'body' => $body,
            'signature' => Keys::b64(random_bytes(64)),
            'signer_public' => Keys::b64($recovery['public']),
        ],
    ], 1700000000);
    check_same($state->status, 'invalid', 'an invalid signature is not a registration');
}

function test_relock_sequence_beats_an_older_unlock(): void
{
    $recovery = Keys::signPair();
    $trusted = Keys::signPair();
    $cancel = Keys::signPair();
    $id = Keys::id();
    $nonce = Keys::b64(random_bytes(24));
    $register = sign_event('register', [
        'message_id' => $id,
        'created_at' => '1700000000',
        'k' => '1',
        'n' => '1',
        'ciphertext_sha256' => str_repeat('ab', 32),
        'nonce' => $nonce,
        'trusted_pubkey' => Keys::b64($trusted['public']),
        'recovery_pubkey' => Keys::b64($recovery['public']),
        'owner_page' => 'https://example.com/words',
        'services' => 'https://example.com/service',
        'share_commitments' => '1:' . str_repeat('cd', 32),
    ], $recovery['secret'], $recovery['public']);
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
        'relocked_at' => '1700001000',
    ], $recovery['secret'], $recovery['public']);
    $afterDeadline = 1700000000 + Protocol::UNLOCK_WINDOW + 10;
    $published = State::reduce([$register, $unlock], $afterDeadline);
    check_same($published->status, 'published', 'deadline without a re-lock publishes');
    $hidden = State::reduce([$register, $unlock, $relock], $afterDeadline);
    check_same($hidden->status, 'relocked', 'a later re-lock supersedes the deadline');
    $early = State::reduce([$register, $unlock], 1700000000 + 10);
    check_same($early->status, 'pending', 'the message stays private before the deadline');
}
