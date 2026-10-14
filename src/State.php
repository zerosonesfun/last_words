<?php

declare(strict_types=1);

namespace LastWords;

// The log is the authority. Timestamps do not decide which event wins.
// Recovery events share one increasing sequence. A re-lock supersedes any
// unlock that acknowledged an older sequence. Publication is then just
// "the current unlock is still live and its signed deadline has passed."
final class State
{
    public string $status = 'invalid';
    public array $problems = [];
    public int $recoverySeq = 0;
    public int $nextRecoverySeq = 1;
    public int $maxRelockSeq = 0;
    public int $nextTrustedSeq = 1;
    public string $trustedPubkey = '';
    public string $recoveryPubkey = '';
    public string $messageId = '';
    public string $ownerPage = '';
    public int $k = 0;
    public int $n = 0;
    public ?array $currentUnlock = null;
    public array $cancelled = [];
    public string $ciphertextSha256 = '';
    public string $nonce = '';

    public static function reduce(array $events, int $now): self
    {
        $view = new self();
        $parsed = [];
        foreach ($events as $event) {
            $item = self::verified($event);
            if ($item === null) {
                $view->problems[] = 'Ignored an event with a bad signature or shape.';
                continue;
            }
            $parsed[$item['hash']] = $item;
        }

        $registers = [];
        foreach ($parsed as $item) {
            if ($item['type'] === 'register') {
                $registers[$item['body']] = $item;
            }
        }
        if (count($registers) !== 1) {
            $view->status = 'invalid';
            $view->problems[] = 'The message registration is missing or disputed.';
            return $view;
        }
        $register = array_values($registers)[0];
        $fields = $register['fields'];
        if (!Keys::same($register['signer'], Keys::b64decode($fields['recovery_pubkey']) ?? '')) {
            $view->status = 'invalid';
            return $view;
        }
        $k = (int) $fields['k'];
        $n = (int) $fields['n'];
        if ($k > $n) {
            $view->status = 'invalid';
            return $view;
        }
        try {
            Protocol::parseCommitments($fields['share_commitments'], $n);
        } catch (UserError) {
            $view->status = 'invalid';
            return $view;
        }

        $view->messageId = $fields['message_id'];
        $view->ownerPage = $fields['owner_page'];
        $view->k = $k;
        $view->n = $n;
        $view->ciphertextSha256 = $fields['ciphertext_sha256'];
        $view->nonce = $fields['nonce'];
        $view->recoveryPubkey = $fields['recovery_pubkey'];
        $recoveryRaw = Keys::b64decode($fields['recovery_pubkey']);
        $trustedRaw = Keys::b64decode($fields['trusted_pubkey']);
        $trustedHistory = [0 => $trustedRaw];

        $recoveryEvents = [];
        foreach ($parsed as $item) {
            if (!in_array($item['type'], ['relock', 'rotate_trusted', 'rotate_recovery', 'revise'], true)) {
                continue;
            }
            $seq = (int) $item['fields']['recovery_seq'];
            if ($seq < 1) {
                $view->problems[] = 'Ignored a recovery event with a bad sequence.';
                continue;
            }
            if (isset($recoveryEvents[$seq]) && $recoveryEvents[$seq]['body'] !== $item['body']) {
                $view->status = 'conflict';
                $view->problems[] = 'Two recovery events claim the same sequence.';
                return $view;
            }
            $recoveryEvents[$seq] = $item;
        }

        $expected = 1;
        $appliedRevises = [];
        while (isset($recoveryEvents[$expected])) {
            $item = $recoveryEvents[$expected];
            if (!Keys::same($item['signer'], $recoveryRaw)) {
                $view->problems[] = 'Stopped at a recovery event signed by the wrong key.';
                break;
            }
            if ($item['type'] === 'relock') {
                $view->maxRelockSeq = $expected;
            } elseif ($item['type'] === 'rotate_trusted') {
                $trustedRaw = Keys::b64decode($item['fields']['trusted_pubkey']);
            } elseif ($item['type'] === 'rotate_recovery') {
                $recoveryRaw = Keys::b64decode($item['fields']['new_recovery_pubkey']);
                $view->recoveryPubkey = $item['fields']['new_recovery_pubkey'];
            } elseif ($item['type'] === 'revise') {
                $view->ciphertextSha256 = $item['fields']['ciphertext_sha256'];
                $view->nonce = $item['fields']['nonce'];
                $appliedRevises[$expected] = $item;
            }
            $trustedHistory[$expected] = $trustedRaw;
            $view->trustedPubkey = Keys::b64($trustedRaw);
            $expected++;
        }
        $view->recoverySeq = $expected - 1;
        $view->nextRecoverySeq = $expected;
        if ($view->trustedPubkey === '') {
            $view->trustedPubkey = $fields['trusted_pubkey'];
        }

        $unlocks = [];
        $seqConflict = false;
        foreach ($parsed as $item) {
            if ($item['type'] !== 'unlock_request') {
                continue;
            }
            $seq = (int) $item['fields']['trusted_seq'];
            $seen = (int) $item['fields']['seen_recovery_seq'];
            $deadline = (int) $item['fields']['deadline'];
            $requested = (int) $item['fields']['requested_at'];
            if ($seq < 1 || $seen > $view->recoverySeq || $deadline !== $requested + Protocol::UNLOCK_WINDOW) {
                $view->problems[] = 'Ignored an unlock request that does not fit the log.';
                continue;
            }
            $expectedSigner = $trustedHistory[$seen] ?? null;
            if ($expectedSigner === null || !Keys::same($item['signer'], $expectedSigner)) {
                $view->problems[] = 'Ignored an unlock request signed by the wrong key.';
                continue;
            }
            if (isset($unlocks[$seq]) && $unlocks[$seq]['body'] !== $item['body']) {
                $view->problems[] = 'Two unlock requests claim the same sequence.';
                $seenA = (int) $unlocks[$seq]['fields']['seen_recovery_seq'];
                if ($seenA >= $view->maxRelockSeq || $seen >= $view->maxRelockSeq) {
                    $seqConflict = true;
                }
                continue;
            }
            $unlocks[$seq] = $item;
        }

        $admissible = [];
        $nextTrusted = 1;
        while (isset($unlocks[$nextTrusted])) {
            $admissible[$nextTrusted] = $unlocks[$nextTrusted];
            $nextTrusted++;
        }
        $view->nextTrustedSeq = $nextTrusted;

        foreach ($parsed as $item) {
            if ($item['type'] !== 'cancel') {
                continue;
            }
            $requestId = $item['fields']['request_id'];
            $unlock = null;
            foreach ($admissible as $candidate) {
                if ($candidate['fields']['request_id'] === $requestId) {
                    $unlock = $candidate;
                }
            }
            if ($unlock === null) {
                continue;
            }
            $cancelKey = Keys::b64decode($unlock['fields']['cancel_pubkey']);
            if ($cancelKey === null || !Keys::same($item['signer'], $cancelKey)) {
                $view->problems[] = 'Ignored a cancellation signed by the wrong key.';
                continue;
            }
            $view->cancelled[$requestId] = true;
        }

        if ($seqConflict) {
            $view->status = 'conflict';
            return $view;
        }

        $current = null;
        foreach ($admissible as $unlock) {
            $seen = (int) $unlock['fields']['seen_recovery_seq'];
            if ($seen < $view->maxRelockSeq || self::voidedByRevise($unlock, $appliedRevises)) {
                continue;
            }
            $current = $unlock['fields'];
        }
        $view->currentUnlock = $current;

        if ($current === null) {
            $view->status = $view->maxRelockSeq > 0 ? 'relocked' : 'locked';
            return $view;
        }
        if (!empty($view->cancelled[$current['request_id']])) {
            $view->status = 'locked';
            return $view;
        }
        if ($now < (int) $current['deadline']) {
            $view->status = 'pending';
            return $view;
        }
        $view->status = 'published';
        return $view;
    }

    private static function voidedByRevise(array $unlock, array $revises): bool
    {
        $seen = (int) $unlock['fields']['seen_recovery_seq'];
        $deadline = (int) $unlock['fields']['deadline'];
        foreach ($revises as $seq => $item) {
            if ((int) $seq <= $seen) {
                continue;
            }
            if ((int) $item['fields']['revised_at'] < $deadline) {
                return true;
            }
        }
        return false;
    }

    private static function verified(array $event): ?array
    {
        $body = $event['body'] ?? null;
        $signature = $event['signature'] ?? null;
        $signerPublic = $event['signer_public'] ?? null;
        if (!is_string($body) || !is_string($signature) || !is_string($signerPublic)) {
            return null;
        }
        $sig = Keys::b64decode($signature);
        $signer = Keys::b64decode($signerPublic);
        if ($sig === null || $signer === null) {
            return null;
        }
        if (!Keys::verify($body, $sig, $signer)) {
            return null;
        }
        try {
            $parsed = Protocol::parse($body);
        } catch (UserError) {
            return null;
        }
        return [
            'type' => $parsed['type'],
            'fields' => $parsed['fields'],
            'body' => $body,
            'signer' => $signer,
            'hash' => hash('sha256', $body . $sig),
        ];
    }
}
