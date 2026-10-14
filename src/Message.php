<?php

declare(strict_types=1);

namespace LastWords;

final class Message
{
    public function __construct(
        private Storage $db,
        private Clock $clock,
        private Mailer $mail,
        private string $storageKey,
        private string $publicUrl,
    ) {
    }

    public function submit(array $input, bool $replica = false): array
    {
        $body = $input['body'] ?? null;
        $signature = $input['signature'] ?? null;
        $signerPublic = $input['signer_public'] ?? null;
        if (!is_string($body) || !is_string($signature) || !is_string($signerPublic)) {
            throw new UserError('Event is malformed.');
        }
        $sig = Keys::b64decode($signature);
        $signer = Keys::b64decode($signerPublic);
        if ($sig === null || $signer === null || !Keys::verify($body, $sig, $signer)) {
            throw new UserError('Signature is not valid.');
        }
        $parsed = Protocol::parse($body);
        $hash = hash('sha256', $body . $sig);
        if ($parsed['type'] === 'register') {
            return $this->register($parsed['fields'], $body, $signature, $signerPublic, $hash, $input, $replica);
        }
        return $this->db->transaction(function () use ($parsed, $body, $signature, $signerPublic, $hash, $input, $replica) {
            return $this->apply($parsed, $body, $signature, $signerPublic, $hash, $input, $replica);
        });
    }

    public function importBatch(array $events): array
    {
        $accepted = 0;
        $rejected = 0;
        $pending = array_values($events);
        $guard = 0;
        while ($pending !== [] && $guard < 8) {
            $guard++;
            $next = [];
            $moved = false;
            foreach ($pending as $event) {
                try {
                    $this->submit([
                        'body' => $event['body'] ?? '',
                        'signature' => $event['signature'] ?? '',
                        'signer_public' => $event['signer_public'] ?? '',
                        'ciphertext' => $event['ciphertext'] ?? null,
                        'nonce' => $event['nonce'] ?? null,
                    ], true);
                    $accepted++;
                    $moved = true;
                } catch (UserError) {
                    $next[] = $event;
                }
            }
            if (!$moved) {
                $rejected = count($next);
                break;
            }
            $pending = $next;
        }
        return ['accepted' => $accepted, 'rejected' => $rejected];
    }

    public function reduce(string $messageId): State
    {
        return State::reduce($this->eventRows($messageId), $this->clock->now());
    }

    public function ids(): array
    {
        $rows = $this->db->all('SELECT message_id FROM messages ORDER BY created_at ASC');
        return array_map(static fn (array $row): string => (string) $row['message_id'], $rows);
    }

    public function view(string $messageId): array
    {
        if (!preg_match('/\A[a-f0-9]{32}\z/', $messageId)) {
            throw new UserError('Message not found.');
        }
        $row = $this->messageRow($messageId);
        if ($row === null) {
            throw new UserError('Message not found.');
        }
        $state = $this->reduce($messageId);
        $published = $state->status === 'published';
        $hidden = $state->status === 'relocked' || $state->status === 'invalid';
        $share = null;
        $shareIndex = null;
        if ($published && $row['share_cipher'] !== null && $row['share_nonce'] !== null) {
            $opened = Keys::unbox((string) $row['share_cipher'], (string) $row['share_nonce'], $this->storageKey);
            if ($opened !== null) {
                $share = Keys::b64($opened);
                $shareIndex = (int) $row['share_index'];
            }
        }
        return [
            'message_id' => $messageId,
            'state' => $state->status,
            'server_time' => $this->clock->now(),
            'k' => (int) $row['k'],
            'n' => (int) $row['n'],
            'owner_page' => $hidden ? null : (string) $row['owner_page'],
            'ciphertext' => $hidden ? null : Keys::b64((string) $row['ciphertext']),
            'nonce' => $hidden ? null : Keys::b64((string) $row['nonce']),
            'ciphertext_sha256' => (string) $row['ciphertext_sha256'],
            'share' => $share,
            'share_index' => $shareIndex,
            'deadline' => $state->currentUnlock['deadline'] ?? null,
            'request_id' => $state->currentUnlock['request_id'] ?? null,
            'recovery_seq' => $state->recoverySeq,
            'next_recovery_seq' => $state->nextRecoverySeq,
            'next_trusted_seq' => $state->nextTrustedSeq,
            'events' => $this->eventRows($messageId),
            'problems' => $state->problems,
        ];
    }

    public function queueDuePublications(): int
    {
        $queued = 0;
        foreach ($this->ids() as $messageId) {
            $state = $this->reduce($messageId);
            if ($state->status === 'relocked') {
                $this->wipeShare($messageId);
            }
            if ($state->status !== 'published' || $state->currentUnlock === null) {
                continue;
            }
            $requestId = (string) $state->currentUnlock['request_id'];
            if ($this->db->one('SELECT request_id FROM publications WHERE request_id = ?', [$requestId]) !== null) {
                continue;
            }
            $row = $this->messageRow($messageId);
            $email = $row === null ? null : $this->ownerEmail($row);
            $this->db->transaction(function () use ($requestId, $messageId, $state, $email, &$queued): void {
                if ($this->db->one('SELECT request_id FROM publications WHERE request_id = ?', [$requestId]) !== null) {
                    return;
                }
                $this->db->run(
                    'INSERT INTO publications (request_id, message_id, published_at) VALUES (?, ?, ?)',
                    [$requestId, $messageId, $this->clock->now()]
                );
                if ($email !== null) {
                    [$subject, $body] = Letters::published((string) $state->ownerPage, (int) $state->currentUnlock['deadline']);
                    $this->mail->queue('publish:' . $requestId, 'publish', $email, $subject, $body, $messageId);
                }
                $queued++;
            });
        }
        return $queued;
    }

    public function wipeShare(string $messageId): void
    {
        $this->db->run(
            'UPDATE messages SET share_index = NULL, share_nonce = NULL, share_cipher = NULL WHERE message_id = ?',
            [$messageId]
        );
    }

    public function noteFailure(string $kind, string $detail): void
    {
        $this->db->run(
            'INSERT INTO failures (happened_at, kind, detail) VALUES (?, ?, ?)',
            [$this->clock->now(), substr($kind, 0, 40), Log::safe($detail)]
        );
    }

    public function recentFailures(int $limit = 30): array
    {
        return $this->db->all(
            'SELECT happened_at, kind, detail FROM failures ORDER BY id DESC LIMIT ?',
            [$limit]
        );
    }

    public function hasMessage(string $messageId): bool
    {
        return $this->messageRow($messageId) !== null;
    }

    public function storeReplica(array $message): void
    {
        $messageId = (string) ($message['message_id'] ?? '');
        if ($this->messageRow($messageId) !== null) {
            return;
        }
        $cipher = Keys::b64decode((string) ($message['ciphertext'] ?? ''));
        $nonce = Keys::b64decode((string) ($message['nonce'] ?? ''));
        if ($cipher === null || $nonce === null) {
            throw new UserError('Replica is malformed.');
        }
        $hash = hash('sha256', $nonce . $cipher);
        if (!Keys::same($hash, (string) ($message['ciphertext_sha256'] ?? ''))) {
            throw new UserError('Replica ciphertext does not match its hash.');
        }
        $this->db->run(
            'INSERT INTO messages (message_id, created_at, k, n, ciphertext, nonce, ciphertext_sha256, owner_page)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $messageId,
                (int) ($message['created_at'] ?? $this->clock->now()),
                (int) $message['k'],
                (int) $message['n'],
                $cipher,
                $nonce,
                $hash,
                (string) $message['owner_page'],
            ]
        );
    }

    public function replaceSealed(array $message): void
    {
        $messageId = (string) ($message['message_id'] ?? '');
        $cipher = Keys::b64decode((string) ($message['ciphertext'] ?? ''));
        $nonce = Keys::b64decode((string) ($message['nonce'] ?? ''));
        if ($cipher === null || $nonce === null || strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new UserError('Replica is malformed.');
        }
        if (strlen($cipher) > Protocol::MAX_BODY_BYTES + 128) {
            throw new UserError('Ciphertext is too large.');
        }
        $hash = hash('sha256', $nonce . $cipher);
        if (!Keys::same($hash, (string) ($message['ciphertext_sha256'] ?? ''))) {
            throw new UserError('Replica ciphertext does not match its hash.');
        }
        $row = $this->messageRow($messageId);
        if ($row === null) {
            $this->db->run(
                'INSERT INTO messages (message_id, created_at, k, n, ciphertext, nonce, ciphertext_sha256, owner_page)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    $messageId,
                    (int) ($message['created_at'] ?? $this->clock->now()),
                    (int) $message['k'],
                    (int) $message['n'],
                    $cipher,
                    $nonce,
                    $hash,
                    (string) ($message['owner_page'] ?? ''),
                ]
            );
            return;
        }
        if (Keys::same((string) $row['ciphertext_sha256'], $hash)) {
            return;
        }
        $this->db->run(
            'UPDATE messages SET ciphertext = ?, nonce = ?, ciphertext_sha256 = ? WHERE message_id = ?',
            [$cipher, $nonce, $hash, $messageId]
        );
    }

    public function exportMessages(): array
    {
        $out = [];
        foreach ($this->db->all('SELECT * FROM messages') as $row) {
            $state = $this->reduce((string) $row['message_id']);
            if ($state->status === 'relocked') {
                continue;
            }
            $out[] = [
                'message_id' => $row['message_id'],
                'created_at' => (int) $row['created_at'],
                'k' => (int) $row['k'],
                'n' => (int) $row['n'],
                'ciphertext' => Keys::b64((string) $row['ciphertext']),
                'nonce' => Keys::b64((string) $row['nonce']),
                'ciphertext_sha256' => $row['ciphertext_sha256'],
                'owner_page' => $row['owner_page'],
            ];
        }
        return $out;
    }

    public function exportEvents(int $limit = 2000): array
    {
        return $this->db->all(
            'SELECT body, signature, signer_public, received_at, message_id FROM events ORDER BY received_at ASC LIMIT ?',
            [$limit]
        );
    }

    private function register(array $fields, string $body, string $signature, string $signerPublic, string $hash, array $input, bool $replica): array
    {
        $existing = $this->messageRow($fields['message_id']);
        if ($existing !== null) {
            $prior = $this->db->one('SELECT body FROM events WHERE message_id = ? AND event_type = ?', [$fields['message_id'], 'register']);
            if ($prior !== null && (string) $prior['body'] !== $body) {
                throw new UserError('This message id is already registered.');
            }
            if ($prior === null && !Keys::same((string) $existing['ciphertext_sha256'], $fields['ciphertext_sha256'])) {
                if (!Keys::same(Keys::b64decode($signerPublic) ?? '', Keys::b64decode($fields['recovery_pubkey']) ?? '')) {
                    throw new UserError('Registration must be signed by the recovery key.');
                }
            }
            $this->rememberEvent($fields['message_id'], 'register', $body, $signature, $signerPublic, $hash);
            return ['ok' => true, 'duplicate' => true];
        }
        if (!Keys::same(Keys::b64decode($signerPublic) ?? '', Keys::b64decode($fields['recovery_pubkey']) ?? '')) {
            throw new UserError('Registration must be signed by the recovery key.');
        }
        $cipher = Keys::b64decode((string) ($input['ciphertext'] ?? ''));
        $nonce = Keys::b64decode((string) ($input['nonce'] ?? ''));
        if ($cipher === null || $nonce === null || strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new UserError('Ciphertext is malformed.');
        }
        if (strlen($cipher) > Protocol::MAX_BODY_BYTES + 128) {
            throw new UserError('Ciphertext is too large.');
        }
        $sum = hash('sha256', $nonce . $cipher);
        if (!Keys::same($sum, $fields['ciphertext_sha256'])) {
            throw new UserError('Ciphertext does not match the signed hash.');
        }
        $shareIndex = null;
        $shareNonce = null;
        $shareCipher = null;
        if (!$replica && !isset($input['owner_email'])) {
            throw new UserError('The owner email address is required.');
        }
        if (!$replica) {
            $share = Keys::b64decode((string) ($input['share'] ?? ''));
            if ($share === null) {
                throw new UserError('The share for this service is missing.');
            }
            $parsedShare = $this->inspectShare($share);
            if ($parsedShare['k'] !== (int) $fields['k'] || $parsedShare['n'] !== (int) $fields['n']) {
                throw new UserError('The share does not match the registration.');
            }
            $commitments = Protocol::parseCommitments($fields['share_commitments'], (int) $fields['n']);
            $digest = hash('sha256', $share);
            if (!isset($commitments[$parsedShare['index']]) || !Keys::same($digest, $commitments[$parsedShare['index']])) {
                throw new UserError('The share does not match the signed commitment.');
            }
            $shareIndex = $parsedShare['index'];
            [$shareNonce, $shareCipher] = Keys::box($share, $this->storageKey);
        }
        $emailNonce = null;
        $emailCipher = null;
        if (!$replica && isset($input['owner_email'])) {
            $email = $this->email((string) $input['owner_email']);
            [$emailNonce, $emailCipher] = Keys::box($email, $this->storageKey);
        }
        $this->db->transaction(function () use ($fields, $cipher, $nonce, $shareIndex, $shareNonce, $shareCipher, $emailNonce, $emailCipher, $body, $signature, $signerPublic, $hash): void {
            $this->db->run(
                'INSERT INTO messages (message_id, created_at, k, n, ciphertext, nonce, ciphertext_sha256, owner_page, share_index, share_nonce, share_cipher, email_nonce, email_cipher)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    $fields['message_id'], (int) $fields['created_at'], (int) $fields['k'], (int) $fields['n'],
                    $cipher, $nonce, $fields['ciphertext_sha256'], $fields['owner_page'],
                    $shareIndex, $shareNonce, $shareCipher, $emailNonce, $emailCipher,
                ]
            );
            $this->rememberEvent($fields['message_id'], 'register', $body, $signature, $signerPublic, $hash);
        });
        return ['ok' => true];
    }

    private function apply(array $parsed, string $body, string $signature, string $signerPublic, string $hash, array $input, bool $replica): array
    {
        $fields = $parsed['fields'];
        $messageId = $fields['message_id'];
        $row = $this->messageRow($messageId);
        if ($row === null) {
            throw new UserError('Message not found.');
        }
        if ($this->db->one('SELECT event_hash FROM events WHERE event_hash = ?', [$hash]) !== null) {
            return ['ok' => true, 'duplicate' => true];
        }
        $state = $this->reduce($messageId);
        if ($state->status === 'invalid') {
            throw new UserError('Message is not usable.');
        }
        $signer = Keys::b64decode($signerPublic) ?? '';
        if ($parsed['type'] === 'unlock_request') {
            return $this->unlock($state, $fields, $body, $signature, $signerPublic, $signer, $hash, $input, $replica);
        }
        if ($parsed['type'] === 'cancel') {
            return $this->cancel($state, $row, $fields, $body, $signature, $signerPublic, $signer, $hash, $replica);
        }
        if ($parsed['type'] === 'relock' || $parsed['type'] === 'rotate_trusted' || $parsed['type'] === 'rotate_recovery') {
            return $this->recovery($state, $row, $parsed['type'], $fields, $body, $signature, $signerPublic, $signer, $hash, $replica);
        }
        if ($parsed['type'] === 'revise') {
            return $this->revise($state, $row, $fields, $body, $signature, $signerPublic, $signer, $hash, $input, $replica);
        }
        throw new UserError('Unknown event type.');
    }

    private function unlock(State $state, array $fields, string $body, string $signature, string $signerPublic, string $signer, string $hash, array $input, bool $replica): array
    {
        $now = $this->clock->now();
        $requested = (int) $fields['requested_at'];
        if (abs($now - $requested) > Protocol::ACCEPT_SKEW) {
            throw new UserError('The unlock request is outside the 10 minute acceptance window.');
        }
        $seq = (int) $fields['trusted_seq'];
        if ($seq < $state->nextTrustedSeq) {
            $prior = $this->unlockBody($fields['message_id'], $seq);
            if ($prior === $body) {
                return ['ok' => true, 'duplicate' => true];
            }
            if ($prior !== null) {
                $expected = Keys::b64decode($state->trustedPubkey) ?? '';
                if (!Keys::same($signer, $expected)) {
                    throw new UserError('The trusted person key does not match.');
                }
                $this->rememberEvent($fields['message_id'], 'unlock_request', $body, $signature, $signerPublic, $hash);
                return ['ok' => true, 'conflict' => true];
            }
        }
        if ($seq !== $state->nextTrustedSeq) {
            throw new UserError('The unlock sequence is not the next one.');
        }
        if ((int) $fields['seen_recovery_seq'] !== $state->recoverySeq) {
            throw new UserError('The unlock request does not match the latest recovery sequence.');
        }
        $expected = Keys::b64decode($state->trustedPubkey) ?? '';
        if (!Keys::same($signer, $expected)) {
            throw new UserError('The trusted person key does not match.');
        }
        if ($state->status === 'pending' || $state->status === 'published' || $state->status === 'conflict') {
            throw new UserError('A publication request is already in progress.');
        }
        $this->rememberEvent($fields['message_id'], 'unlock_request', $body, $signature, $signerPublic, $hash);
        $row = $this->messageRow($fields['message_id']);
        $email = $row === null ? null : $this->ownerEmail($row);
        if (!$replica) {
            $secret = Keys::b64decode((string) ($input['cancel_secret'] ?? ''));
            $cancelPub = Keys::b64decode($fields['cancel_pubkey']) ?? '';
            $fromSecret = $secret === null ? null : Keys::publicFromSecret($secret);
            if ($fromSecret === null || !Keys::same($fromSecret, $cancelPub)) {
                throw new UserError('The cancellation key does not match this request.');
            }
            if ($email !== null) {
                $link = $this->publicUrl . '/cancel.php#m=' . $fields['message_id']
                    . '&r=' . $fields['request_id']
                    . '&k=' . rawurlencode(Keys::b64($secret));
                [$subject, $text] = Letters::unlock($requested, (int) $fields['deadline'], $link);
                $this->mail->queue('unlock:' . $fields['request_id'], 'unlock', $email, $subject, $text, $fields['message_id']);
            } else {
                $this->noteFailure('email', 'Unlock was accepted but this service has no owner email to notify.');
            }
            $notice = trim((string) ($input['trusted_email'] ?? ''));
            if ($notice !== '') {
                $trusted = $this->email($notice);
                [$nonce, $cipher] = Keys::box($trusted, $this->storageKey);
                $this->db->run(
                    'INSERT OR IGNORE INTO request_contacts (request_id, message_id, email_nonce, email_cipher) VALUES (?, ?, ?, ?)',
                    [$fields['request_id'], $fields['message_id'], $nonce, $cipher]
                );
            }
        } elseif ($email !== null) {
            [$subject, $text] = Letters::unlockWarning($requested, (int) $fields['deadline']);
            $this->mail->queue('unlock-warn:' . $fields['request_id'], 'unlock-warn', $email, $subject, $text, $fields['message_id']);
        }
        return ['ok' => true];
    }

    private function cancel(State $state, array $row, array $fields, string $body, string $signature, string $signerPublic, string $signer, string $hash, bool $replica): array
    {
        if ($state->currentUnlock === null || $state->currentUnlock['request_id'] !== $fields['request_id']) {
            $known = $this->findUnlock($fields['message_id'], $fields['request_id']);
            if ($known !== null && !empty($state->cancelled[$fields['request_id']])) {
                return ['ok' => true, 'duplicate' => true];
            }
            throw new UserError('There is no matching publication request to cancel.');
        }
        if (!empty($state->cancelled[$fields['request_id']])) {
            return ['ok' => true, 'duplicate' => true];
        }
        $cancelKey = Keys::b64decode($state->currentUnlock['cancel_pubkey']) ?? '';
        if (!Keys::same($signer, $cancelKey)) {
            throw new UserError('The cancellation key does not match this request.');
        }
        $now = $this->clock->now();
        if (!$replica && abs($now - (int) $fields['cancelled_at']) > Protocol::ACCEPT_SKEW) {
            throw new UserError('The cancellation time is too far from this service clock.');
        }
        if ($now >= (int) $state->currentUnlock['deadline'] || $state->status !== 'pending') {
            throw new UserError('The waiting period is over. Use the emergency recovery key to re-lock.');
        }
        $this->rememberEvent($fields['message_id'], 'cancel', $body, $signature, $signerPublic, $hash);
        $email = $this->ownerEmail($row);
        if ($email !== null) {
            [$subject, $text] = Letters::cancelledOwner();
            $this->mail->queue('cancel-owner:' . $fields['request_id'], 'cancel-owner', $email, $subject, $text, $fields['message_id']);
        }
        $contact = $this->db->one('SELECT email_nonce, email_cipher FROM request_contacts WHERE request_id = ?', [$fields['request_id']]);
        if ($contact !== null && $contact['email_cipher'] !== null) {
            $trusted = Keys::unbox((string) $contact['email_cipher'], (string) $contact['email_nonce'], $this->storageKey);
            if ($trusted !== null) {
                [$subject, $text] = Letters::cancelledTrusted();
                $this->mail->queue('cancel-trusted:' . $fields['request_id'], 'cancel-trusted', $trusted, $subject, $text, $fields['message_id']);
            }
        }
        return ['ok' => true];
    }

    private function recovery(State $state, array $row, string $type, array $fields, string $body, string $signature, string $signerPublic, string $signer, string $hash, bool $replica): array
    {
        $seq = (int) $fields['recovery_seq'];
        if ($seq !== $state->nextRecoverySeq) {
            throw new UserError('The recovery sequence is not the next one.');
        }
        $expected = Keys::b64decode($state->recoveryPubkey) ?? '';
        if (!Keys::same($signer, $expected)) {
            throw new UserError('The recovery key does not match.');
        }
        $stampName = $type === 'relock' ? 'relocked_at' : 'rotated_at';
        if (!$replica && abs($this->clock->now() - (int) $fields[$stampName]) > Protocol::ACCEPT_SKEW) {
            throw new UserError('The recovery time is too far from this service clock.');
        }
        $this->rememberEvent($fields['message_id'], $type, $body, $signature, $signerPublic, $hash);
        if ($type === 'relock') {
            $this->wipeShare($fields['message_id']);
            $email = $this->ownerEmail($row);
            if ($email !== null) {
                [$subject, $text] = Letters::relocked();
                $this->mail->queue('relock:' . $fields['message_id'] . ':' . $seq, 'relock', $email, $subject, $text, $fields['message_id']);
            }
        }
        return ['ok' => true];
    }

    private function revise(State $state, array $row, array $fields, string $body, string $signature, string $signerPublic, string $signer, string $hash, array $input, bool $replica): array
    {
        $seq = (int) $fields['recovery_seq'];
        if ($seq !== $state->nextRecoverySeq) {
            throw new UserError('The recovery sequence is not the next one.');
        }
        $expected = Keys::b64decode($state->recoveryPubkey) ?? '';
        if (!Keys::same($signer, $expected)) {
            throw new UserError('The recovery key does not match.');
        }
        if (!$replica && abs($this->clock->now() - (int) $fields['revised_at']) > Protocol::ACCEPT_SKEW) {
            throw new UserError('The recovery time is too far from this service clock.');
        }
        $cipher = Keys::b64decode((string) ($input['ciphertext'] ?? ''));
        $nonce = Keys::b64decode((string) ($input['nonce'] ?? ''));
        if ($cipher === null || $nonce === null) {
            if ($replica) {
                $this->rememberEvent($fields['message_id'], 'revise', $body, $signature, $signerPublic, $hash);
                return ['ok' => true];
            }
            throw new UserError('Ciphertext is malformed.');
        }
        if (strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES || !Keys::same(Keys::b64($nonce), $fields['nonce'])) {
            throw new UserError('Ciphertext is malformed.');
        }
        if (strlen($cipher) > Protocol::MAX_BODY_BYTES + 128) {
            throw new UserError('Ciphertext is too large.');
        }
        $sum = hash('sha256', $nonce . $cipher);
        if (!Keys::same($sum, $fields['ciphertext_sha256'])) {
            throw new UserError('Ciphertext does not match the signed hash.');
        }
        $wasPending = $state->status === 'pending' && $state->currentUnlock !== null;
        $requestId = $wasPending ? (string) $state->currentUnlock['request_id'] : '';
        $this->db->run(
            'UPDATE messages SET ciphertext = ?, nonce = ?, ciphertext_sha256 = ? WHERE message_id = ?',
            [$cipher, $nonce, $sum, $fields['message_id']]
        );
        $this->rememberEvent($fields['message_id'], 'revise', $body, $signature, $signerPublic, $hash);
        $email = $this->ownerEmail($row);
        if ($email !== null) {
            [$subject, $text] = Letters::revised($wasPending);
            $this->mail->queue('revise:' . $fields['message_id'] . ':' . $seq, 'revise', $email, $subject, $text, $fields['message_id']);
        }
        if ($wasPending) {
            $contact = $this->db->one('SELECT email_nonce, email_cipher FROM request_contacts WHERE request_id = ?', [$requestId]);
            if ($contact !== null && $contact['email_cipher'] !== null) {
                $trusted = Keys::unbox((string) $contact['email_cipher'], (string) $contact['email_nonce'], $this->storageKey);
                if ($trusted !== null) {
                    [$subject, $text] = Letters::cancelledTrusted();
                    $this->mail->queue('cancel-trusted:' . $requestId, 'cancel-trusted', $trusted, $subject, $text, $fields['message_id']);
                }
            }
        }
        return ['ok' => true];
    }

    private function rememberEvent(string $messageId, string $type, string $body, string $signature, string $signerPublic, string $hash): void
    {
        $this->db->run(
            'INSERT OR IGNORE INTO events (event_hash, message_id, event_type, body, signature, signer_public, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)',
            [$hash, $messageId, $type, $body, $signature, $signerPublic, $this->clock->now()]
        );
    }

    private function messageRow(string $messageId): ?array
    {
        return $this->db->one('SELECT * FROM messages WHERE message_id = ?', [$messageId]);
    }

    private function ownerEmail(array $row): ?string
    {
        if ($row['email_cipher'] === null || $row['email_nonce'] === null) {
            return null;
        }
        $email = Keys::unbox((string) $row['email_cipher'], (string) $row['email_nonce'], $this->storageKey);
        if ($email === null) {
            return null;
        }
        try {
            return $this->email($email);
        } catch (UserError) {
            return null;
        }
    }

    private function email(string $value): string
    {
        $value = trim($value);
        if (strlen($value) > 200 || filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
            throw new UserError('Email address is not acceptable.');
        }
        return $value;
    }

    private function inspectShare(string $share): array
    {
        if (strlen($share) !== 4 + SODIUM_CRYPTO_SECRETBOX_KEYBYTES || ord($share[0]) !== 1) {
            throw new UserError('The share for this service is malformed.');
        }
        return ['index' => ord($share[1]), 'k' => ord($share[2]), 'n' => ord($share[3])];
    }

    private function eventRows(string $messageId): array
    {
        return $this->db->all(
            'SELECT body, signature, signer_public FROM events WHERE message_id = ? ORDER BY received_at ASC, event_hash ASC',
            [$messageId]
        );
    }

    private function unlockBody(string $messageId, int $seq): ?string
    {
        foreach ($this->eventRows($messageId) as $event) {
            try {
                $parsed = Protocol::parse((string) $event['body']);
            } catch (UserError) {
                continue;
            }
            if ($parsed['type'] === 'unlock_request' && (int) $parsed['fields']['trusted_seq'] === $seq) {
                return (string) $event['body'];
            }
        }
        return null;
    }

    private function findUnlock(string $messageId, string $requestId): ?array
    {
        foreach ($this->eventRows($messageId) as $event) {
            try {
                $parsed = Protocol::parse((string) $event['body']);
            } catch (UserError) {
                continue;
            }
            if ($parsed['type'] === 'unlock_request' && $parsed['fields']['request_id'] === $requestId) {
                return $parsed['fields'];
            }
        }
        return null;
    }
}
