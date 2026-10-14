<?php

declare(strict_types=1);

namespace LastWords;

final class Network
{
    public function __construct(
        private Storage $db,
        private Message $messages,
        private Clock $clock,
        private string $signPublic,
        private string $signSecret,
        private string $publicUrl,
        private $httpGet,
    ) {
    }

    public function replaceKeys(string $public, string $secret): void
    {
        $this->signPublic = $public;
        $this->signSecret = $secret;
    }

    public function directoryDocument(): array
    {
        $body = Protocol::directory($this->publicUrl, Keys::b64($this->signPublic), Version::VERSION);
        $signature = Keys::sign($body, $this->signSecret);
        return [
            'directory' => $body,
            'signature' => Keys::b64($signature),
            'signer_public' => Keys::b64($this->signPublic),
            'rotations' => $this->rotations(),
        ];
    }

    public function rotateTo(string $newPublic, string $newSecret): void
    {
        $body = Protocol::rotation(Keys::b64($this->signPublic), Keys::b64($newPublic), $this->clock->now());
        $signature = Keys::sign($body, $this->signSecret);
        $this->db->run(
            'INSERT INTO key_rotations (body, signature, signer_public, created_at) VALUES (?, ?, ?, ?)',
            [$body, Keys::b64($signature), Keys::b64($this->signPublic), $this->clock->now()]
        );
        $this->signPublic = $newPublic;
        $this->signSecret = $newSecret;
    }

    public function trustPeer(string $endpoint): array
    {
        $endpoint = rtrim($endpoint, '/');
        Protocol::checkUrl($endpoint, true);
        $document = $this->fetchJson($endpoint . '/api/directory.php');
        $parsed = $this->verifiedDirectory($document, null);
        if (rtrim($parsed['endpoint'], '/') !== $endpoint) {
            throw new UserError('That service published a different address than the one you entered.');
        }
        $this->db->run(
            'INSERT INTO peers (endpoint, sign_pubkey, last_sync_at, last_error) VALUES (?, ?, NULL, NULL)
             ON CONFLICT(endpoint) DO UPDATE SET sign_pubkey = excluded.sign_pubkey, last_error = NULL',
            [$endpoint, $parsed['sign_pubkey']]
        );
        return $parsed;
    }

    public function peers(): array
    {
        return $this->db->all('SELECT endpoint, sign_pubkey, last_sync_at, last_error FROM peers ORDER BY endpoint ASC');
    }

    public function pullAll(): array
    {
        $results = [];
        foreach ($this->peers() as $peer) {
            try {
                $count = $this->pull((string) $peer['endpoint'], (string) $peer['sign_pubkey']);
                $this->db->run(
                    'UPDATE peers SET last_sync_at = ?, last_error = NULL WHERE endpoint = ?',
                    [$this->clock->now(), $peer['endpoint']]
                );
                $results[] = ['endpoint' => $peer['endpoint'], 'ok' => true, 'events' => $count];
            } catch (\Throwable $error) {
                $detail = Log::safe($error->getMessage());
                $this->db->run('UPDATE peers SET last_error = ? WHERE endpoint = ?', [$detail, $peer['endpoint']]);
                $this->messages->noteFailure('sync', $peer['endpoint'] . ' ' . $detail);
                $results[] = ['endpoint' => $peer['endpoint'], 'ok' => false, 'error' => $detail];
            }
        }
        return $results;
    }

    public function export(): array
    {
        $events = $this->messages->exportEvents();
        $document = $this->directoryDocument();
        return $document + [
            'messages' => $this->messages->exportMessages(),
            'events' => $events,
            'truncated' => count($events) >= 2000,
        ];
    }

    public static function acceptsPinnedKey(string $pinned, string $current, array $rotations): bool
    {
        $pinnedRaw = Keys::b64decode($pinned);
        $currentRaw = Keys::b64decode($current);
        if ($pinnedRaw === null || $currentRaw === null) {
            return false;
        }
        if (Keys::same($pinnedRaw, $currentRaw)) {
            return true;
        }
        $cursor = $pinned;
        $remaining = $rotations;
        for ($step = 0; $step < 20; $step++) {
            if (Keys::same(Keys::b64decode($cursor) ?? '', $currentRaw)) {
                return true;
            }
            $advanced = false;
            foreach ($remaining as $index => $rotation) {
                if (!is_array($rotation)) {
                    continue;
                }
                try {
                    $parsed = Protocol::parseRotation((string) ($rotation['body'] ?? ''));
                } catch (UserError) {
                    continue;
                }
                $sig = Keys::b64decode((string) ($rotation['signature'] ?? ''));
                $signer = Keys::b64decode((string) ($rotation['signer_public'] ?? ''));
                $old = Keys::b64decode($parsed['old_sign_pubkey']);
                if ($sig === null || $signer === null || $old === null) {
                    continue;
                }
                if (!Keys::same($signer, $old) || !Keys::same(Keys::b64decode($cursor) ?? '', $old)) {
                    continue;
                }
                if (!Keys::verify((string) $rotation['body'], $sig, $signer)) {
                    continue;
                }
                $cursor = $parsed['new_sign_pubkey'];
                unset($remaining[$index]);
                $advanced = true;
                break;
            }
            if (!$advanced) {
                return false;
            }
        }
        return false;
    }

    private function pull(string $endpoint, string $pinned): int
    {
        $data = $this->fetchJson($endpoint . '/api/sync.php');
        $directory = $this->verifiedDirectory($data, $pinned);
        if (rtrim($directory['endpoint'], '/') !== rtrim($endpoint, '/')) {
            throw new UserError('Peer directory address does not match.');
        }
        $events = is_array($data['events'] ?? null) ? $data['events'] : [];
        $messages = is_array($data['messages'] ?? null) ? $data['messages'] : [];
        foreach ($events as $index => $event) {
            if (!is_array($event)) {
                continue;
            }
            try {
                $parsed = Protocol::parse((string) ($event['body'] ?? ''));
            } catch (UserError) {
                continue;
            }
            if ($parsed['type'] !== 'revise') {
                continue;
            }
            foreach ($messages as $message) {
                if (!is_array($message) || ($message['message_id'] ?? '') !== $parsed['fields']['message_id']) {
                    continue;
                }
                if (!Keys::same($parsed['fields']['ciphertext_sha256'], (string) ($message['ciphertext_sha256'] ?? ''))) {
                    continue;
                }
                $events[$index]['ciphertext'] = $message['ciphertext'] ?? '';
                $events[$index]['nonce'] = $message['nonce'] ?? '';
            }
        }
        foreach ($messages as $message) {
            if (!is_array($message)) {
                continue;
            }
            $this->importReplicaMessage($message, $events);
        }
        $result = $this->messages->importBatch($events);
        if (($result['rejected'] ?? 0) > 0) {
            $this->messages->noteFailure('sync', 'Rejected ' . $result['rejected'] . ' events from ' . $endpoint);
        }
        return (int) $result['accepted'];
    }

    private function importReplicaMessage(array $message, array $events): void
    {
        $messageId = (string) ($message['message_id'] ?? '');
        $sawRegister = false;
        foreach ($events as $event) {
            if (!is_array($event)) {
                continue;
            }
            $body = (string) ($event['body'] ?? '');
            $sig = Keys::b64decode((string) ($event['signature'] ?? ''));
            $signer = Keys::b64decode((string) ($event['signer_public'] ?? ''));
            if ($sig === null || $signer === null || !Keys::verify($body, $sig, $signer)) {
                continue;
            }
            try {
                $parsed = Protocol::parse($body);
            } catch (UserError) {
                continue;
            }
            if ($parsed['fields']['message_id'] !== $messageId) {
                continue;
            }
            if ($parsed['type'] === 'register') {
                $sawRegister = true;
                $message['k'] = (int) $parsed['fields']['k'];
                $message['n'] = (int) $parsed['fields']['n'];
                $message['owner_page'] = $parsed['fields']['owner_page'];
                $message['created_at'] = (int) $parsed['fields']['created_at'];
                if (Keys::same($parsed['fields']['ciphertext_sha256'], (string) ($message['ciphertext_sha256'] ?? ''))) {
                    $this->messages->storeReplica($message);
                    return;
                }
            }
            if ($parsed['type'] === 'revise' && Keys::same($parsed['fields']['ciphertext_sha256'], (string) ($message['ciphertext_sha256'] ?? ''))) {
                if ($this->messages->hasMessage($messageId)) {
                    return;
                }
                $this->messages->replaceSealed($message);
                return;
            }
        }
        if ($sawRegister) {
            throw new UserError('Replica ciphertext does not match a signed version.');
        }
    }

    private function verifiedDirectory(array $document, ?string $pinned): array
    {
        $body = (string) ($document['directory'] ?? '');
        $sig = Keys::b64decode((string) ($document['signature'] ?? ''));
        $signer = Keys::b64decode((string) ($document['signer_public'] ?? ''));
        if ($sig === null || $signer === null || !Keys::verify($body, $sig, $signer)) {
            throw new UserError('Service directory signature is not valid.');
        }
        $parsed = Protocol::parseDirectory($body);
        if (!Keys::same($signer, Keys::b64decode($parsed['sign_pubkey']) ?? '')) {
            throw new UserError('Service directory key does not match its signature.');
        }
        $rotations = is_array($document['rotations'] ?? null) ? $document['rotations'] : [];
        if ($pinned !== null && !self::acceptsPinnedKey($pinned, $parsed['sign_pubkey'], $rotations)) {
            throw new UserError('Service identity does not match the key this installation pinned.');
        }
        return $parsed;
    }

    private function fetchJson(string $url): array
    {
        $httpGet = $this->httpGet;
        $raw = $httpGet($url);
        if (!is_string($raw) || strlen($raw) > 5000000) {
            throw new UserError('The other service sent too much data.');
        }
        try {
            $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new UserError('The other service returned malformed data.');
        }
        if (!is_array($data)) {
            throw new UserError('The other service returned malformed data.');
        }
        return $data;
    }

    private function rotations(): array
    {
        return $this->db->all('SELECT body, signature, signer_public FROM key_rotations ORDER BY id ASC');
    }
}
