<?php

declare(strict_types=1);

use LastWords\App;
use LastWords\Backup;
use LastWords\FakeClock;
use LastWords\Keys;
use LastWords\MemoryTransport;
use LastWords\Protocol;
use LastWords\Shamir;
use LastWords\State;
use LastWords\UserError;

function test_locked_message_is_not_stored_as_plaintext(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8101', $clock, $mail);
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    $view = $app->messages->view($message['id']);
    check_same($view['state'], 'locked', 'a new message is locked');
    check($view['share'] === null, 'a locked message does not include a share');
    $raw = file_get_contents($app->dataDir . '/service.sqlite');
    check(is_string($raw) && !str_contains($raw, 'the silver locket'), 'sqlite does not contain the plaintext');
    check(!str_contains(json_encode($view), 'the silver locket'), 'the API view does not contain the plaintext');
}

function test_unlock_mail_cancel_and_a_second_request(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8102', $clock, $mail);
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    $bad = Keys::signPair();
    $rejected = false;
    try {
        $fields = [
            'message_id' => $message['id'],
            'request_id' => Keys::id(),
            'trusted_seq' => '1',
            'seen_recovery_seq' => '0',
            'requested_at' => (string) $clock->now(),
            'deadline' => (string) ($clock->now() + Protocol::UNLOCK_WINDOW),
            'cancel_pubkey' => Keys::b64(Keys::signPair()['public']),
        ];
        $event = sign_event('unlock_request', $fields, $bad['secret'], $bad['public']);
        $app->messages->submit($event + ['cancel_secret' => Keys::b64(Keys::signPair()['secret'])]);
    } catch (UserError) {
        $rejected = true;
    }
    check($rejected, 'a different key cannot start a request');
    $unlock = request_unlock($app, $message, $clock, 1, 0);
    $again = $app->messages->submit($unlock['event'] + ['cancel_secret' => Keys::b64($unlock['cancel']['secret'])]);
    check(!empty($again['duplicate']), 'the same request is idempotent');
    $app->mail->drain();
    $letters = array_values(array_filter($mail->sent, static fn (array $item): bool => $item['subject'] === 'A request to publish your Last Words message'));
    check(count($letters) === 1, 'one request sends one owner email');
    check(!str_contains($letters[0]['body'], 'the silver locket'), 'the email does not include the message');
    check(!str_contains($letters[0]['body'], Keys::b64($message['trusted']['secret'])), 'the email does not include the trusted key');
    check_same($app->messages->view($message['id'])['state'], 'pending', 'the request is pending');
    $clock->advance(Protocol::UNLOCK_WINDOW - 1);
    check_same($app->messages->reduce($message['id'])->status, 'pending', 'one second early is still private');
    $cancelFields = [
        'message_id' => $message['id'],
        'request_id' => $unlock['fields']['request_id'],
        'cancelled_at' => (string) $clock->now(),
    ];
    $cancel = sign_event('cancel', $cancelFields, $unlock['cancel']['secret'], $unlock['cancel']['public']);
    $app->messages->submit($cancel);
    $app->mail->drain();
    check_same($app->messages->view($message['id'])['state'], 'locked', 'cancellation returns the message to locked');
    $clock->advance(2);
    $app->scheduler->run(true);
    check_same($app->messages->view($message['id'])['state'], 'locked', 'a cancelled request does not publish at the old deadline');
    $second = request_unlock($app, $message, $clock, 2, 0);
    check_same($app->messages->view($message['id'])['state'], 'pending', 'the trusted person can request again');
    check($second['fields']['request_id'] !== $unlock['fields']['request_id'], 'the new request has its own id');
}

function test_publication_after_thirty_days_is_idempotent(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8103', $clock, $mail);
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    request_unlock($app, $message, $clock, 1, 0);
    $clock->advance(Protocol::UNLOCK_WINDOW);
    $first = $app->scheduler->run(true);
    $second = $app->scheduler->run(true);
    $view = $app->messages->view($message['id']);
    check_same($view['state'], 'published', 'the deadline publishes the message');
    check(is_string($view['share']), 'the share is released only once the deadline has passed');
    $key = Shamir::join([Keys::b64decode($view['share'])]);
    $plain = sodium_crypto_secretbox_open($message['cipher'], $message['nonce'], $key);
    $decoded = Keys::decodeMessage($plain, $message['id']);
    check($decoded !== null && $decoded['body'] === 'the silver locket', 'the released share decrypts the message');
    $publishMails = array_values(array_filter($mail->sent, static fn (array $item): bool => str_contains($item['subject'], 'can now be read')));
    check(count($publishMails) === 1, 'publication mail is sent once');
    check($first['published'] === 1 && $second['published'] === 0, 'a second scheduler run does not publish again');
}

function test_email_failure_keeps_the_notice_and_still_publishes_once(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8104', $clock, $mail);
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    request_unlock($app, $message, $clock, 1, 0);
    $app->mail->drain();
    $mail->fail = true;
    $clock->advance(Protocol::UNLOCK_WINDOW);
    $app->scheduler->run(true);
    check_same($app->messages->view($message['id'])['state'], 'published', 'mail failure does not hold the state back');
    check(($app->mail->summary()['pending'] + $app->mail->summary()['failed']) >= 1, 'the failed notice stays queued');
    $mail->fail = false;
    $clock->advance(120);
    $app->scheduler->run(true);
    $publishMails = array_values(array_filter($mail->sent, static fn (array $item): bool => str_contains($item['subject'], 'can now be read')));
    check(count($publishMails) === 1, 'the retried notice is sent once');
}

function test_relock_before_and_after_publication(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $before = install_app('http://127.0.0.1:8105', $clock, $mail);
    $message = make_message([$before], $clock, 'For my brother', 'the silver locket', 1);
    request_unlock($before, $message, $clock, 1, 0);
    $relock = sign_event('relock', [
        'message_id' => $message['id'],
        'recovery_seq' => '1',
        'relocked_at' => (string) $clock->now(),
    ], $message['recovery']['secret'], $message['recovery']['public']);
    $before->messages->submit($relock);
    $clock->advance(Protocol::UNLOCK_WINDOW + 5);
    $before->scheduler->run(true);
    $view = $before->messages->view($message['id']);
    check_same($view['state'], 'relocked', 'a re-lock before the deadline prevents publication');
    check($view['share'] === null && $view['ciphertext'] === null, 'a re-lock removes the message from the public view');

    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $after = install_app('http://127.0.0.1:8106', $clock, $mail);
    $message = make_message([$after], $clock, 'For my brother', 'the silver locket', 1);
    request_unlock($after, $message, $clock, 1, 0);
    $clock->advance(Protocol::UNLOCK_WINDOW);
    $after->scheduler->run(true);
    check_same($after->messages->view($message['id'])['state'], 'published', 'published before the emergency key is used');
    $relock = sign_event('relock', [
        'message_id' => $message['id'],
        'recovery_seq' => '1',
        'relocked_at' => (string) $clock->now(),
    ], $message['recovery']['secret'], $message['recovery']['public']);
    $after->messages->submit($relock);
    $view = $after->messages->view($message['id']);
    check_same($view['state'], 'relocked', 're-lock after publication hides the message again');
    check($view['share'] === null && $view['ciphertext'] === null, 'shares and ciphertext leave the public response');
    $clock->advance(86400);
    $after->scheduler->run(true);
    check_same($after->messages->view($message['id'])['state'], 'relocked', 'an old deadline does not undo the re-lock');
}

function test_two_services_sync_failover_and_stale_replica(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mailA = new MemoryTransport();
    $mailB = new MemoryTransport();
    $mailC = new MemoryTransport();
    $a = install_app('http://127.0.0.1:8111', $clock, $mailA);
    $b = install_app('http://127.0.0.1:8112', $clock, $mailB);
    $c = install_app('http://127.0.0.1:8113', $clock, $mailC);
    $message = make_message([$a, $b, $c], $clock, 'For my brother', 'the silver locket', 2);
    link_apps($a, $b);
    $unlock = request_unlock($a, $message, $clock, 1, 0);
    $b->scheduler->run(false);
    check_same($b->messages->view($message['id'])['state'], 'pending', 'a peer learns the request by syncing');
    $clock->advance(Protocol::UNLOCK_WINDOW);
    $b->messages->submit(sign_event('relock', [
        'message_id' => $message['id'],
        'recovery_seq' => '1',
        'relocked_at' => (string) $clock->now(),
    ], $message['recovery']['secret'], $message['recovery']['public']));
    $a->scheduler->run(true);
    check_same($a->messages->view($message['id'])['state'], 'relocked', 'an older replica picks up the re-lock before it releases a share');
    check($a->messages->view($message['id'])['share'] === null, 'the stale service does not release its share');

    $clock = new FakeClock(1_700_000_000);
    $mailA = new MemoryTransport();
    $mailB = new MemoryTransport();
    $mailC = new MemoryTransport();
    $a = install_app('http://127.0.0.1:8121', $clock, $mailA);
    $b = install_app('http://127.0.0.1:8122', $clock, $mailB);
    $c = install_app('http://127.0.0.1:8123', $clock, $mailC);
    $message = make_message([$a, $b, $c], $clock, 'For my brother', 'the silver locket', 2);
    request_unlock($a, $message, $clock, 1, 0);
    request_unlock($b, $message, $clock, 1, 0);
    $clock->advance(Protocol::UNLOCK_WINDOW);
    $a->scheduler->run(true);
    $b->scheduler->run(true);
    $shares = [
        Keys::b64decode((string) $a->messages->view($message['id'])['share']),
        Keys::b64decode((string) $b->messages->view($message['id'])['share']),
    ];
    $key = Shamir::join($shares);
    $plain = sodium_crypto_secretbox_open($message['cipher'], $message['nonce'], $key);
    check(Keys::decodeMessage($plain, $message['id'])['body'] === 'the silver locket', 'two of three services can reconstruct the key');
    check($c->messages->view($message['id'])['state'] === 'locked', 'a service that never saw the request does not invent publication');

    $events = $a->messages->view($message['id'])['events'];
    $events[] = [
        'body' => $events[0]['body'],
        'signature' => Keys::b64(random_bytes(64)),
        'signer_public' => $events[0]['signer_public'],
    ];
    $merged = State::reduce($events, $clock->now());
    check_same($merged->status, 'published', 'a bad signature is ignored and the valid log still stands');
}

function test_conflicting_unlocks_do_not_publish(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8131', $clock, $mail);
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    $first = request_unlock($app, $message, $clock, 1, 0);
    $cancel = Keys::signPair();
    $fields = $first['fields'];
    $fields['request_id'] = Keys::id();
    $fields['cancel_pubkey'] = Keys::b64($cancel['public']);
    $second = sign_event('unlock_request', $fields, $message['trusted']['secret'], $message['trusted']['public']);
    $result = $app->messages->submit($second + ['cancel_secret' => Keys::b64($cancel['secret'])]);
    check(!empty($result['conflict']), 'a second body for the same sequence is kept as a conflict');
    $clock->advance(Protocol::UNLOCK_WINDOW);
    $app->scheduler->run(true);
    $view = $app->messages->view($message['id']);
    check_same($view['state'], 'conflict', 'conflict fails closed');
    check($view['share'] === null, 'a conflict does not release a share');
}

function test_service_key_rotation_and_backup_restore(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8141', $clock, $mail);
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    $old = Keys::b64($app->signPublic);
    $new = $app->rotateServiceKey();
    check($old !== $new, 'rotation changes the public key');
    $document = $app->network->directoryDocument();
    check(LastWords\Network::acceptsPinnedKey($old, $document['signer_public'], $document['rotations']), 'the old pin follows the signed rotation');
    $otherMail = new MemoryTransport();
    $other = install_app('http://127.0.0.1:8142', $clock, $otherMail);
    $router = static function (string $url) use ($app, $other): string {
        $target = str_starts_with($url, 'http://127.0.0.1:8141') ? $app : $other;
        if (str_contains($url, '/api/directory.php')) {
            return json_encode($target->network->directoryDocument(), JSON_THROW_ON_ERROR);
        }
        return json_encode($target->network->export(), JSON_THROW_ON_ERROR);
    };
    $app->network = new LastWords\Network($app->storage, $app->messages, $app->clock, $app->signPublic, $app->signSecret, 'http://127.0.0.1:8141', $router);
    $other->network = new LastWords\Network($other->storage, $other->messages, $other->clock, $other->signPublic, $other->signSecret, 'http://127.0.0.1:8142', $router);
    $app->network->trustPeer('http://127.0.0.1:8142');
    $pulled = $app->network->pullAll();
    check($pulled[0]['ok'] === true, 'sync accepts a peer with a valid directory signature');
    $archive = $app->backup('correct horse battery');
    $restored = temp_dir();
    Backup::restore($restored, 'correct horse battery', $archive);
    $opened = App::open($restored, $clock, $mail, static fn (): string => '');
    check_same($opened->messages->view($message['id'])['state'], 'locked', 'restore brings the message log back');
    $bad = false;
    try {
        Backup::restore(temp_dir(), 'wrong password here', $archive);
    } catch (UserError) {
        $bad = true;
    }
    check($bad, 'a wrong backup password is refused');
}

function test_rate_limit_and_malformed_requests(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8151', $clock, $mail);
    $allowed = 0;
    for ($i = 0; $i < 7; $i++) {
        if ($app->rates->allow('login:203.0.113.5', 5, 900)) {
            $allowed++;
        }
    }
    check_same($allowed, 5, 'the sixth attempt in the window is refused');
    $malformed = false;
    try {
        $app->messages->submit(['body' => 'nope', 'signature' => 'aa', 'signer_public' => 'bb']);
    } catch (UserError $error) {
        $malformed = true;
        $app->messages->noteFailure('request', $error->getMessage());
    }
    check($malformed, 'malformed events are rejected');
    $detail = $app->messages->recentFailures()[0]['detail'];
    check(!str_contains($detail, 'nope'), 'failure notes do not echo the submitted payload');
}

function test_a_rewrite_replaces_the_seal_and_drops_a_pending_request(): void
{
    $clock = new FakeClock(1_700_000_000);
    $mail = new MemoryTransport();
    $app = install_app('http://127.0.0.1:8161', $clock, $mail);
    $peer = install_app('http://127.0.0.1:8162', $clock, new MemoryTransport());
    $message = make_message([$app, $peer], $clock, 'For my brother', 'the silver locket', 2);
    link_apps($app, $peer);
    request_unlock($app, $message, $clock, 1, 0);
    $rejected = false;
    try {
        submit_revision($app, $message, $clock, 1, 'For my brother', 'a later letter', $message['trusted']);
    } catch (UserError) {
        $rejected = true;
    }
    check($rejected, 'the trusted person key cannot replace the sealed text');
    submit_revision($app, $message, $clock, 1, 'For my brother', 'a later letter', $message['recovery']);
    $view = $app->messages->view($message['id']);
    check_same($view['state'], 'locked', 'a rewrite drops the waiting request');
    check($view['ciphertext_sha256'] !== $message['fields']['ciphertext_sha256'], 'the service stores the new sealed text');
    check_same(open_view($view, $message['shares'], $message['id']), 'a later letter', 'the old shares open the new words');
    $app->mail->drain();
    $letters = array_values(array_filter($mail->sent, static fn (array $item): bool => $item['subject'] === 'Your Last Words message was updated'));
    check(count($letters) === 1, 'the owner is told the words were replaced');
    $again = false;
    try {
        submit_revision($app, $message, $clock, 1, 'For my brother', 'too late for this sequence', $message['recovery']);
    } catch (UserError) {
        $again = true;
    }
    check($again, 'a second save needs the next sequence');
    submit_revision($app, $message, $clock, 2, 'For my brother', 'the newest letter', $message['recovery']);
    $clock->advance(Protocol::UNLOCK_WINDOW + 5);
    $app->scheduler->run(true);
    $latest = $app->messages->view($message['id']);
    check_same($latest['state'], 'locked', 'the dropped request does not publish at the old deadline');
    $peer->scheduler->run(false);
    $copied = $peer->messages->view($message['id']);
    check_same($copied['ciphertext_sha256'], $latest['ciphertext_sha256'], 'a peer stores the replacement');
    check_same(open_view($copied, $message['shares'], $message['id']), 'the newest letter', 'the peer copy opens with the old shares');
}

function test_a_published_page_follows_the_new_text(): void
{
    $clock = new FakeClock(1_700_000_000);
    $app = install_app('http://127.0.0.1:8163', $clock, new MemoryTransport());
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    request_unlock($app, $message, $clock, 1, 0);
    $clock->advance(Protocol::UNLOCK_WINDOW);
    $app->scheduler->run(true);
    check_same($app->messages->view($message['id'])['state'], 'published', 'the original request publishes');
    submit_revision($app, $message, $clock, 1, 'For my brother', 'the words I mean now', $message['recovery']);
    $view = $app->messages->view($message['id']);
    check_same($view['state'], 'published', 'a later rewrite stays public');
    check($view['share'] !== null, 'the same share still opens the message');
    check_same(open_view($view, $message['shares'], $message['id']), 'the words I mean now', 'the public copy is the new text');
}

function submit_revision(App $app, array $message, FakeClock $clock, int $seq, string $title, string $bodyText, array $signer): void
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain = Keys::encodeMessage($message['id'], $title, $bodyText);
    $cipher = sodium_crypto_secretbox($plain, $nonce, $message['key']);
    $fields = [
        'message_id' => $message['id'],
        'recovery_seq' => (string) $seq,
        'revised_at' => (string) $clock->now(),
        'ciphertext_sha256' => hash('sha256', $nonce . $cipher),
        'nonce' => Keys::b64($nonce),
    ];
    $event = sign_event('revise', $fields, $signer['secret'], $signer['public']);
    $app->messages->submit($event + [
        'ciphertext' => Keys::b64($cipher),
        'nonce' => Keys::b64($nonce),
    ]);
}

function open_view(array $view, array $shares, string $id): string
{
    $key = Shamir::join(array_values($shares));
    $nonce = Keys::b64decode((string) $view['nonce']);
    $cipher = Keys::b64decode((string) $view['ciphertext']);
    $plain = ($nonce !== null && $cipher !== null) ? sodium_crypto_secretbox_open($cipher, $nonce, $key) : false;
    $decoded = is_string($plain) ? Keys::decodeMessage($plain, $id) : null;
    if ($decoded === null) {
        throw new RuntimeException('The sealed text did not open.');
    }
    return $decoded['body'];
}
