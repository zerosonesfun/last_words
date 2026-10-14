<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/autoload.php';
require dirname(__DIR__) . '/src/Web.php';

require_app();
$body = '<h1>Cancel a publication request</h1>';
$body .= '<p>Someone asked to publish your Last Words message. Opening this page does not cancel that request. If you want to keep the message private, confirm below. You will need the link from the email, because the cancellation key is part of that link.</p>';
$body .= '<p id="cancel-status" class="note">Read this first. Then confirm if you want the request cancelled.</p>';
$body .= '<button type="button" id="cancel-go">Cancel this request</button>';
$body .= '<p class="muted">This does not retire the trusted person key. If the message is already public, use your recovery file instead. Re-locking cannot erase copies other people already have.</p>';
render_page('Cancel a publication request', $body, ['assets/nacl.js', 'assets/protocol.js', 'assets/cancel.js']);
