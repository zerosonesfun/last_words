<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/autoload.php';
require dirname(__DIR__) . '/src/Web.php';

$repo = 'https://github.com/zerosonesfun/last_words';
$url = '';
try {
    $app = open_installed_app();
    if ($app !== null) {
        $repo = (string) ($app->config['source_repository'] ?? $repo);
        $url = (string) ($app->config['public_url'] ?? '');
    }
} catch (Throwable) {
    $repo = 'https://github.com/zerosonesfun/last_words';
}

$here = $url !== '' ? '<p>This service is at <code>' . e($url) . '</code>.</p>' : '';

$body = <<<HTML
<h1>Become a Last Words service</h1>
<p>A service stores encrypted messages, one share of each message key, and a signed history of unlock, cancel, re-lock, and rewrite events. It sends the notification emails. It does not need permission from any other operator, including the person who published this software.</p>
{$here}
<h2>Why more than one service</h2>
<p>A person's page can list several services. If one is offline, the others can still accept a signed event. Reading a published message takes enough shares to meet the threshold, usually two. One operator, or one broken server, is not supposed to be a single point of failure or a single reader of a locked message.</p>
<p>That holds when the owner chose a threshold above one. A setup that uses only your service is weaker: you would hold the only share. The owner's setup page says so before they continue.</p>
<h2>What you can and cannot see</h2>
<p>You can see message ids, ciphertext, your own key share, service public keys, and the owner's email address on messages that named you as a notifier. You need the email address in order to send mail. You cannot read a locked message from your share alone when the threshold is two or higher. You cannot invent a valid unlock, cancellation, re-lock, or rewrite, because those are signed by keys you do not have. A rewrite keeps the same message key, so a service that already holds every share can read the new words too.</p>
<p>You do learn the one-time cancellation key for a request when your service is the one that emails it. A dishonest operator could cancel that request. Cancellation keeps the message locked. It does not reveal the message or let you publish it.</p>
<h2>Requirements</h2>
<ul>
<li>PHP 8.2 or newer, with PDO SQLite, Sodium, OpenSSL, and JSON.</li>
<li>HTTPS for the public address. Localhost is the only plain HTTP exception, and it is for testing.</li>
<li>A private directory outside the web root, or a directory the installer can prove is not downloadable.</li>
<li>Outgoing mail through SMTP.</li>
<li>A way for the host to POST to <code>cron.php</code> on a schedule. The installer explains the command. If the host cannot do that, publication still runs when the work endpoint receives a POST, but that is not a guarantee.</li>
<li><code>allow_url_fopen</code> or curl, so the service can talk to peers you add.</li>
</ul>
<p>The installer checks these and stops if one is missing. It will not switch to a weaker setup.</p>
<h2>Install</h2>
<ol>
<li>Download a release from <a href="{$repo}">the source repository</a>.</li>
<li>Upload the zip and extract it with the hosting file manager. Point the site at the <code>public</code> folder when the host lets you choose a document root.</li>
<li>Visit <code>install/</code> in a browser.</li>
<li>Read the checks. Set the public URL, SMTP, and the private data directory if the default one is inside the web root.</li>
<li>Install. Save the admin password, the reset token, and the cron key from that page. They are not shown again.</li>
<li>Add the cron command in the hosting panel. It must be a POST, not a plain visit.</li>
</ol>
<p>There is no account application and no command line step for this.</p>
<h2>Storage</h2>
<p>A message is small: the ciphertext is limited to about 64 KB of text, plus one share and the event log. A personal service can stay small for years. The admin page shows how much disk the data directory is using.</p>
<h2>Peers</h2>
<p>After install, the admin page can add another service by its URL. Last Words fetches that service's signed directory and stores the public key it advertised. Later syncs reject a directory that is not signed by that key, or by a later key that the old key signed over to. You choose peers. A message registration does not make this server contact an arbitrary address by itself.</p>
<h2>Updates</h2>
<p>Read the changelog, replace the PHP, JavaScript, and vendor files from a release, and keep the <code>data</code> directory. Do not overwrite <code>data</code>. The admin page shows the running version and links to the repository so you can compare it. This service does not phone home.</p>
<h2>Backup, move, and removal</h2>
<p>The admin page builds an encrypted backup. It contains the database and the service keys, wrapped with a password you choose for that file. Restore it on a new host with the same admin page, then set the public URL if the address changed. Tell people who listed you so their pages can be updated, because a moved URL is a different endpoint until they edit their page.</p>
<p>To leave the network, tell peer operators to remove you, and leave the server online long enough for clients to sync. Deleting your server deletes your copy and your share. It does not delete copies on other services. Do not treat shutdown as a way to erase a message that other services still hold.</p>
<h2>Service key rotation</h2>
<p>If the service signing key might have leaked, rotate it from the admin page. The old key signs a rotation record. Clients that pinned the old key can follow that record to the new one. The old private key is removed.</p>
HTML;

render_page('Become a service', $body);
