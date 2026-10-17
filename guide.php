<?php

declare(strict_types=1);

require __DIR__ . '/src/autoload.php';
require __DIR__ . '/src/Web.php';

$repo = 'https://github.com/zerosonesfun/last_words';
try {
    $app = open_installed_app();
    if ($app !== null) {
        $repo = (string) ($app->config['source_repository'] ?? $repo);
    }
} catch (Throwable) {
    $repo = 'https://github.com/zerosonesfun/last_words';
}

$body = <<<HTML
<h1>Create a Last Words page</h1>
<p>You keep your own website. Last Words adds a small page to it. The message is encrypted in your browser before a service stores it. A service operator cannot read it from one share.</p>
<h2>What you will end up with</h2>
<p>A public page that says the message is locked. A file for one trusted person. A separate recovery file that only you keep. The trusted person can ask for the message to be published. You then have 30 days, counted as 2,592,000 seconds, to cancel that request by email. If you do not, the page can show the message.</p>
<div class="note">
<p>The service cannot tell whether you have died. It trusts the person who holds the trusted person key, and it trusts that you will see the email if you are able to. Email is a notification. Your recovery file still works if you cannot reach the email account.</p>
</div>
<h2>Before you start</h2>
<ol>
<li>Choose more than one Last Words service when you can. With one service, that operator holds the only share and can read the message. With two services, both shares are required. With three or more, the default threshold is two, so one operator is not enough.</li>
<li>Use a current version of Firefox, Chrome, or Safari. Setup needs JavaScript because the encryption happens on your computer.</li>
<li>Decide who the trusted person is, and talk to them. They should know what the key is for, and that using it starts a 30 day wait rather than opening the message immediately.</li>
</ol>
<h2>Steps</h2>
<ol>
<li>On your existing website, create a folder for the page. You can download the client files from the <a href="{$repo}">source repository</a>, in the <code>client</code> folder of a release.</li>
<li>Upload <code>index.html</code>, <code>setup.html</code>, <code>unlock.html</code>, <code>recover.html</code>, <code>lastwords.js</code>, <code>protocol.js</code>, <code>style.css</code>, and <code>vendor/nacl.js</code>.</li>
<li>Open <code>setup.html</code> on your site over HTTPS.</li>
<li>Write the message. Add a title if you want one. The title stays inside the encryption until publication.</li>
<li>Enter your email address and the addresses of the services you chose. You can start with this service: the address is the site you are reading now, without a page name on the end.</li>
<li>The page encrypts the message, splits the key, and sends each service only its own share.</li>
<li>The page downloads three files. Upload <code>config.js</code> next to <code>index.html</code>. Give the trusted person file to that person. Store the recovery file somewhere else, not in the same email account and not next to their file.</li>
<li>The page reads the services back and confirms the message is locked. Leave the confirmation on screen until the three files are saved.</li>
</ol>
<h2>What the trusted person does</h2>
<p>They open <code>unlock.html</code> on your website, or the copy you gave them, and choose their file. The page explains that confirming starts the 30 day wait. Nothing is published by merely opening the link. They confirm with a button, which sends a signed request. You receive an email. Cancelling requires a second confirmation. Doing nothing until the deadline allows publication.</p>
<p>A cancelled request does not retire their key. They can make a new request later.</p>
<h2>If the message is published by mistake</h2>
<p>Open <code>recover.html</code> and use the recovery file. Re-locking tells participating services to stop handing the message out. It cannot erase a copy someone already saved, photographed, or cached.</p>
<h2>If the words should change</h2>
<p>The same page can replace the sealed text. Upload or paste the recovery file first. The page will not save new words without it. The key stays the same, so the trusted person file still works. Upload the new <code>config.js</code> the page downloads. A request that is still waiting is dropped.</p>
<h2>What stays on your website</h2>
<p>The public page stores the encrypted message and the list of services. It does not store either secret file. You can move the page to another host later. The services still have the shares and the signed history. Download an encrypted copy from the page if you want your own extra record.</p>
HTML;

render_page('Create a Last Words page', $body);
