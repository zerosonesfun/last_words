<?php

declare(strict_types=1);

use LastWords\FakeClock;
use LastWords\MemoryTransport;

function test_cancel_page_script_matches_the_markup(): void
{
    $root = dirname(__DIR__);
    $js = (string) file_get_contents($root . '/public/assets/cancel.js');
    $page = (string) file_get_contents($root . '/public/cancel.php');
    check(str_contains($page, 'id="cancel-status"'), 'the cancel page has a status line');
    check(str_contains($page, 'id="cancel-go"'), 'the cancel page has a confirm button');
    check(!str_contains($js, 'cancel-app'), 'the cancel script must not wait for an element the page does not have');
}

function test_pages_escape_message_text_and_get_does_not_publish(): void
{
    $js = (string) file_get_contents(dirname(__DIR__) . '/client/lastwords.js');
    check(!str_contains($js, 'innerHTML'), 'the client must not assign HTML from message text');

    $port = 18080;
    $clock = new FakeClock(time());
    $mail = new MemoryTransport();
    $base = 'http://127.0.0.1:' . $port;
    $app = install_app($base, $clock, $mail);
    $message = make_message([$app], $clock, 'For my brother', 'the silver locket', 1);
    request_unlock($app, $message, $clock, 1, 0);
    $before = $app->storage->one('SELECT COUNT(*) AS n FROM events');

    $log = temp_dir() . '/server.log';
    $cmd = escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . $port . ' -t ' . escapeshellarg(dirname(__DIR__) . '/public');
    $env = getenv();
    if (!is_array($env)) {
        $env = [];
    }
    $env['LASTWORDS_DATA_DIR'] = $app->dataDir;
    $proc = proc_open($cmd, [['pipe', 'r'], ['file', $log, 'w'], ['file', $log, 'a']], $pipes, null, $env);
    check(is_resource($proc), 'the test server did not start');
    try {
        $ready = false;
        for ($i = 0; $i < 40; $i++) {
            $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if (is_resource($socket)) {
                fclose($socket);
                $ready = true;
                break;
            }
            usleep(100000);
        }
        check($ready, 'the test server did not accept connections');
        $home = http_call($base . '/');
        check(str_contains($home['body'], 'Last Words'), 'home page renders');
        check(str_contains(http_call($base . '/guide.php')['body'], 'trusted person'), 'guide renders');
        check(str_contains(http_call($base . '/become.php')['body'], 'Why more than one service'), 'become page renders');
        $view = http_call($base . '/api/message.php?id=' . $message['id']);
        check(!str_contains($view['body'], 'the silver locket'), 'the API does not return plaintext');
        check(str_contains($view['body'], '"state":"pending"'), 'the request is pending');
        http_call($base . '/cancel.php');
        http_call($base . '/cron.php?key=' . rawurlencode((string) $app->config['cron_key']));
        http_call($base . '/api/work.php');
        $after = $app->storage->one('SELECT COUNT(*) AS n FROM events');
        check_same((int) $after['n'], (int) $before['n'], 'GET requests did not add events');
        $again = http_call($base . '/api/message.php?id=' . $message['id']);
        check(str_contains($again['body'], '"state":"pending"'), 'GET did not publish the message');
        $login = http_call($base . '/admin.php', ['action' => 'login', 'password' => 'not-the-password']);
        check(str_contains($login['body'], 'not accepted'), 'a bad admin password is refused');
        check(!str_contains($login['body'], (string) $app->dataDir), 'the error page does not reveal the data path');
    } finally {
        proc_terminate($proc);
        proc_close($proc);
    }
}

function http_call(string $url, ?array $post = null): array
{
    $headers = "Accept: text/html\r\n";
    $content = null;
    $method = 'GET';
    if ($post !== null) {
        $method = 'POST';
        $content = http_build_query($post);
        $headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    $context = stream_context_create([
        'http' => [
            'method' => $method,
            'header' => $headers,
            'content' => $content,
            'ignore_errors' => true,
            'timeout' => 5,
        ],
    ]);
    $body = file_get_contents($url, false, $context);
    return ['body' => $body === false ? '' : $body];
}

function test_no_typography_dashes_in_the_project(): void
{
    $root = dirname(__DIR__);
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        $path = $file->getPathname();
        if (str_contains($path, '/.git/') || !$file->isFile()) {
            continue;
        }
        $data = file_get_contents($path);
        if ($data === false) {
            continue;
        }
        if (str_contains($data, "\u{2014}") || str_contains($data, "\u{2013}")) {
            throw new RuntimeException('Typography dash in ' . $path);
        }
    }
}
