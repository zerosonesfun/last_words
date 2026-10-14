<?php

declare(strict_types=1);

use LastWords\Installer;
use LastWords\MemoryTransport;
use LastWords\UserError;

function test_fresh_install_sends_mail_and_refuses_a_second_time(): void
{
    $mail = new MemoryTransport();
    $dir = temp_dir();
    $result = Installer::install($dir, install_input('http://127.0.0.1/service'), host_env($dir), $mail);
    check(is_file($dir . '/INSTALLED'), 'install writes the completed flag');
    check(is_file($dir . '/sign.secret'), 'install writes a signing key');
    check_same($mail->sent[0]['subject'], 'Last Words test', 'a test message is sent');
    check(!str_contains($mail->sent[0]['body'], $result['admin_password']), 'the test message does not carry the admin password');
    $again = false;
    try {
        Installer::install($dir, install_input('http://127.0.0.1/service'), host_env($dir), $mail);
    } catch (UserError) {
        $again = true;
    }
    check($again, 'a second install is refused');
}

function test_install_refuses_an_incompatible_host(): void
{
    $mail = new MemoryTransport();
    $dir = temp_dir();
    $env = host_env($dir);
    $env['extensions'] = ['openssl', 'json'];
    $refused = false;
    try {
        Installer::install($dir, install_input('http://127.0.0.1/service'), $env, $mail);
    } catch (UserError) {
        $refused = true;
    }
    check($refused, 'missing sodium and sqlite must stop installation');
    check(!is_file($dir . '/INSTALLED'), 'a failed install does not mark itself complete');
}

function test_private_directory_inside_the_web_root_is_refused_when_readable(): void
{
    $doc = temp_dir();
    $data = $doc . '/data';
    mkdir($data);
    $tokenSeen = null;
    $fetch = static function (string $url) use (&$tokenSeen): string {
        $name = basename(parse_url($url, PHP_URL_PATH) ?: '');
        $tokenSeen = $name;
        return $name;
    };
    $threw = false;
    try {
        Installer::assertPrivate($data, $doc, 'http://127.0.0.1', $fetch);
    } catch (UserError $error) {
        $threw = str_contains($error->getMessage(), 'downloaded');
    }
    check($threw, 'a readable private file stops installation');
    check(is_string($tokenSeen) && !is_file($data . '/' . $tokenSeen), 'the test file is removed');
}

function test_private_directory_outside_the_web_root_is_accepted(): void
{
    $doc = temp_dir();
    $data = temp_dir();
    $detail = Installer::assertPrivate($data, $doc, 'http://127.0.0.1', static function (): ?string {
        throw new RuntimeException('fetch should not run');
    });
    check(str_contains($detail, 'outside'), $detail);
}
