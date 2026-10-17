<?php

declare(strict_types=1);

// The installer writes the real file to the private data directory.
// SMTP passwords and the cron key never belong in this example.
return [
    'public_url' => 'https://example.com',
    'service_name' => 'Last Words',
    'smtp' => [
        'host' => 'smtp.example.com',
        'port' => 587,
        'encryption' => 'starttls',
        'username' => '',
        'password' => '',
        'from_email' => 'last-words@example.com',
        'from_name' => 'Last Words',
    ],
    'operator_email' => 'you@example.com',
    'source_repository' => 'https://github.com/zerosonesfun/last_words',
    'cron_key' => '',
    'installed_at' => 0,
    'version' => '1.0.3',
];
