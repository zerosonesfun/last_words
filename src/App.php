<?php

declare(strict_types=1);

namespace LastWords;

final class App
{
    public function __construct(
        public Storage $storage,
        public Clock $clock,
        public Mailer $mail,
        public Message $messages,
        public Network $network,
        public Scheduler $scheduler,
        public RateLimit $rates,
        public array $config,
        public string $dataDir,
        public string $signPublic,
        public string $signSecret,
        public string $storageKey,
    ) {
    }

    public static function dataDir(): string
    {
        $env = getenv('LASTWORDS_DATA_DIR');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        $pathFile = dirname(__DIR__) . '/data_path.php';
        if (is_file($pathFile)) {
            $path = require $pathFile;
            if (is_string($path) && $path !== '') {
                return $path;
            }
        }
        return dirname(__DIR__) . '/data';
    }

    public static function open(string $dataDir, ?Clock $clock = null, ?MailTransport $transport = null, ?callable $httpGet = null): self
    {
        $configPath = $dataDir . '/config.php';
        if (!is_file($configPath) || !is_file($dataDir . '/INSTALLED')) {
            throw new UserError('This service is not installed.');
        }
        $config = require $configPath;
        if (!is_array($config)) {
            throw new \RuntimeException('Configuration is unreadable.');
        }
        $clock = $clock ?? new SystemClock();
        $storageKey = self::readKey($dataDir . '/storage.key', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $db = Storage::open($dataDir . '/service.sqlite');
        self::promotePendingKey($dataDir, $db);
        $signPublic = self::readKey($dataDir . '/sign.public', SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
        $signSecret = self::readKey($dataDir . '/sign.secret', SODIUM_CRYPTO_SIGN_SECRETKEYBYTES);
        $transport = $transport ?? new SmtpTransport($config['smtp'] ?? []);
        $mail = new Mailer($db, $clock, $transport, $storageKey);
        $messages = new Message($db, $clock, $mail, $storageKey, rtrim((string) $config['public_url'], '/'));
        $httpGet = $httpGet ?? static function (string $url): string {
            return self::httpGet($url);
        };
        $network = new Network(
            $db,
            $messages,
            $clock,
            $signPublic,
            $signSecret,
            rtrim((string) $config['public_url'], '/'),
            $httpGet
        );
        $scheduler = new Scheduler($db, $clock, $network, $messages, $mail, $dataDir);
        return new self(
            $db,
            $clock,
            $mail,
            $messages,
            $network,
            $scheduler,
            new RateLimit($db, $clock),
            $config,
            $dataDir,
            $signPublic,
            $signSecret,
            $storageKey
        );
    }

    public function rotateServiceKey(): string
    {
        $pair = Keys::signPair();
        file_put_contents($this->dataDir . '/sign.public.next', $pair['public'], LOCK_EX);
        file_put_contents($this->dataDir . '/sign.secret.next', $pair['secret'], LOCK_EX);
        @chmod($this->dataDir . '/sign.public.next', 0600);
        @chmod($this->dataDir . '/sign.secret.next', 0600);
        $this->network->rotateTo($pair['public'], $pair['secret']);
        rename($this->dataDir . '/sign.public.next', $this->dataDir . '/sign.public');
        rename($this->dataDir . '/sign.secret.next', $this->dataDir . '/sign.secret');
        $this->signPublic = $pair['public'];
        $this->signSecret = $pair['secret'];
        return Keys::b64($pair['public']);
    }

    public function status(): array
    {
        $pending = 0;
        foreach ($this->messages->ids() as $id) {
            if ($this->messages->reduce($id)->status === 'pending') {
                $pending++;
            }
        }
        $bytes = 0;
        foreach (scandir($this->dataDir) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $this->dataDir . '/' . $name;
            if (is_file($path)) {
                $bytes += (int) filesize($path);
            }
        }
        $mail = $this->mail->summary();
        return [
            'version' => Version::VERSION,
            'service_name' => (string) ($this->config['service_name'] ?? 'Last Words'),
            'public_url' => (string) $this->config['public_url'],
            'sign_public' => Keys::b64($this->signPublic),
            'operator_email' => (string) ($this->config['operator_email'] ?? ''),
            'source_repository' => (string) ($this->config['source_repository'] ?? Version::SOURCE_REPOSITORY),
            'pending_unlocks' => $pending,
            'storage_bytes' => $bytes,
            'mail' => $mail,
            'peers' => $this->network->peers(),
            'failures' => $this->messages->recentFailures(),
            'last_work_at' => $this->storage->meta('last_work_at'),
            'last_cron_at' => $this->storage->meta('last_cron_at'),
            'installed_at' => (int) ($this->config['installed_at'] ?? 0),
            'php' => PHP_VERSION,
        ];
    }

    public function mentionedServices(): array
    {
        $found = [];
        foreach ($this->messages->exportEvents(5000) as $event) {
            try {
                $parsed = Protocol::parse((string) $event['body']);
            } catch (UserError) {
                continue;
            }
            if ($parsed['type'] !== 'register') {
                continue;
            }
            foreach (Protocol::serviceList($parsed['fields']['services']) as $url) {
                $found[$url] = true;
            }
        }
        return array_keys($found);
    }

    public function writeConfig(array $config): void
    {
        $path = $this->dataDir . '/config.php';
        $bytes = "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($config, true) . ";\n";
        if (file_put_contents($path, $bytes, LOCK_EX) === false) {
            throw new UserError('Could not update configuration.');
        }
        @chmod($path, 0600);
        $this->config = $config;
    }

    public function backup(string $password): string
    {
        $this->storage->checkpoint();
        return Backup::create($this->dataDir, $password);
    }

    public static function httpGet(string $url): string
    {
        $context = stream_context_create([
            'http' => [
                'timeout' => 8,
                'ignore_errors' => true,
                'follow_location' => 0,
            ],
        ]);
        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            throw new UserError('The other service did not respond.');
        }
        $status = 200;
        foreach ($http_response_header ?? [] as $header) {
            if (preg_match('#\AHTTP/\S+\s+(\d+)#', (string) $header, $match) === 1) {
                $status = (int) $match[1];
            }
        }
        if ($status >= 400) {
            throw new UserError('The other service rejected the request.');
        }
        if (strlen($body) > 5000000) {
            throw new UserError('The other service sent too much data.');
        }
        return $body;
    }

    private static function promotePendingKey(string $dataDir, Storage $db): void
    {
        $nextPublic = $dataDir . '/sign.public.next';
        $nextSecret = $dataDir . '/sign.secret.next';
        if (!is_file($nextPublic) || !is_file($nextSecret)) {
            return;
        }
        $public = file_get_contents($nextPublic);
        if ($public === false) {
            return;
        }
        $matched = false;
        foreach ($db->all('SELECT body FROM key_rotations ORDER BY id DESC LIMIT 5') as $row) {
            try {
                $parsed = Protocol::parseRotation((string) $row['body']);
            } catch (UserError) {
                continue;
            }
            $raw = Keys::b64decode($parsed['new_sign_pubkey']);
            if ($raw !== null && Keys::same($raw, $public)) {
                $matched = true;
                break;
            }
        }
        if (!$matched) {
            @unlink($nextPublic);
            @unlink($nextSecret);
            return;
        }
        rename($nextPublic, $dataDir . '/sign.public');
        rename($nextSecret, $dataDir . '/sign.secret');
    }

    private static function readKey(string $path, int $bytes): string
    {
        $raw = file_get_contents($path);
        if ($raw === false || strlen($raw) !== $bytes) {
            throw new \RuntimeException('A private key file is unreadable.');
        }
        return $raw;
    }
}
