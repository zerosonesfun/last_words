<?php

declare(strict_types=1);

namespace LastWords;

final class Storage
{
    private function __construct(private \PDO $pdo)
    {
    }

    public static function open(string $path): self
    {
        $pdo = new \PDO('sqlite:' . $path, null, null, [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            \PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec('PRAGMA busy_timeout = 5000');
        $pdo->exec('PRAGMA journal_mode = WAL');
        return new self($pdo);
    }

    public function migrate(string $directory): void
    {
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)');
        $files = glob($directory . '/*.sql') ?: [];
        sort($files);
        foreach ($files as $file) {
            $version = basename($file);
            $seen = $this->one('SELECT version FROM schema_migrations WHERE version = ?', [$version]);
            if ($seen !== null) {
                continue;
            }
            $sql = file_get_contents($file);
            if ($sql === false) {
                throw new \RuntimeException('Could not read a migration.');
            }
            $this->transaction(function () use ($sql, $version): void {
                foreach (self::statements($sql) as $statement) {
                    $this->pdo->exec($statement);
                }
                // 001 creates schema_migrations too. Ignore a duplicate insert target by checking.
                $again = $this->one('SELECT version FROM schema_migrations WHERE version = ?', [$version]);
                if ($again === null) {
                    $this->run('INSERT INTO schema_migrations (version) VALUES (?)', [$version]);
                }
            });
        }
    }

    public function one(string $sql, array $params = []): ?array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        $row = $statement->fetch();
        return $row === false ? null : $row;
    }

    public function all(string $sql, array $params = []): array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement->fetchAll();
    }

    public function run(string $sql, array $params = []): void
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
    }

    public function transaction(callable $fn): mixed
    {
        $this->pdo->beginTransaction();
        try {
            $result = $fn();
            $this->pdo->commit();
            return $result;
        } catch (\Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }

    public function meta(string $key, ?string $default = null): ?string
    {
        $row = $this->one('SELECT value FROM meta WHERE key = ?', [$key]);
        return $row === null ? $default : (string) $row['value'];
    }

    public function checkpoint(): void
    {
        $this->pdo->exec('PRAGMA wal_checkpoint(FULL)');
    }

    public function setMeta(string $key, string $value): void
    {
        $this->run(
            'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
            [$key, $value]
        );
    }

    private static function statements(string $sql): array
    {
        $parts = explode(';', $sql);
        $out = [];
        foreach ($parts as $part) {
            $trimmed = trim($part);
            if ($trimmed !== '') {
                $out[] = $trimmed;
            }
        }
        return $out;
    }
}
