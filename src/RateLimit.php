<?php

declare(strict_types=1);

namespace LastWords;

final class RateLimit
{
    public function __construct(private Storage $db, private Clock $clock)
    {
    }

    public function allow(string $bucket, int $max, int $windowSeconds): bool
    {
        $bucket = hash('sha256', $bucket);
        return $this->db->transaction(function () use ($bucket, $max, $windowSeconds): bool {
            $now = $this->clock->now();
            $row = $this->db->one('SELECT hits, window_start FROM rate_limits WHERE bucket = ?', [$bucket]);
            if ($row === null || ($now - (int) $row['window_start']) >= $windowSeconds) {
                $this->db->run(
                    'INSERT INTO rate_limits (bucket, hits, window_start) VALUES (?, 1, ?)
                     ON CONFLICT(bucket) DO UPDATE SET hits = 1, window_start = excluded.window_start',
                    [$bucket, $now]
                );
                return true;
            }
            if ((int) $row['hits'] >= $max) {
                return false;
            }
            $this->db->run('UPDATE rate_limits SET hits = hits + 1 WHERE bucket = ?', [$bucket]);
            return true;
        });
    }
}
