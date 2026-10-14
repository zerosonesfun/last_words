<?php

declare(strict_types=1);

namespace LastWords;

interface Clock
{
    public function now(): int;
}

final class SystemClock implements Clock
{
    public function now(): int
    {
        return time();
    }
}

final class FakeClock implements Clock
{
    public function __construct(private int $now)
    {
    }

    public function now(): int
    {
        return $this->now;
    }

    public function set(int $now): void
    {
        $this->now = $now;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }
}
