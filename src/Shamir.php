<?php

declare(strict_types=1);

namespace LastWords;

// Standard Shamir sharing over GF(256), one polynomial per key byte.
// This is not a cipher. Secretbox encrypts the message. Sharing only splits the key
// so that fewer than k services cannot reconstruct it.
final class Shamir
{
    public static function split(string $secret, int $k, int $n): array
    {
        if (strlen($secret) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new UserError('Message key is malformed.');
        }
        if ($k < 1 || $n < $k || $n > Protocol::MAX_SERVICES) {
            throw new UserError('Share threshold is not acceptable.');
        }
        $ys = [];
        for ($index = 1; $index <= $n; $index++) {
            $ys[$index] = '';
        }
        for ($byte = 0; $byte < strlen($secret); $byte++) {
            $coeff = [ord($secret[$byte])];
            for ($c = 1; $c < $k; $c++) {
                $coeff[$c] = ord(random_bytes(1));
            }
            // A zero leading coefficient would silently lower the threshold.
            if ($k > 1) {
                while ($coeff[$k - 1] === 0) {
                    $coeff[$k - 1] = ord(random_bytes(1));
                }
            }
            for ($index = 1; $index <= $n; $index++) {
                $ys[$index] .= chr(self::evalPoly($coeff, $index));
            }
        }
        $shares = [];
        for ($index = 1; $index <= $n; $index++) {
            $shares[$index] = chr(1) . chr($index) . chr($k) . chr($n) . $ys[$index];
        }
        return $shares;
    }

    public static function join(array $shares): string
    {
        $points = [];
        $k = null;
        $n = null;
        foreach ($shares as $share) {
            if (!is_string($share) || strlen($share) !== 4 + SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
                throw new UserError('A share is malformed.');
            }
            if (ord($share[0]) !== 1) {
                throw new UserError('A share is malformed.');
            }
            $index = ord($share[1]);
            $shareK = ord($share[2]);
            $shareN = ord($share[3]);
            if ($index < 1 || $index > 255 || $shareK < 1 || $shareN < $shareK) {
                throw new UserError('A share is malformed.');
            }
            if ($k === null) {
                $k = $shareK;
                $n = $shareN;
            }
            if ($shareK !== $k || $shareN !== $n || isset($points[$index])) {
                throw new UserError('Shares do not belong together.');
            }
            $points[$index] = substr($share, 4);
        }
        if ($k === null || count($points) < $k) {
            throw new UserError('Not enough shares to reconstruct the key.');
        }
        $chosen = array_slice($points, 0, $k, true);
        $secret = '';
        for ($byte = 0; $byte < SODIUM_CRYPTO_SECRETBOX_KEYBYTES; $byte++) {
            $set = [];
            foreach ($chosen as $index => $y) {
                $set[] = [$index, ord($y[$byte])];
            }
            $secret .= chr(self::atZero($set));
        }
        return $secret;
    }

    public static function mul(int $a, int $b): int
    {
        $p = 0;
        $a &= 0xff;
        $b &= 0xff;
        for ($i = 0; $i < 8; $i++) {
            if (($b & 1) === 1) {
                $p ^= $a;
            }
            $hi = $a & 0x80;
            $a = ($a << 1) & 0xff;
            if ($hi !== 0) {
                $a ^= 0x1b;
            }
            $b >>= 1;
        }
        return $p;
    }

    private static function evalPoly(array $coeff, int $x): int
    {
        $y = 0;
        for ($i = count($coeff) - 1; $i >= 0; $i--) {
            $y = self::mul($y, $x) ^ $coeff[$i];
        }
        return $y;
    }

    private static function atZero(array $points): int
    {
        $result = 0;
        $count = count($points);
        for ($i = 0; $i < $count; $i++) {
            $xi = $points[$i][0];
            $yi = $points[$i][1];
            $num = 1;
            $den = 1;
            for ($j = 0; $j < $count; $j++) {
                if ($i === $j) {
                    continue;
                }
                $xj = $points[$j][0];
                $num = self::mul($num, $xj);
                $den = self::mul($den, $xi ^ $xj);
            }
            $result ^= self::mul($yi, self::mul($num, self::inv($den)));
        }
        return $result;
    }

    private static function inv(int $a): int
    {
        if ($a === 0) {
            throw new UserError('A share is malformed.');
        }
        $result = 1;
        $base = $a;
        $exp = 254;
        while ($exp > 0) {
            if (($exp & 1) === 1) {
                $result = self::mul($result, $base);
            }
            $base = self::mul($base, $base);
            $exp >>= 1;
        }
        return $result;
    }
}
