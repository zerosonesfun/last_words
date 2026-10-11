<?php

declare(strict_types=1);

namespace LastWords;

// A message in this exception is safe to show to the person who sent the request.
final class UserError extends \RuntimeException
{
}
