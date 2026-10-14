<?php

declare(strict_types=1);

namespace LastWords;

final class Letters
{
    public static function when(int $unix): string
    {
        return gmdate('j F Y, H:i', $unix) . ' UTC';
    }

    public static function unlock(int $requestedAt, int $deadline, string $cancelUrl): array
    {
        $subject = 'A request to publish your Last Words message';
        $body = "Someone has asked to publish your Last Words message.\n\n"
            . 'Request time: ' . self::when($requestedAt) . "\n"
            . 'Deadline: ' . self::when($deadline) . "\n\n"
            . "If you want to keep the message private, open the link below and confirm the cancellation before the deadline:\n\n"
            . $cancelUrl . "\n\n"
            . "Opening the link does not cancel the request. The page will ask you to confirm.\n\n"
            . "If you do nothing before the deadline, the message can be published.\n\n"
            . "If the message has already been published, cancelling will not hide it. Use your emergency recovery key to re-lock it. Re-locking stops participating services from handing the message out again. It cannot erase copies that someone has already saved.\n\n"
            . "This email does not include your message or your recovery key.\n";
        return [$subject, $body];
    }

    public static function unlockWarning(int $requestedAt, int $deadline): array
    {
        $subject = 'A request to publish your Last Words message';
        $body = "A service recorded a request to publish your Last Words message, but it was not given the cancellation key for that request.\n\n"
            . 'Request time: ' . self::when($requestedAt) . "\n"
            . 'Deadline: ' . self::when($deadline) . "\n\n"
            . "If you did not expect this, use your emergency recovery key to re-lock the message before the deadline. You can also check the other services you chose, in case one of them sent a cancellation link.\n\n"
            . "This email does not include your message.\n";
        return [$subject, $body];
    }

    public static function cancelledOwner(): array
    {
        return [
            'Publication request cancelled',
            "The publication request was cancelled. The message stays private.\n\nThe trusted person can make a new request later. This did not retire their key.\n",
        ];
    }

    public static function cancelledTrusted(): array
    {
        return [
            'The publication request was cancelled',
            "The owner cancelled this publication request. The message stays private.\n\nYou can make a new request later if that is still the right thing to do.\n\nThis note does not include the owner's email address or the message.\n",
        ];
    }

    public static function published(string $ownerPage, int $deadline): array
    {
        $subject = 'Your Last Words message can now be read';
        $body = "The waiting period ended without a cancellation. Your Last Words message can now be read on the public page.\n\n"
            . 'Deadline that passed: ' . self::when($deadline) . "\n"
            . 'Public page: ' . $ownerPage . "\n\n"
            . "If this was a mistake, use your emergency recovery key. Re-locking stops participating services from handing the message out again. It cannot erase copies that someone has already saved.\n";
        return [$subject, $body];
    }

    public static function revised(bool $droppedRequest): array
    {
        $body = "Your Last Words message was replaced with a new sealed copy. The key did not change.\n\n";
        if ($droppedRequest) {
            $body .= "A publication request was still waiting, so that request was dropped. The trusted person can ask again later.\n\n";
        }
        $body .= "Put the new config.js next to your page. Copies of an older published text that someone already saved cannot be erased.\n";
        return ['Your Last Words message was updated', $body];
    }

    public static function relocked(): array
    {
        return [
            'Your Last Words message was re-locked',
            "An emergency re-lock was accepted. Participating services that receive it will stop handing out the message.\n\nIf someone already saved a copy while it was public, this cannot erase that copy.\n",
        ];
    }
}
