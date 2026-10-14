<?php

declare(strict_types=1);

namespace LastWords;

interface MailTransport
{
    public function send(string $to, string $subject, string $body): void;
}

final class MemoryTransport implements MailTransport
{
    public array $sent = [];
    public bool $fail = false;

    public function send(string $to, string $subject, string $body): void
    {
        if ($this->fail) {
            throw new \RuntimeException('smtp rejected');
        }
        $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
    }
}

final class SmtpTransport implements MailTransport
{
    public function __construct(private array $smtp)
    {
    }

    public function send(string $to, string $subject, string $body): void
    {
        require_once dirname(__DIR__) . '/lib/phpmailer/Exception.php';
        require_once dirname(__DIR__) . '/lib/phpmailer/PHPMailer.php';
        require_once dirname(__DIR__) . '/lib/phpmailer/SMTP.php';
        $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = (string) $this->smtp['host'];
        $mail->Port = (int) $this->smtp['port'];
        $mail->SMTPAuth = ($this->smtp['username'] ?? '') !== '';
        $mail->Username = (string) ($this->smtp['username'] ?? '');
        $mail->Password = (string) ($this->smtp['password'] ?? '');
        $encryption = (string) ($this->smtp['encryption'] ?? 'starttls');
        if ($encryption === 'starttls') {
            $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
        } elseif ($encryption === 'tls') {
            $mail->SMTPSecure = \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        } else {
            $mail->SMTPSecure = '';
            $mail->SMTPAutoTLS = false;
        }
        $mail->CharSet = 'UTF-8';
        $mail->SMTPDebug = 0;
        $mail->Timeout = 15;
        $mail->setFrom((string) $this->smtp['from_email'], (string) ($this->smtp['from_name'] ?? 'Last Words'));
        $mail->addAddress($to);
        $mail->isHTML(false);
        $mail->Subject = $subject;
        $mail->Body = $body;
        try {
            $mail->send();
        } catch (\Throwable $error) {
            $detail = $error->getMessage();
            $password = (string) ($this->smtp['password'] ?? '');
            if ($password !== '' && str_contains($detail, $password)) {
                $detail = 'Mail delivery failed.';
            }
            throw new \RuntimeException(Log::safe($detail === '' ? 'Mail delivery failed.' : $detail));
        }
    }
}

final class Mailer
{
    private const MAX_ATTEMPTS = 8;

    public function __construct(
        private Storage $db,
        private Clock $clock,
        private MailTransport $transport,
        private string $storageKey,
    ) {
    }

    public function queue(string $dedupe, string $kind, string $to, string $subject, string $body, ?string $messageId = null): void
    {
        if ($this->db->one('SELECT dedupe_key FROM notices WHERE dedupe_key = ?', [$dedupe]) !== null) {
            return;
        }
        [$nonce, $cipher] = Keys::box($body, $this->storageKey);
        $this->db->run(
            'INSERT INTO notices (dedupe_key, message_id, kind, to_address, subject, body_nonce, body_cipher, attempts, next_attempt_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)',
            [$dedupe, $messageId, $kind, $to, $subject, $nonce, $cipher, $this->clock->now()]
        );
    }

    public function drain(): int
    {
        $rows = $this->db->all(
            'SELECT * FROM notices WHERE sent_at IS NULL AND attempts < ? AND next_attempt_at <= ? ORDER BY next_attempt_at ASC LIMIT 20',
            [self::MAX_ATTEMPTS, $this->clock->now()]
        );
        $sent = 0;
        foreach ($rows as $row) {
            $body = Keys::unbox((string) $row['body_cipher'], (string) $row['body_nonce'], $this->storageKey);
            if ($body === null) {
                $this->markFailed($row, 'Stored mail could not be read.');
                continue;
            }
            try {
                $this->transport->send((string) $row['to_address'], (string) $row['subject'], $body);
                $this->db->run(
                    'UPDATE notices SET sent_at = ?, body_nonce = NULL, body_cipher = NULL, last_error = NULL WHERE dedupe_key = ?',
                    [$this->clock->now(), $row['dedupe_key']]
                );
                $sent++;
            } catch (\Throwable $error) {
                $this->markFailed($row, Log::safe($error->getMessage()));
            }
        }
        return $sent;
    }

    public function summary(): array
    {
        $pending = $this->db->one('SELECT COUNT(*) AS n FROM notices WHERE sent_at IS NULL AND attempts < ?', [self::MAX_ATTEMPTS]);
        $failed = $this->db->one('SELECT COUNT(*) AS n FROM notices WHERE sent_at IS NULL AND attempts >= ?', [self::MAX_ATTEMPTS]);
        $recent = $this->db->all(
            'SELECT kind, to_address, subject, attempts, last_error, sent_at, next_attempt_at FROM notices ORDER BY COALESCE(sent_at, next_attempt_at) DESC LIMIT 20'
        );
        return [
            'pending' => (int) ($pending['n'] ?? 0),
            'failed' => (int) ($failed['n'] ?? 0),
            'recent' => $recent,
        ];
    }

    private function markFailed(array $row, string $error): void
    {
        $attempts = (int) $row['attempts'] + 1;
        $delays = [60, 300, 900, 3600, 21600];
        $delay = $delays[min($attempts - 1, count($delays) - 1)];
        $this->db->run(
            'UPDATE notices SET attempts = ?, next_attempt_at = ?, last_error = ? WHERE dedupe_key = ?',
            [$attempts, $this->clock->now() + $delay, $error, $row['dedupe_key']]
        );
    }
}
