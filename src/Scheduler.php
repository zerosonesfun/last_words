<?php

declare(strict_types=1);

namespace LastWords;

final class Scheduler
{
    public function __construct(
        private Storage $db,
        private Clock $clock,
        private Network $network,
        private Message $messages,
        private Mailer $mail,
        private string $dataDir,
    ) {
    }

    public function run(bool $fromCron): array
    {
        $lockPath = $this->dataDir . '/work.lock';
        $lock = fopen($lockPath, 'c');
        if ($lock === false) {
            throw new \RuntimeException('Could not lock the scheduler.');
        }
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);
            return ['busy' => true, 'published' => 0, 'sent' => 0, 'peers' => []];
        }
        try {
            $peers = $this->network->pullAll();
            $published = $this->messages->queueDuePublications();
            $sent = $this->mail->drain();
            $now = (string) $this->clock->now();
            $this->db->setMeta('last_work_at', $now);
            if ($fromCron) {
                $this->db->setMeta('last_cron_at', $now);
            }
            return ['busy' => false, 'published' => $published, 'sent' => $sent, 'peers' => $peers];
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
