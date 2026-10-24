<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Command;

use Doctrine\DBAL\Connection;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;

/**
 * One email a day instead of one per scanner: the addresses blocked in the last 24 hours,
 * by reason, and any sensitive answer served (those also alert at once). Nothing to report:
 * nothing is sent. Run it once a day (cron, scheduler): bin/console sentinelle:digest
 */
#[AsCommand(name: 'sentinelle:digest', description: 'Email the last 24 hours of blocks (nothing when nothing happened)')]
final class DigestCommand extends Command
{
    public function __construct(
        private Connection $db,
        private MailerInterface $mailer,
        private string $recipient,
        private string $sender,
        private string $siteName,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('hours', null, InputOption::VALUE_REQUIRED, 'Window, in hours', '24');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $since = (new \DateTimeImmutable('-'.max(1, (int) $input->getOption('hours')).' hours'))->format('Y-m-d H:i:s');
        $reasons = $this->db->fetchAllKeyValue('SELECT reason, COUNT(*) FROM sentinelle_blocked_ip WHERE created_at >= ? GROUP BY reason ORDER BY COUNT(*) DESC', [$since]);
        $breaches = $this->db->fetchAllAssociative("SELECT ip, url, created_at FROM sentinelle_visit WHERE event_type = 'breach_served' AND created_at >= ? ORDER BY created_at DESC LIMIT 20", [$since]);
        $blocked = array_sum(array_map('intval', $reasons));
        if (0 === $blocked && !$breaches) {
            $output->writeln('Nothing to report.');

            return Command::SUCCESS;
        }
        $esc = static fn ($v): string => htmlspecialchars((string) $v, \ENT_QUOTES, 'UTF-8');
        $lines = '';
        foreach ($reasons as $reason => $n) {
            $lines .= '<tr><td style="padding:4px 10px 4px 0">'.$esc($reason).'</td><td style="padding:4px 0;text-align:right">'.(int) $n.'</td></tr>';
        }
        $red = '';
        foreach ($breaches as $b) {
            $red .= '<li>'.$esc($b['created_at']).' — '.$esc($b['url']).' — '.$esc($b['ip']).'</li>';
        }
        $html = '<div style="font-family:sans-serif;max-width:560px;margin:0 auto">'
            .($red ? '<div style="background:#b91c1c;color:#fff;padding:12px;border-radius:8px;font-weight:bold">🔴 Sensitive answers served:<ul>'.$red.'</ul></div>' : '')
            .'<p>'.$blocked.' address(es) blocked automatically in the window. None of them is in the red list above unless shown there.</p>'
            .'<table style="font-size:13px">'.$lines.'</table></div>';
        $this->mailer->send((new Email())->from(new Address($this->sender, 'Sentinelle'))->to($this->recipient)
            ->subject(sprintf('%s Sentinelle %s — %d blocked in 24 h', $red ? '🔴' : '🛡', $this->siteName, $blocked))->html($html));
        $output->writeln(sprintf('%d blocked, %d breach(es): digest sent.', $blocked, \count($breaches)));

        return Command::SUCCESS;
    }
}
