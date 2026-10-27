<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Command;

use Acencyril\SentinelleBundle\Service\Mail;
use Acencyril\SentinelleBundle\Service\SecurityAlert;
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
 * One email a day instead of one per scanner. Since 0.6 it is where every alert not listed in
 * `alert.immediate` ends up: the alerts of the window by kind (and how many were emailed at
 * once), any sensitive answer served, what the hostile requests were, the addresses blocked by
 * reason, and the ten busiest hostile addresses. Nothing happened (no alert, no block, no
 * exploitation attempt, no breach): nothing is sent. Run it once a day (cron, scheduler):
 * bin/console sentinelle:digest
 *
 * Since 0.7.1: in the language of `mail.locale` (en, fr), laid out by Mail.
 */
#[AsCommand(name: 'sentinelle:digest', description: 'Email the last 24 hours of alerts and blocks (nothing when nothing happened)')]
final class DigestCommand extends Command
{
    /** Requests that say something about an address's intent, for the "top addresses" table. */
    private const HOSTILE = ['breach_served', 'attack_attempt', 'scan_probe', 'access_denied', 'ip_blocked'];

    private const TYPES = ['breach_served', 'attack_attempt', 'scan_probe', 'access_denied', 'ip_blocked'];

    /** The reasons SiteEventLogger and the breach watch block with, by alert kind. */
    private const REASON_KINDS = [
        'Probable breach' => 'breach',
        'Exploitation attempt' => 'exploitation',
        'Likely brute force' => 'brute_force',
        'Automated scan' => 'scan',
    ];

    /** @param list<string> $immediate */
    public function __construct(
        private Connection $db,
        private MailerInterface $mailer,
        private string $recipient,
        private string $sender,
        private string $siteName,
        private array $immediate = SecurityAlert::IMMEDIATE_DEFAULT,
        private Mail $mail = new Mail(),
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('hours', null, InputOption::VALUE_REQUIRED, 'Window, in hours', '24')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Print the counts, send nothing');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $hours = max(1, (int) $input->getOption('hours'));
        $since = (new \DateTimeImmutable('-'.$hours.' hours'))->format('Y-m-d H:i:s');

        $alerts = $this->alerts($since);
        $types = array_map('intval', $this->db->fetchAllKeyValue(
            'SELECT event_type, COUNT(*) FROM sentinelle_visit WHERE created_at >= ? AND event_type IN ('.self::marks(self::HOSTILE).') GROUP BY event_type',
            [$since, ...self::HOSTILE],
        ));
        $blocks = $this->blocks($since);
        $breaches = $this->db->fetchAllAssociative("SELECT ip, url, created_at FROM sentinelle_visit WHERE event_type = 'breach_served' AND created_at >= ? ORDER BY created_at DESC LIMIT 20", [$since]);

        $alertTotal = array_sum(array_column($alerts, 'total'));
        $blocked = array_sum($blocks);
        if (0 === $alertTotal && 0 === $blocked && !$breaches && 0 === ($types['attack_attempt'] ?? 0)) {
            $output->writeln('Nothing to report.');

            return Command::SUCCESS;
        }
        $top = $this->topAddresses($since);

        if ($input->getOption('dry-run')) {
            foreach ($alerts as $kind => $a) {
                $output->writeln(sprintf('alert %s: %d (%d emailed)', $kind, $a['total'], $a['emailed']));
            }
            foreach ($types as $type => $n) {
                $output->writeln(sprintf('%s: %d', $type, $n));
            }
            $output->writeln(sprintf('%d blocked, %d breach(es), top: %s. Dry run: nothing sent.', $blocked, \count($breaches), implode(', ', array_column($top, 'ip')) ?: '—'));

            return Command::SUCCESS;
        }

        $this->mailer->send((new Email())->from(new Address($this->sender, 'Sentinelle'))->to($this->recipient)
            ->subject($this->subject($alertTotal, $blocked, \count($breaches), $hours))
            ->html($this->html($alerts, $types, $blocks, $breaches, $top, $hours)));
        $output->writeln(sprintf('%d alert(s), %d blocked, %d breach(es): digest sent.', $alertTotal, $blocked, \count($breaches)));

        return Command::SUCCESS;
    }

    /** @return array<string, array{total:int, emailed:int}> by kind, every kind present */
    private function alerts(string $since): array
    {
        $out = array_fill_keys(SecurityAlert::KINDS, ['total' => 0, 'emailed' => 0]);
        foreach ($this->db->fetchFirstColumn("SELECT meta FROM sentinelle_visit WHERE event_type = 'alert' AND created_at >= ?", [$since]) as $meta) {
            $m = json_decode((string) $meta, true);
            $kind = \is_array($m) && isset($m['kind']) && \is_string($m['kind']) ? $m['kind'] : 'scan';
            $out[$kind] ??= ['total' => 0, 'emailed' => 0];
            ++$out[$kind]['total'];
            $out[$kind]['emailed'] += !empty($m['emailed']) ? 1 : 0;
        }
        // A breach is counted from what was served, not from alerts: the breach watch logs it
        // as breach_served whether or not an email went out.
        $out['breach']['total'] = max($out['breach']['total'], (int) $this->db->fetchOne(
            "SELECT COUNT(*) FROM sentinelle_visit WHERE event_type = 'breach_served' AND created_at >= ?", [$since]));
        if (\in_array('breach', $this->immediate, true)) {
            $out['breach']['emailed'] = $out['breach']['total'];
        }

        return $out;
    }

    /** @return array<string, int> new blocks by reason ("Automated scan — 15 probes…" counts as "Automated scan") */
    private function blocks(string $since): array
    {
        $out = [];
        foreach ($this->db->fetchFirstColumn('SELECT reason FROM sentinelle_blocked_ip WHERE created_at >= ?', [$since]) as $reason) {
            $key = trim(explode(' — ', (string) $reason, 2)[0]);
            $key = str_starts_with($key, 'Probable breach:') ? 'Probable breach' : $key;
            $out[$key] = ($out[$key] ?? 0) + 1;
        }
        arsort($out);

        return $out;
    }

    /** @return list<array{ip:string, n:int, blocked:bool}> */
    private function topAddresses(string $since): array
    {
        $rows = $this->db->fetchAllAssociative(
            'SELECT ip, COUNT(*) AS n FROM sentinelle_visit WHERE created_at >= ? AND ip IS NOT NULL AND event_type IN ('.self::marks(self::HOSTILE).') GROUP BY ip ORDER BY n DESC, ip ASC LIMIT 10',
            [$since, ...self::HOSTILE],
        );
        $ips = array_column($rows, 'ip');
        $blocked = $ips ? $this->db->fetchFirstColumn(
            'SELECT ip FROM sentinelle_blocked_ip WHERE (expires_at IS NULL OR expires_at > ?) AND ip IN ('.self::marks($ips).')',
            [(new \DateTimeImmutable())->format('Y-m-d H:i:s'), ...$ips],
        ) : [];

        return array_map(static fn (array $r): array => ['ip' => (string) $r['ip'], 'n' => (int) $r['n'], 'blocked' => \in_array($r['ip'], $blocked, true)], $rows);
    }

    /** "?, ?, ?" for a list: plain positional parameters work on every DBAL version. */
    private static function marks(array $values): string
    {
        return implode(', ', array_fill(0, \count($values), '?'));
    }

    /** "Sentinelle Shop — 4 addresses blocked in 24 h", "— nothing to report", "🔴 … — probable breach". */
    private function subject(int $alerts, int $blocked, int $breaches, int $hours): string
    {
        $m = $this->mail;
        $p = ['%hours%' => (string) $hours];
        $what = match (true) {
            $breaches > 0 => $m->t('digest.subject.breach', $p),
            $blocked > 0 => $m->n('digest.subject.blocked', $blocked, $p),
            $alerts > 0 => $m->n('digest.subject.alerts', $alerts, $p),
            default => $m->t('digest.subject.quiet'),
        };

        return ($breaches > 0 ? '🔴 ' : '').'Sentinelle '.$this->siteName.' — '.$what;
    }

    private function html(array $alerts, array $types, array $blocks, array $breaches, array $top, int $hours): string
    {
        $m = $this->mail;
        $esc = Mail::esc(...);

        $body = '';
        if ($breaches) {
            $items = '';
            foreach ($breaches as $b) {
                $items .= '<li style="margin:0 0 4px">'.$esc($b['created_at']).' — '.Mail::mono($esc($b['url'])).' — '.$esc($b['ip']).'</li>';
            }
            $body .= Mail::note('<strong>🔴 '.$esc($m->t('digest.breaches')).'</strong><ul style="margin:8px 0 0;padding-left:20px">'.$items.'</ul>', '#b91c1c', '#ffffff');
        }

        $rows = [];
        foreach ($alerts as $kind => $a) {
            $now = \in_array($kind, $this->immediate, true);
            $when = $now ? $m->t('digest.when.immediate') : $m->t('digest.when.digest');
            if (!$now && $a['emailed']) {
                $when .= ' ('.$m->n('digest.emailed', $a['emailed']).')';
            }
            $rows[] = [$esc($m->t('kind.'.$kind)), (string) $a['total'], Mail::muted($esc($when))];
        }
        $body .= Mail::heading($esc($m->t('digest.alerts', ['%hours%' => (string) $hours])))
            .Mail::table([$m->t('digest.col.kind'), $m->t('digest.col.alerts'), $m->t('digest.col.email')], $rows, [1]);

        $rows = [];
        foreach (self::TYPES as $type) {
            $rows[] = [$esc($m->t('digest.type.'.$type)), (string) ($types[$type] ?? 0)];
        }
        $body .= Mail::heading($esc($m->t('digest.hostile'))).Mail::table([], $rows, [1]);

        $rows = [];
        foreach ($blocks as $reason => $n) {
            $kind = self::REASON_KINDS[$reason] ?? null;
            $rows[] = [$esc(null !== $kind ? $m->t('kind.'.$kind) : $reason), (string) $n];
        }
        $body .= Mail::heading($esc($m->n('digest.blocked', array_sum($blocks))))
            .($rows ? Mail::table([$m->t('digest.col.reason'), $m->t('digest.col.addresses')], $rows, [1]) : '');

        $rows = [];
        foreach ($top as $t) {
            $rows[] = [Mail::mono($esc($t['ip'])), (string) $t['n'], Mail::muted($esc($m->t($t['blocked'] ? 'digest.blocked_now' : 'digest.not_blocked_now')))];
        }
        $body .= Mail::heading($esc($m->t('digest.top')))
            .($rows ? Mail::table([$m->t('digest.col.address'), $m->t('digest.col.requests'), $m->t('digest.col.now')], $rows, [1]) : '<p style="font-size:13px;color:'.Mail::MUTED.'">—</p>');

        return $m->page(
            $breaches ? '#b91c1c' : '#0f766e',
            $this->siteName,
            $this->subjectTitle(\count($breaches), array_sum($blocks), array_sum(array_column($alerts, 'total')), $hours),
            $esc($m->t('digest.lead', ['%hours%' => (string) $hours])),
            $body,
            $m->t('digest.footer'),
        );
    }

    /** The subject without "Sentinelle <site> — ", as the email's title. */
    private function subjectTitle(int $breaches, int $blocked, int $alerts, int $hours): string
    {
        $s = $this->subject($alerts, $blocked, $breaches, $hours);
        $t = substr($s, strpos($s, ' — ') + \strlen(' — '));

        return mb_strtoupper(mb_substr($t, 0, 1)).mb_substr($t, 1);
    }
}
