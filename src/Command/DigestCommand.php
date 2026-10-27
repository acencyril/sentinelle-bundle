<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Command;

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
 */
#[AsCommand(name: 'sentinelle:digest', description: 'Email the last 24 hours of alerts and blocks (nothing when nothing happened)')]
final class DigestCommand extends Command
{
    /** Requests that say something about an address's intent, for the "top addresses" table. */
    private const HOSTILE = ['breach_served', 'attack_attempt', 'scan_probe', 'access_denied', 'ip_blocked'];

    private const KIND_LABELS = [
        'breach' => 'Probable breach (sensitive answer served)',
        'exploitation' => 'Exploitation attempt',
        'brute_force' => 'Likely brute force',
        'scan' => 'Automated scan',
    ];

    private const TYPE_LABELS = [
        'breach_served' => 'Sensitive answers served (2xx)',
        'attack_attempt' => 'Exploitation attempts',
        'scan_probe' => 'Probes recorded',
        'access_denied' => 'Access denied',
        'ip_blocked' => 'Requests refused (address blocked)',
    ];

    /** @param list<string> $immediate */
    public function __construct(
        private Connection $db,
        private MailerInterface $mailer,
        private string $recipient,
        private string $sender,
        private string $siteName,
        private array $immediate = SecurityAlert::IMMEDIATE_DEFAULT,
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
            ->subject(sprintf('%s Sentinelle %s — %d alert(s), %d blocked in %d h', $breaches ? '🔴' : '🛡', $this->siteName, $alertTotal, $blocked, $hours))
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

    private function html(array $alerts, array $types, array $blocks, array $breaches, array $top, int $hours): string
    {
        $esc = static fn ($v): string => htmlspecialchars((string) $v, \ENT_QUOTES, 'UTF-8');
        $td = 'padding:4px 12px 4px 0';
        $num = 'padding:4px 0;text-align:right;font-variant-numeric:tabular-nums';
        $table = static fn (string $head, string $rows): string => '<table style="font-size:13px;border-collapse:collapse;margin:0 0 16px">'.$head.$rows.'</table>';
        $th = static fn (string ...$cols): string => '<tr>'.implode('', array_map(static fn ($c) => '<th style="text-align:left;padding:4px 12px 4px 0;color:#64748b;font-weight:normal">'.$c.'</th>', $cols)).'</tr>';

        $red = '';
        foreach ($breaches as $b) {
            $red .= '<li>'.$esc($b['created_at']).' — '.$esc($b['url']).' — '.$esc($b['ip']).'</li>';
        }

        $kindRows = '';
        foreach ($alerts as $kind => $a) {
            $when = \in_array($kind, $this->immediate, true) ? 'at once' : 'here only';
            $kindRows .= '<tr><td style="'.$td.'">'.$esc(self::KIND_LABELS[$kind] ?? $kind).'</td><td style="'.$num.'">'.$a['total'].'</td><td style="'.$td.';padding-left:12px;color:#64748b">'.$when.($a['emailed'] && 'here only' === $when ? ' ('.$a['emailed'].' emailed)' : '').'</td></tr>';
        }

        $typeRows = '';
        foreach (self::TYPE_LABELS as $type => $label) {
            $typeRows .= '<tr><td style="'.$td.'">'.$label.'</td><td style="'.$num.'">'.($types[$type] ?? 0).'</td></tr>';
        }

        $blockRows = '';
        foreach ($blocks as $reason => $n) {
            $blockRows .= '<tr><td style="'.$td.'">'.$esc($reason).'</td><td style="'.$num.'">'.$n.'</td></tr>';
        }

        $topRows = '';
        foreach ($top as $t) {
            $topRows .= '<tr><td style="'.$td.';font-family:monospace">'.$esc($t['ip']).'</td><td style="'.$num.'">'.$t['n'].'</td><td style="'.$td.';padding-left:12px;color:#64748b">'.($t['blocked'] ? 'blocked' : 'not blocked').'</td></tr>';
        }

        return '<div style="font-family:sans-serif;max-width:560px;margin:0 auto">'
            .($red ? '<div style="background:#b91c1c;color:#fff;padding:12px;border-radius:8px;font-weight:bold;margin:0 0 16px">🔴 Sensitive answers served:<ul>'.$red.'</ul></div>' : '')
            .'<h3 style="font-size:14px;margin:0 0 6px">Alerts in the last '.$hours.' h, by kind</h3>'
            .$table($th('Kind', 'Alerts', 'Emailed'), $kindRows)
            .'<h3 style="font-size:14px;margin:0 0 6px">Hostile requests</h3>'
            .$table('', $typeRows)
            .'<h3 style="font-size:14px;margin:0 0 6px">'.array_sum($blocks).' address(es) blocked automatically</h3>'
            .($blockRows ? $table($th('Reason', 'Addresses'), $blockRows) : '<p style="font-size:13px;color:#64748b">None in the window.</p>')
            .'<h3 style="font-size:14px;margin:0 0 6px">Top addresses</h3>'
            .($topRows ? $table($th('Address', 'Requests', 'Now'), $topRows) : '<p style="font-size:13px;color:#64748b">—</p>')
            .'<p style="font-size:12px;color:#64748b">Only what is in <code>sentinelle.alert.immediate</code> is emailed at once; everything else waits for this digest.</p>'
            .'</div>';
    }
}
