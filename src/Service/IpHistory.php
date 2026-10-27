<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

use Doctrine\DBAL\Connection;

/**
 * What an address did on the site lately, read from Sentinelle's own log (sentinelle_visit):
 * every request, its answer, its time. Every alert carries it, so it never comes without its
 * context, and it tells whether one of the tries got through.
 */
class IpHistory
{
    public function __construct(private Connection $db)
    {
    }

    /** @return list<array{at: string, type: string, url: ?string, status: ?int, method: ?string}> */
    public function of(string $ip, int $hours = 48, int $limit = 80): array
    {
        try {
            $rows = $this->db->fetchAllAssociative(
                'SELECT created_at, event_type, url, status_code, meta FROM sentinelle_visit WHERE ip = ? AND created_at >= ? ORDER BY created_at DESC LIMIT '.max(1, $limit),
                [$ip, (new \DateTimeImmutable("-{$hours} hours"))->format('Y-m-d H:i:s')],
            );
        } catch (\Throwable) {
            return [];
        }

        return array_map(static function (array $r): array {
            $meta = json_decode((string) ($r['meta'] ?? ''), true) ?: [];

            return [
                'at' => (string) $r['created_at'],
                'type' => (string) $r['event_type'],
                'url' => $r['url'] ?? null,
                'status' => null !== ($r['status_code'] ?? null) ? (int) $r['status_code'] : (isset($meta['status']) ? (int) $meta['status'] : null),
                'method' => $meta['method'] ?? null,
            ];
        }, $rows);
    }

    /** The rows where something sensitive was actually served. */
    public static function served(array $rows): array
    {
        return array_values(array_filter($rows, static fn (array $r): bool => 'breach_served' === $r['type']
            || (null !== $r['status'] && $r['status'] >= 200 && $r['status'] < 300 && null !== $r['url'] && Sensitive::isSensitivePath($r['url']))));
    }

    /** The history as an email table, a sensitive answer that went out in red. */
    public static function html(array $rows, ?Mail $mail = null): string
    {
        $mail ??= new Mail();
        if (!$rows) {
            return '<p style="font-size:13px;color:'.Mail::MUTED.'">'.Mail::esc($mail->t('history.none')).'</p>';
        }
        $hot = self::served($rows);
        $cells = [];
        $styles = [];
        foreach ($rows as $r) {
            $isHot = \in_array($r, $hot, true);
            $ok = null !== $r['status'] && $r['status'] >= 200 && $r['status'] < 300;
            $styles[] = $isHot ? 'background:#b91c1c;color:#ffffff;font-weight:bold' : ($ok && 'page_view' !== $r['type'] ? 'background:#fef3c7' : '');
            $cells[] = [
                '<span style="white-space:nowrap">'.Mail::esc(substr($r['at'], 5, 14)).'</span>',
                Mail::mono(Mail::esc(trim(($r['method'] ?? '').' '.($r['url'] ?? '')))),
                Mail::esc($r['status']).($isHot ? ' ⚠ '.Mail::esc($mail->t('history.served')) : ''),
            ];
        }

        return Mail::table([$mail->t('history.time'), $mail->t('history.request'), $mail->t('history.answer')], $cells, [], $styles);
    }
}
