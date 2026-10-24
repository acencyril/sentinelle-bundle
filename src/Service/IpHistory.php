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
    public static function html(array $rows): string
    {
        if (!$rows) {
            return '<p style="font-size:12px;color:#64748b">No history recorded for this address.</p>';
        }
        $esc = static fn ($v): string => htmlspecialchars((string) ($v ?? '—'), \ENT_QUOTES, 'UTF-8');
        $hot = self::served($rows);
        $out = '<table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace">'
            .'<tr style="background:#f1f5f9"><th align="left" style="padding:4px">Time (UTC)</th><th align="left" style="padding:4px">Request</th><th align="left" style="padding:4px">Answer</th></tr>';
        foreach ($rows as $r) {
            $isHot = \in_array($r, $hot, true);
            $ok = null !== $r['status'] && $r['status'] >= 200 && $r['status'] < 300;
            $style = $isHot ? 'background:#b91c1c;color:#fff;font-weight:bold' : ($ok && 'page_view' !== $r['type'] ? 'background:#fef3c7' : '');
            $out .= '<tr style="'.$style.'"><td style="padding:3px 4px;white-space:nowrap">'.$esc(substr($r['at'], 5, 14)).'</td>'
                .'<td style="padding:3px 4px;word-break:break-all">'.$esc(trim(($r['method'] ?? '').' '.($r['url'] ?? ''))).'</td>'
                .'<td style="padding:3px 4px">'.$esc($r['status']).($isHot ? ' ⚠ SERVED' : '').'</td></tr>';
        }

        return $out.'</table>';
    }
}
