<?php

namespace Acencyril\SentinelleBundle\Service;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\EventListener\BlockedIpListener;
use Doctrine\DBAL\Connection;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Records requests into sentinelle_visit.
 *
 * Called from SiteActivityListener on kernel.terminate: the response has
 * already reached the client, so the insert costs nothing in perceived latency.
 *
 * Three goals, in that order:
 *   1. keep a scanner from filling the table (per-IP anti-flood);
 *   2. classify what is abnormal (status code and event type);
 *   3. send an email about what is genuinely dangerous.
 *
 * Written through raw DBAL rather than the ORM: this is an append-only write
 * happening on every request, there is no point loading the UnitOfWork, and it
 * is immune to an EntityManager already closed by an earlier exception.
 */
class SiteEventLogger
{
    /**
     * Pure noise, never recorded.
     *
     * The admin prefix is added on the fly: an observation tool must not log
     * itself. Without that, opening the dashboard filled the table with its own
     * visits — eight rows out of fifteen on the first try — and the referer
     * exposed admin navigation.
     */
    private const IGNORED_PREFIXES = ['/_wdt', '/_profiler', '/_fragment', '/health', '/favicon.ico'];

    /**
     * Critical payloads: code execution, SQL injection, directory traversal,
     * Log4Shell. These are the ones that still reach PHP, since /.env, /.git
     * and /wp-* probes are often stopped upstream by the web server. They
     * trigger an immediate email.
     */
    private const CRITICAL_PATTERNS = [
        'rce_php_wrapper' => '#php://(input|filter)|auto_prepend_file|allow_url_include#i',
        'rce_exec'        => '#eval-stdin|\b(system|exec|passthru|shell_exec|proc_open)\s*\(#i',
        'sql_injection'   => '#(\bunion\b[\s/*]+\bselect\b)|(\bor\b\s+1\s*=\s*1\b)|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|information_schema|\bdrop\s+table\b#i',
        'path_traversal'  => '#(\.\.[/\\\\]){2,}|/etc/passwd|/proc/self/environ#i',
        'log4shell'       => '#\$\{jndi:#i',
        'deserialization' => '#O:\d+:"[a-z_\\\\]+":\d+:\{#i',
    ];

    /**
     * More ordinary probes: noisy but not immediately dangerous. Recorded as
     * scan_probe, with no individual email — it is the burst that alerts.
     */
    private const SUSPICIOUS_PATTERNS = [
        '#\.(env|sql|bak|old|orig|ya?ml|ini|pem|key|log)$#i',
        '#/\.(git|aws|azure|kube|docker|ssh|gcloud|anthropic|openai|cursor)#i',
        '#(wp-|wordpress|xmlrpc|phpmyadmin|adminer|actuator|cgi-bin|\.well-known/security)#i',
        '#(credentials|secrets?|service.?account|serviceaccountkey|id_rsa|client_secret)#i',
        '#<script\b|javascript:|onerror\s*=#i',
    ];

    /**
     * Six former class constants are arguments now. The original values suited
     * one application; a high-traffic site wants a wider anti-flood quota, a
     * confidential one wants lower thresholds. The defaults below are the
     * values that were actually run in production.
     */
    public function __construct(
        private Connection $connection,
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private SecurityAlert $notifier,
        private IpBlocklist $blocklist,
        /** @var array{burst:int,burst_window:int,bruteforce:int,bruteforce_window:int,flood_max:int,flood_window:int} */
        private array $thresholds = [],
        private int $alertCooldown = 3600,
        /**
         * Paths whose refusals never trigger an automatic block.
         *
         * An inbound webhook answers 401 as soon as the signature does not
         * match. That has already happened for a perfectly legitimate delivery,
         * while a signing key was making its way to the container environment.
         * With automatic blocking, that configuration incident would have
         * banned the provider and cut off all incoming mail — an outage far
         * worse than the one being prevented.
         *
         * @var string[]
         */
        private array $exemptPaths = ['/api/webhook/'],
        /** @var array<string,string> */
        private array $extraPatterns = [],
        /** @var string[] */
        private array $extraIgnored = [],
        private string $adminPrefix = '/admin/activity',
        private ?HumanPass $humanPass = null,
    ) {
        $this->thresholds += [
            'burst' => 15, 'burst_window' => 600,
            'bruteforce' => 10, 'bruteforce_window' => 600,
            'flood_max' => 5, 'flood_window' => 3600,
        ];
    }

    /**
     * Entry point: records a finished request.
     *
     * The whole body is guarded, not just the write. Wrapping only the insert
     * left errors in the classification or the counters free to propagate — and
     * on `kernel.terminate` the response has already been sent, so the exception
     * goes nowhere. The site answers 200, the table stays empty, and nothing
     * says why. A logger that can fail silently is worse than no logger: you
     * believe it is running.
     */
    public function logRequest(Request $request, Response $response): void
    {
        try {
            $this->record($request, $response);
        } catch (\Throwable $e) {
            $this->logger->error('Sentinelle: logging failed', [
                'error' => $e->getMessage(),
                'file'  => $e->getFile().':'.$e->getLine(),
            ]);
        }
    }

    private function record(Request $request, Response $response): void
    {
        $path = $request->getPathInfo();

        // Added to, never replaced. The admin prefix is configurable: the
        // observation tool must never log itself, wherever it is mounted.
        $ignored = array_merge(self::IGNORED_PREFIXES, $this->extraIgnored, [$this->adminPrefix]);
        foreach ($ignored as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return;
            }
        }

        $status = $response->getStatusCode();
        $ip = $request->getClientIp() ?? 'unknown';
        $query = $request->getQueryString() ?? '';

        // What the patterns are matched against: path plus query string. The
        // POST body is not inspected — expensive, and often personal data that
        // should not be stored.
        $haystack = rawurldecode($path . ($query !== '' ? '?' . $query : ''));

        $critical = $this->matchCritical($haystack);
        $suspicious = $critical === null && $this->isSuspicious($haystack);

        // A request already turned away by BlockedIpListener gets its own type.
        // Without this it would fall under 'access_denied', inflate the address's
        // brute-force counter and extend its block indefinitely — a blocked
        // address could then never leave the list.
        $alreadyBlocked = $request->attributes->getBoolean(BlockedIpListener::REQUEST_ATTRIBUTE);

        $type = match (true) {
            $request->attributes->getBoolean(HumanPass::GRANTED_ATTRIBUTE) => 'human_pass',
            $alreadyBlocked    => 'ip_blocked',
            $critical !== null => 'attack_attempt',
            $suspicious        => 'scan_probe',
            $status >= 500     => 'server_error',
            $status === 404    => 'not_found',
            $status === 401 || $status === 403 => 'access_denied',
            $status >= 400     => 'client_error',
            default            => 'page_view',
        };

        $meta = array_filter([
            'method'  => $request->getMethod(),
            'query'   => $query !== '' ? mb_substr($this->redact($query), 0, 500) : null,
            'pattern' => $critical,
            'referer' => $request->headers->get('Referer'),
        ]);

        // Anti-flood: a 155-request scan in 16 seconds must not produce 155
        // rows. Ordinary page views and critical attacks always get through —
        // those are the ones we want complete.
        //
        // The quota stops the INSERT only: evaluateAlerts must keep counting,
        // otherwise the burst threshold would never be reached and the alerting
        // mechanism would neutralise itself after five probes.
        $flooding = $type !== 'page_view' && $type !== 'human_pass' && $critical === null && $this->isFlooding($ip, $type);

        if (!$flooding) {
            $this->insert($type, $path, $status, $ip, $request->headers->get('User-Agent'), $meta);
        }

        $this->evaluateAlerts($type, $critical, $path, $status, $ip, $request, $meta);
    }

    /**
     * Manual logging from application code.
     */
    public function log(string $type, ?string $url = null, ?string $ip = null, ?string $userAgent = null, array $meta = []): void
    {
        $this->insert($type, $url, null, $ip, $userAgent, $meta);
    }

    private function insert(string $type, ?string $url, ?int $status, ?string $ip, ?string $userAgent, array $meta): void
    {
        try {
            $this->connection->insert('sentinelle_visit', [
                'event_type'  => mb_substr($type, 0, 255),
                'url'         => $url !== null ? mb_substr($url, 0, 255) : null,
                'status_code' => $status,
                'ip'          => $ip !== null ? mb_substr($ip, 0, 45) : null,
                'user_agent'  => $userAgent !== null ? mb_substr($userAgent, 0, 255) : null,
                'meta'        => json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                'created_at'  => (new \DateTimeImmutable())->format('Y-m-d H:i:s'),
            ]);
        } catch (\Throwable $e) {
            // Logging must never break a request, nor close the EntityManager.
            $this->logger->warning('sentinelle_visit insert failed', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Redacts sensitive values before writing to the database.
     *
     * A webhook may accept its secret as a URL parameter when the provider
     * cannot send headers. Without this masking, every legitimate call would
     * write the secret in cleartext into a table readable from the admin
     * dashboard.
     */
    private function redact(string $query): string
    {
        return preg_replace(
            '/\b(secret|token|api[-_]?key|password|signature)=[^&]*/i',
            '$1=***',
            $query
        ) ?? $query;
    }

    private function matchCritical(string $haystack): ?string
    {
        // Project patterns are added; none are ever removed.
        foreach (array_merge(self::CRITICAL_PATTERNS, $this->extraPatterns) as $name => $pattern) {
            if (preg_match($pattern, $haystack) === 1) {
                return $name;
            }
        }

        return null;
    }

    private function isSuspicious(string $haystack): bool
    {
        foreach (self::SUSPICIOUS_PATTERNS as $pattern) {
            if (preg_match($pattern, $haystack) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * True when this address has already exceeded its error-row quota for the
     * window.
     */
    private function isFlooding(string $ip, string $type): bool
    {
        return $this->bump('flood_' . $ip . '_' . $type, $this->thresholds['flood_window'])
            > $this->thresholds['flood_max'];
    }

    private function evaluateAlerts(
        string $type,
        ?string $critical,
        string $path,
        int $status,
        string $ip,
        Request $request,
        array $meta,
    ): void {
        // Already blocked: nothing to reassess, and above all no counter to
        // increment.
        if ($type === 'ip_blocked' || $type === 'human_pass') {
            return;
        }

        $reason = null;
        $detail = null;
        $kind = null;

        if ($critical !== null) {
            $kind = 'exploitation';
            $reason = 'Exploitation attempt';
            $detail = 'Pattern matched: ' . $critical;
        } elseif ($type === 'access_denied') {
            $count = $this->bump('bf_' . $ip, $this->thresholds['bruteforce_window']);
            // >= rather than ==: two concurrent requests can skip the exact
            // value. The per-IP cooldown already prevents a repeated email.
            if ($count >= $this->thresholds['bruteforce']) {
                $kind = 'brute_force';
                $reason = 'Likely brute force';
                $detail = sprintf('%d access denials in under %d minutes', $count, $this->thresholds['bruteforce_window'] / 60);
            }
        } elseif ($type === 'scan_probe' || $type === 'not_found') {
            $count = $this->bump('burst_' . $ip, $this->thresholds['burst_window']);
            if ($count >= $this->thresholds['burst']) {
                $kind = 'scan';
                $reason = 'Automated scan';
                $detail = sprintf('%d probes in under %d minutes', $count, $this->thresholds['burst_window'] / 60);
            }
        }

        if ($reason === null) {
            return;
        }

        // Let through by a human pass, and still attacking: whoever solved the
        // challenge was not a person reading pages. The pass goes, for every
        // browser on that address, and the challenge is no longer offered.
        if ($this->humanPass !== null && $request->attributes->getBoolean(HumanPass::PASSED_ATTRIBUTE)) {
            $this->humanPass->revoke($ip);
        }

        // Blocking follows exactly the thresholds that already triggered the
        // email: what deserved warning a human deserves closing the door. The
        // difference is that the door now closes without waiting for anyone to
        // read their mail.
        $blocked = $this->autoBlock($ip, $path, $reason, $detail);

        if (!$this->acquireAlertSlot($ip)) {
            return;
        }

        if ($blocked !== null) {
            $detail .= sprintf(
                ' — IP blocked automatically (%s)',
                $blocked->isPermanent() ? 'permanently' : 'until ' . $blocked->getExpiresAt()->format('Y-m-d H:i')
            );
        }

        $emailed = $this->notifier->notify([
            'reason'     => $reason,
            'detail'     => $detail,
            'ip'         => $ip,
            'path'       => $path,
            'method'     => $request->getMethod(),
            'query'      => $meta['query'] ?? null,
            'status'     => $status,
            'user_agent' => $request->headers->get('User-Agent'),
            'kind'       => $kind,
        ], $blocked);

        // Every alert leaves a row, emailed or not: the daily digest counts them by kind, so an
        // alert held back by `alert.immediate` is never lost. One per address per cooldown,
        // like the emails they replace.
        $this->insert('alert', $path, $status, $ip, $request->headers->get('User-Agent'), array_filter([
            'kind'    => $kind,
            'reason'  => $reason,
            'detail'  => $detail,
            'emailed' => $emailed,
            'blocked' => $blocked !== null,
        ], static fn ($v) => $v !== null));
    }

    /**
     * Adds the address to the blocklist, unless the path is exempt.
     */
    private function autoBlock(string $ip, string $path, string $reason, ?string $detail): ?BlockedIp
    {
        foreach ($this->exemptPaths as $prefix) {
            if (str_starts_with($path, $prefix)) {
                $this->logger->info('Automatic block skipped: exempt path', ['ip' => $ip, 'path' => $path]);

                return null;
            }
        }

        return $this->blocklist->block($ip, $detail !== null ? $reason . ' — ' . $detail : $reason);
    }

    /**
     * Increments a sliding-window counter and returns its value. Approximate by
     * nature — there is no atomicity — which is good enough for a threshold.
     */
    private function bump(string $key, int $ttl): int
    {
        try {
            $item = $this->cache->getItem('sev_' . preg_replace('/[^a-z0-9_]/i', '_', $key));
            $count = ($item->isHit() ? (int) $item->get() : 0) + 1;
            $item->set($count)->expiresAfter($ttl);
            $this->cache->save($item);

            return $count;
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Alert throttling: at most one email per address per hour.
     */
    private function acquireAlertSlot(string $ip): bool
    {
        try {
            $item = $this->cache->getItem('sev_alert_' . preg_replace('/[^a-z0-9_]/i', '_', $ip));
            if ($item->isHit()) {
                return false;
            }
            $item->set(1)->expiresAfter($this->alertCooldown);
            $this->cache->save($item);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }
}