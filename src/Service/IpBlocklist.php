<?php

namespace Acencyril\SentinelleBundle\Service;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\Repository\BlockedIpRepository;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;

/**
 * The list of barred addresses, and the decision to add one to it.
 *
 * Read on every request by BlockedIpListener, written by SiteEventLogger when
 * an address crosses a threshold. Reads go through the cache: a database round
 * trip per request, for a list holding a handful of addresses, would be out of
 * proportion.
 */
class IpBlocklist
{
    /**
     * Default block duration by strike count: 24 hours, 7 days, then permanent.
     * Configurable through `blocking.durations`; the last value repeats.
     *
     * Progressive rather than permanent from the start: most scanning addresses
     * are compromised machines or cloud addresses being constantly reassigned.
     * An address that comes back after 24 hours, then after 7 days, is
     * deliberate. A permanent block can still catch real people behind a
     * shared address (an office, a mobile carrier): the human pass lets their
     * browsers through, see HumanPass.
     */
    public const DEFAULT_DURATIONS = ['+24 hours', '+7 days', 'permanent'];

    /** Cache key holding the whole list; invalidated on every write. */
    private const CACHE_KEY = 'ip_blocklist_active';
    private const CACHE_TTL = 300;

    /**
     * Never blocked, whatever they do.
     *
     * The private ranges cover the Docker network: without a correctly
     * configured reverse proxy, every request appears to come from the
     * container gateway, and a single scanner would get the whole site banned.
     *
     * @var string[] CIDR notation
     */
    private const ALWAYS_ALLOWED = [
        '127.0.0.0/8',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '::1/128',
    ];

    /** @var string[]|null Configured allowlist, split on first access. */
    private ?array $configuredAllowlist = null;

    public function __construct(
        private BlockedIpRepository $repository,
        private EntityManagerInterface $em,
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private IpIdentifier $identifier,
        // Nullable: '%env(default::SENTINELLE_ALLOWLIST)%' is null when the
        // variable is undefined, not the empty string.
        private ?string $allowlist = null,
        /**
         * Dry-run: detect and alert, but never block.
         *
         * Nobody wires automatic blocking into a live site without first seeing
         * what it would shut out. For the first weeks you want to read the log
         * and ask "would I have wanted to block this one?" — not find out
         * afterwards that a customer was banned.
         *
         * Refusals are logged with the decision that would have been taken,
         * duration included, which is what you need in order to judge before
         * switching it off.
         */
        private bool $dryRun = false,
        /** @var string[] Automatic block length by strike; the last one repeats. */
        private array $durations = self::DEFAULT_DURATIONS,
    ) {
        $this->durations = array_values(array_filter(array_map(
            static fn ($d): ?string => self::normaliseDuration((string) $d),
            $durations,
        ))) ?: self::DEFAULT_DURATIONS;
    }

    /**
     * "24 hours" or "+24 hours" become "+24 hours", "permanent" stays. Anything
     * that is not a time in the future is refused (null): "-1 day" or "now"
     * would block for nothing and look like it worked.
     */
    public static function normaliseDuration(string $duration): ?string
    {
        $duration = trim($duration);
        if ('permanent' === strtolower($duration)) {
            return 'permanent';
        }
        if ('' === $duration) {
            return null;
        }
        if (!\in_array($duration[0], ['+', '-'], true)) {
            $duration = '+'.$duration;
        }
        $now = new \DateTimeImmutable();
        try {
            $then = $now->modify($duration);
        } catch (\Throwable) {
            return null;
        }

        return false !== $then && $then > $now ? $duration : null;
    }

    /**
     * What an automatic block on this strike would last: a relative time or
     * "permanent".
     */
    public function durationFor(int $strikes): string
    {
        return $this->durations[max(1, min($strikes, \count($this->durations))) - 1];
    }

    /**
     * Should this address be turned away right now?
     */
    public function isBlocked(string $ip): bool
    {
        if ($this->isAllowed($ip)) {
            return false;
        }

        return in_array($ip, $this->activeIps(), true);
    }

    /**
     * A protected address can be blocked neither automatically nor by hand.
     */
    public function isAllowed(string $ip): bool
    {
        foreach (self::ALWAYS_ALLOWED as $cidr) {
            if (self::matchesCidr($ip, $cidr)) {
                return true;
            }
        }

        foreach ($this->configuredAllowlist() as $entry) {
            if ($entry === $ip || (str_contains($entry, '/') && self::matchesCidr($ip, $entry))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Adds or extends a block. Returns the entry, or null when the address is
     * protected by the allowlist.
     *
     * Idempotent: calling again for the same address while the block is running
     * does not add a strike; only a fresh block after expiry counts.
     */
    public function block(string $ip, string $reason, string $source = BlockedIp::SOURCE_AUTO, ?string $ttl = null): ?BlockedIp
    {
        if ($this->isAllowed($ip)) {
            $this->logger->info('Block skipped: IP is allowlisted', ['ip' => $ip, 'reason' => $reason]);

            return null;
        }

        if ($this->isProtectedProvider($ip)) {
            $this->logger->warning('Block refused: IP belongs to a critical provider', ['ip' => $ip, 'reason' => $reason]);

            return null;
        }

        if ($this->dryRun) {
            $this->logger->warning('Sentinelle dry-run: block SIMULATED', [
                'ip' => $ip,
                'reason' => $reason,
                'source' => $source,
                'would_have_lasted' => $ttl ?? ($source === BlockedIp::SOURCE_MANUAL ? 'permanent' : $this->durationFor(1)),
            ]);

            return null;
        }

        try {
            $existing = $this->repository->findOneByIp($ip);

            if ($existing !== null && !$existing->isExpired()) {
                return $existing;
            }

            $entry = $existing ?? new BlockedIp($ip, $reason, $source);
            $strikes = $existing !== null ? $existing->getStrikes() + 1 : 1;

            $entry->setReason($reason)->setSource($source)->setStrikes($strikes);
            $entry->setExpiresAt($this->expiryFor($strikes, $source, $ttl));

            $this->em->persist($entry);
            $this->em->flush();
            $this->invalidate();

            $this->logger->warning('IP blocked', [
                'ip'         => $ip,
                'reason'     => $reason,
                'source'     => $source,
                'strikes'    => $strikes,
                'expires_at' => $entry->getExpiresAt()?->format('c') ?? 'never',
            ]);

            return $entry;
        } catch (\Throwable $e) {
            // Blocking is a protection, not a vital function: if it fails, the
            // request in flight must carry on as normal.
            $this->logger->error('Failed to block IP', ['ip' => $ip, 'error' => $e->getMessage()]);

            return null;
        }
    }

    public function unblock(string $ip): bool
    {
        $entry = $this->repository->findOneByIp($ip);
        if ($entry === null) {
            return false;
        }

        $this->em->remove($entry);
        $this->em->flush();
        $this->invalidate();

        $this->logger->info('IP unblocked', ['ip' => $ip]);

        return true;
    }

    /**
     * Counts a refused request, so the dashboard shows whether the address is
     * still insisting after being blocked.
     */
    public function registerHit(string $ip): void
    {
        try {
            $entry = $this->repository->findOneByIp($ip);
            if ($entry !== null) {
                $entry->registerHit();
                $this->em->flush();
            }
        } catch (\Throwable $e) {
            $this->logger->warning('Failed to count hit on blocked IP', ['ip' => $ip, 'error' => $e->getMessage()]);
        }
    }

    /**
     * @return BlockedIp[]
     */
    public function activeEntries(): array
    {
        return $this->repository->findActive();
    }

    public function purgeExpired(\DateTimeImmutable $before): int
    {
        $deleted = $this->repository->purgeExpired($before);
        $this->invalidate();

        return $deleted;
    }

    /**
     * @return string[]
     */
    private function activeIps(): array
    {
        try {
            $item = $this->cache->getItem(self::CACHE_KEY);
            if ($item->isHit()) {
                return $item->get();
            }

            $ips = $this->repository->findActiveIps();
            $item->set($ips)->expiresAfter(self::CACHE_TTL);
            $this->cache->save($item);

            return $ips;
        } catch (\Throwable $e) {
            // Cache or database unavailable: let the traffic through. A missed
            // block is less serious than a site turning everybody away.
            $this->logger->warning('Could not read the blocklist', ['error' => $e->getMessage()]);

            return [];
        }
    }

    private function invalidate(): void
    {
        try {
            $this->cache->deleteItem(self::CACHE_KEY);
        } catch (\Throwable) {
            // Harmless: the entry expires on its own within five minutes.
        }
    }

    /**
     * Null means permanent.
     */
    private function expiryFor(int $strikes, string $source, ?string $ttl): ?\DateTimeImmutable
    {
        if ($ttl !== null) {
            return $ttl === 'permanent' ? null : new \DateTimeImmutable($ttl);
        }

        // A manual block with no explicit duration is a deliberate choice:
        // permanent.
        if ($source === BlockedIp::SOURCE_MANUAL) {
            return null;
        }

        $interval = $this->durationFor($strikes);

        return 'permanent' === $interval ? null : new \DateTimeImmutable($interval);
    }

    /**
     * Does this address belong to a provider whose blocking would break a
     * working part of the site — email delivery, payments, signatures?
     *
     * A Mailgun address was once blocked BY HAND from the dashboard: it appeared
     * there as suspicious after a 401. All inbound mail would have died
     * silently, and nobody would have known for hours. The path exemption only
     * covered AUTOMATIC blocking.
     *
     * Deliberately called from block() only, never from isBlocked(): a reverse
     * lookup per incoming request would be ruinous. The cost is paid once, at
     * the moment of the decision.
     */
    private function isProtectedProvider(string $ip): bool
    {
        return $this->identifier->identify($ip)['critical'];
    }

    /**
     * @return string[]
     */
    private function configuredAllowlist(): array
    {
        if ($this->configuredAllowlist === null) {
            $this->configuredAllowlist = array_values(array_filter(
                array_map('trim', explode(',', $this->allowlist ?? ''))
            ));
        }

        return $this->configuredAllowlist;
    }

    /**
     * CIDR membership test, IPv4 and IPv6.
     */
    private static function matchesCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $bits = $bits === null ? strlen($ipBin) * 8 : (int) $bits;
        $wholeBytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;

        if ($wholeBytes > 0 && substr($ipBin, 0, $wholeBytes) !== substr($subnetBin, 0, $wholeBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = 0xFF << (8 - $remainingBits) & 0xFF;

        return (ord($ipBin[$wholeBytes]) & $mask) === (ord($subnetBin[$wholeBytes]) & $mask);
    }
}