<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * A way back in for the real people behind a blocked address.
 *
 * Blocks are per address, and an address is not a person. An office, a school or a mobile
 * carrier puts hundreds of people behind one IP; a single infected machine among them gets
 * that IP blocked, sometimes for good, and everybody else with it. They did nothing.
 *
 * So a blocked address asking for a page gets a challenge instead of a bare refusal: a small
 * proof of work, solved by the browser in a second or two, with no third party involved. Solved,
 * it earns a signed cookie bound to the address, valid 24 hours, that lets that browser through.
 * The address itself stays blocked: a scanner that does not run JavaScript, or does not keep
 * cookies, still gets the door. Sensitive paths (.env, .git…) stay closed even with a pass.
 *
 * Stateless where it can be: challenges and passes are HMAC-signed with the kernel secret and
 * carry their own expiry. The cache only holds what has to be remembered: attempts per address
 * (rate limit), challenges already used (no replay) and revocations (an address whose pass was
 * used for an attack loses it).
 */
final class HumanPass
{
    public const COOKIE = 'sentinelle_pass';
    /** Where the solved challenge is posted. Only ever answered for a blocked address. */
    public const PATH = '/_sentinelle/pass';
    /** Request attribute: this request from a blocked address was let through by a valid pass. */
    public const PASSED_ATTRIBUTE = '_sentinelle_passed';
    /** Request attribute: this request earned a pass. Logged as "human_pass". */
    public const GRANTED_ATTRIBUTE = '_sentinelle_pass_granted';

    private const CHALLENGE_TTL = 600;

    public function __construct(
        private string $secret,
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger = new NullLogger(),
        private int $ttl = 86400,
        /** Leading zero bits of sha256(challenge.solution): 16 is about 65,000 hashes, a second or two. */
        private int $difficulty = 16,
        private int $maxAttempts = 10,
        private int $attemptWindow = 600,
    ) {
        if ('' === $this->secret) {
            throw new \InvalidArgumentException('Sentinelle: the human pass needs a non-empty kernel.secret.');
        }
    }

    public function difficulty(): int
    {
        return $this->difficulty;
    }

    public function ttl(): int
    {
        return $this->ttl;
    }

    /** A challenge for this address: "<issued>.<nonce>.<signature>". */
    public function challenge(string $ip, ?int $now = null): string
    {
        $issued = (string) ($now ?? time());
        $nonce = bin2hex(random_bytes(12));

        return $issued.'.'.$nonce.'.'.$this->sign('challenge', $ip, $issued.'.'.$nonce);
    }

    /**
     * True when the challenge was issued to this address, is recent, has not been used yet,
     * and sha256(challenge.solution) starts with enough zero bits.
     */
    public function verify(string $ip, string $challenge, string $solution, ?int $now = null): bool
    {
        $now ??= time();
        $parts = explode('.', $challenge);
        if (3 !== \count($parts) || !ctype_digit($parts[0]) || 1 !== preg_match('/^\d{1,12}$/', $solution)) {
            return false;
        }
        [$issued, $nonce, $signature] = $parts;
        if (!hash_equals($this->sign('challenge', $ip, $issued.'.'.$nonce), $signature)) {
            return false;
        }
        if ((int) $issued > $now + 60 || $now - (int) $issued > self::CHALLENGE_TTL) {
            return false;
        }
        if (!self::hasLeadingZeroBits(hash('sha256', $challenge.$solution, true), $this->difficulty)) {
            return false;
        }

        return $this->consume($nonce);
    }

    /** The cookie value: "<expires>.<signature>", bound to the address. */
    public function passFor(string $ip, ?int $now = null): string
    {
        $expires = (string) (($now ?? time()) + $this->ttl);

        return $expires.'.'.$this->sign('pass', $ip, $expires);
    }

    public function isValidPass(?string $value, string $ip, ?int $now = null): bool
    {
        if (null === $value || 1 !== preg_match('/^(\d{1,12})\.([A-Za-z0-9_-]{20,})$/', $value, $m)) {
            return false;
        }
        if ((int) $m[1] <= ($now ?? time()) || !hash_equals($this->sign('pass', $ip, $m[1]), $m[2])) {
            return false;
        }

        return !$this->isRevoked($ip);
    }

    /**
     * Counts one attempt to solve the challenge; false once the address has used its quota.
     * Each attempt costs a hash on our side and nothing else, but an unbounded endpoint on a
     * blocked address is still an invitation.
     */
    public function allowAttempt(string $ip): bool
    {
        try {
            $item = $this->cache->getItem('sentinelle_pass_try_'.self::key($ip));
            $count = ($item->isHit() ? (int) $item->get() : 0) + 1;
            $this->cache->save($item->set($count)->expiresAfter($this->attemptWindow));

            return $count <= $this->maxAttempts;
        } catch (\Throwable) {
            return true;
        }
    }

    /**
     * Withdraws every pass of an address and stops offering it the challenge, for as long as a
     * pass lives. Called when a request let through by a pass looks like an attack: the person
     * behind the browser was not a person after all.
     */
    public function revoke(string $ip): void
    {
        try {
            $item = $this->cache->getItem('sentinelle_pass_revoked_'.self::key($ip));
            $this->cache->save($item->set(time())->expiresAfter($this->ttl));
            $this->logger->warning('Sentinelle: human pass revoked', ['ip' => $ip]);
        } catch (\Throwable $e) {
            $this->logger->warning('Sentinelle: could not revoke a human pass', ['ip' => $ip, 'error' => $e->getMessage()]);
        }
    }

    public function isRevoked(string $ip): bool
    {
        try {
            return $this->cache->getItem('sentinelle_pass_revoked_'.self::key($ip))->isHit();
        } catch (\Throwable) {
            return false;
        }
    }

    public static function hasLeadingZeroBits(string $binary, int $bits): bool
    {
        $whole = intdiv($bits, 8);
        for ($i = 0; $i < $whole; ++$i) {
            if ("\0" !== $binary[$i]) {
                return false;
            }
        }
        $rest = $bits % 8;

        return 0 === $rest || 0 === (\ord($binary[$whole]) >> (8 - $rest));
    }

    /** A challenge is good for one pass: a solved one replayed is refused. */
    private function consume(string $nonce): bool
    {
        try {
            $item = $this->cache->getItem('sentinelle_pass_used_'.self::key($nonce));
            if ($item->isHit()) {
                return false;
            }
            $this->cache->save($item->set(1)->expiresAfter(self::CHALLENGE_TTL + 60));
        } catch (\Throwable) {
            // No cache: a replay only yields another pass for the same address.
        }

        return true;
    }

    private function sign(string $purpose, string $ip, string $payload): string
    {
        return rtrim(strtr(base64_encode(hash_hmac('sha256', 'sentinelle|'.$purpose.'|'.$ip.'|'.$payload, $this->secret, true)), '+/', '-_'), '=');
    }

    private static function key(string $value): string
    {
        return preg_replace('/[^a-z0-9_]/i', '_', $value) ?? sha1($value);
    }
}
