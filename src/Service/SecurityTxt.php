<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

/**
 * The site's security.txt (RFC 9116): who to write to when you find a flaw.
 *
 * Generated, never a file in public/: a static file's Expires date is the field
 * everybody forgets, and an expired security.txt tells a researcher the address
 * in it is probably dead too. Here Expires is recomputed from today, so it is
 * always in the future and always less than a year away, as the RFC asks.
 *
 * Relative URLs ("/en/security") are made absolute against the address the file
 * was asked on, so one configuration serves every environment.
 */
final class SecurityTxt
{
    public const PATH = '/.well-known/security.txt';
    public const LEGACY_PATH = '/security.txt';

    /**
     * @param list<string> $contact
     * @param list<string> $preferredLanguages
     * @param list<string> $canonical
     * @param list<string> $encryption
     */
    public function __construct(
        private readonly array $contact,
        private readonly string $expires = '+11 months',
        private readonly array $preferredLanguages = [],
        private readonly ?string $policy = null,
        private readonly array $canonical = [],
        private readonly array $encryption = [],
        private readonly ?string $acknowledgments = null,
        private readonly ?string $hiring = null,
    ) {
        if ([] === $contact) {
            throw new \InvalidArgumentException('security.txt needs at least one contact (RFC 9116 §2.5.3).');
        }
    }

    /** The file's content, as served to $origin ("https://example.com"). */
    public function render(string $origin, ?\DateTimeImmutable $now = null): string
    {
        $origin = rtrim($origin, '/');
        $lines = [];
        foreach ($this->contact as $c) {
            $lines[] = 'Contact: '.self::absolute($c, $origin);
        }
        $lines[] = 'Expires: '.$this->expiresAt($now)->format('Y-m-d\TH:i:s\Z');
        foreach ($this->encryption as $e) {
            $lines[] = 'Encryption: '.self::absolute($e, $origin);
        }
        if (null !== $this->acknowledgments) {
            $lines[] = 'Acknowledgments: '.self::absolute($this->acknowledgments, $origin);
        }
        if ([] !== $this->preferredLanguages) {
            $lines[] = 'Preferred-Languages: '.implode(', ', $this->preferredLanguages);
        }
        foreach ([] !== $this->canonical ? $this->canonical : [self::PATH] as $c) {
            $lines[] = 'Canonical: '.self::absolute($c, $origin);
        }
        if (null !== $this->policy) {
            $lines[] = 'Policy: '.self::absolute($this->policy, $origin);
        }
        if (null !== $this->hiring) {
            $lines[] = 'Hiring: '.self::absolute($this->hiring, $origin);
        }

        return implode("\n", $lines)."\n";
    }

    /**
     * Midnight UTC of today, moved by the configured interval: stable for a whole day (so the
     * file can be cached), and never more than a year ahead with the default.
     */
    public function expiresAt(?\DateTimeImmutable $now = null): \DateTimeImmutable
    {
        $today = ($now ?? new \DateTimeImmutable())->setTimezone(new \DateTimeZone('UTC'))->setTime(0, 0);

        return $today->modify($this->expires);
    }

    /** Whether $expires is a usable interval: in the future, at most a year and a day away. */
    public static function isValidInterval(string $expires): bool
    {
        $now = new \DateTimeImmutable('2026-01-01T00:00:00Z');
        try {
            $at = @$now->modify($expires);
        } catch (\Throwable) {
            return false;
        }

        return $at instanceof \DateTimeImmutable && $at > $now && $at <= $now->modify('+366 days');
    }

    private static function absolute(string $value, string $origin): string
    {
        return str_starts_with($value, '/') ? $origin.$value : $value;
    }
}
