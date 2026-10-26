<?php

namespace Acencyril\SentinelleBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * One request received by the site — who, when, what, and how it ended.
 *
 * Everything is recorded, not just attacks. An attempt cannot be recognised on
 * its own: it is recognised by contrast with ordinary traffic. Without the page
 * views you are left with a list of alarms and no scale, unable to tell whether
 * three 404s are a scan or a dead link.
 */
#[ORM\Entity]
#[ORM\Table(name: 'sentinelle_visit')]
#[ORM\Index(name: 'idx_sentinelle_visit_created', columns: ['created_at'])]
#[ORM\Index(name: 'idx_sentinelle_visit_ip_created', columns: ['ip', 'created_at'])]
#[ORM\Index(name: 'idx_sentinelle_visit_type_created', columns: ['event_type', 'created_at'])]
class Visit
{
    #[ORM\Id, ORM\GeneratedValue, ORM\Column(type: 'integer')]
    private ?int $id = null;

    /** page_view, not_found, access_denied, scan_probe, attack_attempt… */
    #[ORM\Column(type: 'string', length: 255)]
    private string $eventType;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $url = null;

    /** Response status. Nullable for rows written before it was recorded. */
    #[ORM\Column(type: 'smallint', nullable: true)]
    private ?int $statusCode = null;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column(type: 'string', length: 45, nullable: true)]
    private ?string $ip = null;

    /**
     * Method, query string, matched pattern, referer.
     *
     * Secrets are redacted before this is written: a `?token=…` parameter is
     * stored as `token=***`. Without that, every legitimate call would put a
     * secret in cleartext into a table readable from the admin interface.
     */
    #[ORM\Column(type: 'json', nullable: true)]
    private ?array $meta = [];

    #[ORM\Column(type: 'datetime')]
    private \DateTimeInterface $createdAt;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(?int $id): void
    {
        $this->id = $id;
    }

    public function getEventType(): string
    {
        return $this->eventType;
    }

    public function setEventType(string $eventType): void
    {
        $this->eventType = $eventType;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function setUrl(?string $url): void
    {
        $this->url = $url;
    }

    public function getStatusCode(): ?int
    {
        return $this->statusCode;
    }

    public function setStatusCode(?int $statusCode): void
    {
        $this->statusCode = $statusCode;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function setUserAgent(?string $userAgent): void
    {
        $this->userAgent = $userAgent;
    }

    public function getIp(): ?string
    {
        return $this->ip;
    }

    public function setIp(?string $ip): void
    {
        $this->ip = $ip;
    }

    public function getMeta(): array
    {
        // The column is nullable: a row written without meta must not break the dashboard.
        return $this->meta ?? [];
    }

    public function setMeta(array $meta): void
    {
        $this->meta = $meta;
    }

    public function getCreatedAt(): \DateTimeInterface
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeInterface $createdAt): void
    {
        $this->createdAt = $createdAt;
    }
}