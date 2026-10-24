<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\Service\IpHistory;
use Acencyril\SentinelleBundle\Service\SecurityAlert;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final class SecurityAlertTest extends TestCase
{
    /** @var list<Email> */
    private array $sent = [];

    /** @param list<array<string, mixed>> $rows sentinelle_visit rows */
    private function alert(array $rows, bool $quiet = true): SecurityAlert
    {
        $this->sent = [];
        $mailer = $this->createStub(MailerInterface::class);
        $mailer->method('send')->willReturnCallback(function (Email $e): void {
            $this->sent[] = $e;
        });
        $db = $this->createStub(Connection::class);
        $db->method('fetchAllAssociative')->willReturn($rows);
        $urls = $this->createStub(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturn('https://example.com/admin/activity');

        return new SecurityAlert($mailer, new NullLogger(), $urls, 'me@example.com', 'noreply@example.com', 'Sentinelle', 'Shop', new IpHistory($db), $quiet);
    }

    private static function context(): array
    {
        return ['reason' => 'Automated scan', 'detail' => '15 probes', 'ip' => '203.0.113.5', 'path' => '/.env', 'method' => 'GET', 'query' => null, 'status' => 404, 'user_agent' => 'curl'];
    }

    private static function row(string $type, string $url, ?int $status): array
    {
        return ['created_at' => '2026-10-24 10:00:00', 'event_type' => $type, 'url' => $url, 'status_code' => $status, 'meta' => '{}'];
    }

    public function testABlockedScannerThatGotNothingSendsNoEmail(): void
    {
        $this->alert([self::row('probe', '/.env', 404), self::row('probe', '/wp-login.php', 404)])->notify(self::context(), new BlockedIp('203.0.113.5', 'scan'));
        self::assertCount(0, $this->sent);
    }

    public function testItStillAlertsWhenQuietIsOff(): void
    {
        $this->alert([self::row('probe', '/.env', 404)], false)->notify(self::context(), new BlockedIp('203.0.113.5', 'scan'));
        self::assertCount(1, $this->sent);
        self::assertStringStartsWith('🚨 Security alert Shop', (string) $this->sent[0]->getSubject());
        self::assertStringContainsString('None of its requests to a sensitive address succeeded', (string) $this->sent[0]->getHtmlBody());
    }

    public function testAnAddressNotBlockedAlerts(): void
    {
        $this->alert([self::row('probe', '/.env', 404)])->notify(self::context());
        self::assertCount(1, $this->sent);
        self::assertSame(Email::PRIORITY_HIGH, $this->sent[0]->getPriority());
    }

    public function testASensitiveAnswerServedIsRedEvenWhenBlocked(): void
    {
        $this->alert([self::row('probe', '/.env', 200), self::row('page_view', '/', 200)])->notify(self::context(), new BlockedIp('203.0.113.5', 'scan'));
        self::assertCount(1, $this->sent);
        $mail = $this->sent[0];
        self::assertStringStartsWith('🔴🔴 POSSIBLE BREACH Shop', (string) $mail->getSubject());
        self::assertSame(Email::PRIORITY_HIGHEST, $mail->getPriority());
        self::assertStringContainsString('1 sensitive address(es) answered 2xx', (string) $mail->getHtmlBody());
        self::assertStringContainsString('⚠ SERVED', (string) $mail->getHtmlBody());
    }
}
