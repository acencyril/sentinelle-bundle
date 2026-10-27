<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\Command\DigestCommand;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

/** The daily digest: where every alert not emailed at once ends up. */
final class DigestCommandTest extends TestCase
{
    private Connection $db;
    /** @var list<Email> */
    private array $sent = [];

    protected function setUp(): void
    {
        $this->db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $this->db->executeStatement('CREATE TABLE sentinelle_visit (id INTEGER PRIMARY KEY, event_type VARCHAR(255), url VARCHAR(255), status_code INT, ip VARCHAR(45), user_agent VARCHAR(255), meta TEXT, created_at DATETIME)');
        $this->db->executeStatement('CREATE TABLE sentinelle_blocked_ip (id INTEGER PRIMARY KEY, ip VARCHAR(45), reason VARCHAR(255), source VARCHAR(10), strikes INT, expires_at DATETIME, created_at DATETIME, last_hit_at DATETIME, hit_count INT)');
    }

    private function visit(string $type, string $ip, array $meta = [], string $when = '-1 hour', string $url = '/.env'): void
    {
        $this->db->insert('sentinelle_visit', ['event_type' => $type, 'url' => $url, 'ip' => $ip, 'meta' => json_encode($meta), 'created_at' => (new \DateTimeImmutable($when))->format('Y-m-d H:i:s')]);
    }

    private function block(string $ip, string $reason, ?string $expires = '+1 day'): void
    {
        $this->db->insert('sentinelle_blocked_ip', ['ip' => $ip, 'reason' => $reason, 'source' => 'auto', 'strikes' => 1, 'hit_count' => 0,
            'expires_at' => $expires ? (new \DateTimeImmutable($expires))->format('Y-m-d H:i:s') : null,
            'created_at' => (new \DateTimeImmutable('-1 hour'))->format('Y-m-d H:i:s')]);
    }

    private function digest(array $options = []): CommandTester
    {
        $mailer = $this->createStub(MailerInterface::class);
        $mailer->method('send')->willReturnCallback(function (Email $e): void {
            $this->sent[] = $e;
        });
        $tester = new CommandTester(new DigestCommand($this->db, $mailer, 'me@example.com', 'noreply@example.com', 'Shop'));
        $tester->execute($options);

        return $tester;
    }

    public function testNothingHappenedSendsNothing(): void
    {
        $this->visit('page_view', '198.51.100.1');
        $this->visit('scan_probe', '203.0.113.9');
        $this->visit('alert', '203.0.113.9', ['kind' => 'scan'], '-3 days');
        self::assertStringContainsString('Nothing to report', $this->digest()->getDisplay());
        self::assertCount(0, $this->sent);
    }

    public function testItCountsTheAlertsByKindAndNamesTheBusiestAddresses(): void
    {
        foreach (range(1, 4) as $i) {
            $this->visit('scan_probe', '203.0.113.5');
        }
        $this->visit('ip_blocked', '203.0.113.5');
        $this->visit('attack_attempt', '192.0.2.7');
        $this->visit('alert', '203.0.113.5', ['kind' => 'scan', 'emailed' => false, 'blocked' => true]);
        $this->visit('alert', '203.0.113.6', ['kind' => 'scan', 'emailed' => false]);
        $this->visit('alert', '192.0.2.7', ['kind' => 'exploitation', 'emailed' => false]);
        $this->block('203.0.113.5', 'Automated scan — 15 probes in under 10 minutes');
        $this->block('192.0.2.7', 'Exploitation attempt — Pattern matched: sql_injection', '-1 minute');

        $this->digest();
        self::assertCount(1, $this->sent);
        $mail = $this->sent[0];
        self::assertSame('🛡 Sentinelle Shop — 3 alert(s), 2 blocked in 24 h', $mail->getSubject());
        $html = (string) $mail->getHtmlBody();
        self::assertMatchesRegularExpression('#Automated scan</td><td[^>]*>2</td>#', $html);
        self::assertMatchesRegularExpression('#Exploitation attempt</td><td[^>]*>1</td>#', $html);
        self::assertMatchesRegularExpression('#Probes recorded</td><td[^>]*>4</td>#', $html);
        self::assertMatchesRegularExpression('#Automated scan</td><td[^>]*>1</td></tr>#', $html, 'blocks grouped by reason, without the detail');
        // Top addresses: the scanner first, still blocked; the expired block reads "not blocked".
        self::assertMatchesRegularExpression('#203\.0\.113\.5</td><td[^>]*>5</td><td[^>]*>blocked</td>.*192\.0\.2\.7</td><td[^>]*>1</td><td[^>]*>not blocked#s', $html);
        self::assertStringNotContainsString('Sensitive answers served:', $html);
    }

    public function testABreachIsListedInRed(): void
    {
        $this->visit('breach_served', '203.0.113.5', ['status' => 200], '-2 hours', '/.git/config');
        $this->digest();
        self::assertCount(1, $this->sent);
        self::assertStringStartsWith('🔴 Sentinelle Shop', (string) $this->sent[0]->getSubject());
        self::assertStringContainsString('/.git/config', (string) $this->sent[0]->getHtmlBody());
    }

    public function testDryRunSendsNothing(): void
    {
        $this->visit('alert', '203.0.113.6', ['kind' => 'scan']);
        $display = $this->digest(['--dry-run' => true])->getDisplay();
        self::assertStringContainsString('alert scan: 1 (0 emailed)', $display);
        self::assertCount(0, $this->sent);
    }
}
