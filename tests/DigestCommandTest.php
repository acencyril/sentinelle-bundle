<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\Command\DigestCommand;
use Acencyril\SentinelleBundle\Service\Mail;
use Acencyril\SentinelleBundle\Service\SecurityAlert;
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

    private function digest(array $options = [], string $locale = 'en'): CommandTester
    {
        $mailer = $this->createStub(MailerInterface::class);
        $mailer->method('send')->willReturnCallback(function (Email $e): void {
            $this->sent[] = $e;
        });
        $tester = new CommandTester(new DigestCommand($this->db, $mailer, 'me@example.com', 'noreply@example.com', 'Shop', SecurityAlert::IMMEDIATE_DEFAULT, new Mail(null, $locale)));
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
        $this->block('192.0.2.8', 'Manual: spam', null);

        $this->digest();
        self::assertCount(1, $this->sent);
        $mail = $this->sent[0];
        self::assertSame('Sentinelle Shop — 3 addresses blocked in 24 h', $mail->getSubject());
        $html = (string) $mail->getHtmlBody();
        self::assertMatchesRegularExpression('#Automated scan</td><td[^>]*>2</td>#', $html);
        self::assertMatchesRegularExpression('#Exploitation attempt</td><td[^>]*>1</td>#', $html);
        self::assertMatchesRegularExpression('#Probes recorded</td><td[^>]*>4</td>#', $html);
        self::assertMatchesRegularExpression('#Automated scan</td><td[^>]*>1</td></tr>#', $html, 'blocks grouped by reason, without the detail');
        // Top addresses: the scanner first, still blocked; the expired block reads "not blocked".
        self::assertMatchesRegularExpression('#203\.0\.113\.5</span></td><td[^>]*>5</td><td[^>]*><span[^>]*>blocked</span></td>.*192\.0\.2\.7</span></td><td[^>]*>1</td><td[^>]*><span[^>]*>not blocked#s', $html);
        self::assertStringNotContainsString('Sensitive answers served<', $html);
        self::assertMatchesRegularExpression('#Exploitation attempt</td><td[^>]*>1</td><td[^>]*><span[^>]*>here only#', $html);
        self::assertMatchesRegularExpression('#Manual: spam</td><td[^>]*>1</td>#', $html, 'a reason of its own is kept as written');
    }

    public function testABreachIsListedInRed(): void
    {
        $this->visit('breach_served', '203.0.113.5', ['status' => 200], '-2 hours', '/.git/config');
        $this->digest();
        self::assertCount(1, $this->sent);
        self::assertSame('🔴 Sentinelle Shop — probable breach in 24 h', $this->sent[0]->getSubject());
        self::assertStringContainsString('/.git/config', (string) $this->sent[0]->getHtmlBody());
    }

    public function testDryRunSendsNothing(): void
    {
        $this->visit('alert', '203.0.113.6', ['kind' => 'scan']);
        $display = $this->digest(['--dry-run' => true])->getDisplay();
        self::assertStringContainsString('alert scan: 1 (0 emailed)', $display);
        self::assertCount(0, $this->sent);
    }

    private function frenchDay(): void
    {
        foreach (range(1, 4) as $i) {
            $this->visit('scan_probe', '203.0.113.5');
        }
        $this->visit('attack_attempt', '192.0.2.7');
        $this->visit('alert', '203.0.113.5', ['kind' => 'scan', 'emailed' => false]);
        $this->visit('alert', '192.0.2.7', ['kind' => 'exploitation', 'emailed' => false]);
        foreach (['203.0.113.5', '203.0.113.6', '203.0.113.7'] as $ip) {
            $this->block($ip, 'Automated scan — 15 probes in under 10 minutes');
        }
        $this->block('192.0.2.7', 'Exploitation attempt — Pattern matched: sql_injection');
    }

    public function testInFrench(): void
    {
        $this->frenchDay();
        $this->digest([], 'fr');
        $mail = $this->sent[0];
        self::assertSame('Sentinelle Shop — 4 adresses bloquées en 24 h', $mail->getSubject());
        $html = (string) $mail->getHtmlBody();
        foreach (['Alertes des dernières 24 h', 'Requêtes hostiles', 'Fuite probable (fichier sensible servi)', 'Tentative d’exploitation', 'Force brute probable', 'Sondages enregistrés', '4 adresses bloquées automatiquement', 'Adresses les plus actives', 'envoyée tout de suite', 'ici seulement', '<html lang="fr">'] as $text) {
            self::assertStringContainsString($text, $html);
        }
        self::assertMatchesRegularExpression('#Scan automatisé</td><td[^>]*>3</td></tr>#', $html, 'block reasons in French too');
        self::assertMatchesRegularExpression('#203\.0\.113\.5</span></td><td[^>]*>4</td><td[^>]*><span[^>]*>bloquée#', $html);
        self::assertStringNotContainsString('Hostile', $html);
    }

    public function testFrenchSubjects(): void
    {
        $this->visit('alert', '203.0.113.6', ['kind' => 'scan']);
        $this->digest([], 'fr');
        self::assertSame('Sentinelle Shop — 1 alerte en 24 h', $this->sent[0]->getSubject());
        self::assertStringContainsString('Aucune adresse bloquée', (string) $this->sent[0]->getHtmlBody());

        $this->sent = [];
        $this->db->executeStatement('DELETE FROM sentinelle_visit');
        $this->visit('attack_attempt', '192.0.2.7');
        $this->digest([], 'fr');
        self::assertSame('Sentinelle Shop — rien à signaler', $this->sent[0]->getSubject());

        $this->sent = [];
        $this->block('203.0.113.9', 'Automated scan');
        $this->digest([], 'fr');
        self::assertSame('Sentinelle Shop — 1 adresse bloquée en 24 h', $this->sent[0]->getSubject());
    }

    public function testAnUnknownLocaleFallsBackToEnglish(): void
    {
        $this->frenchDay();
        $this->digest([], 'de');
        self::assertSame('Sentinelle Shop — 4 addresses blocked in 24 h', $this->sent[0]->getSubject());
    }
}
