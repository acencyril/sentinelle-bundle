<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\EventListener\BreachWatchListener;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpHistory;
use Acencyril\SentinelleBundle\Service\Mail;
use Acencyril\SentinelleBundle\Service\SiteEventLogger;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Contracts\Translation\TranslatorInterface;

/** The emails' texts and layout: en and fr, the application's translator first. */
final class MailTest extends TestCase
{
    public function testEveryEnglishTextHasAFrenchOne(): void
    {
        $en = array_filter(require __DIR__.'/../translations/sentinelle.en.php', static fn ($k) => str_starts_with($k, 'mail.'), \ARRAY_FILTER_USE_KEY);
        $fr = array_filter(require __DIR__.'/../translations/sentinelle.fr.php', static fn ($k) => str_starts_with($k, 'mail.'), \ARRAY_FILTER_USE_KEY);
        self::assertSame(array_keys($en), array_keys($fr));
        self::assertNotSame($en, $fr);
    }

    public function testPluralsAndFallback(): void
    {
        $fr = new Mail(null, 'fr');
        self::assertSame('1 adresse bloquée en 24 h', $fr->n('digest.subject.blocked', 1, ['%hours%' => '24']));
        self::assertSame('4 adresses bloquées en 24 h', $fr->n('digest.subject.blocked', 4, ['%hours%' => '24']));
        self::assertSame('Aucune adresse bloquée', $fr->n('digest.blocked', 0));
        self::assertSame('0 alerts in 24 h', (new Mail(null, 'it'))->n('digest.subject.alerts', 0, ['%hours%' => '24']));
        self::assertSame('en', (new Mail(null, 'it'))->locale());
    }

    public function testTheApplicationTranslatorWins(): void
    {
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturnCallback(static fn (string $id) => 'mail.digest.subject.quiet' === $id ? 'tout va bien' : $id);
        self::assertSame('tout va bien', (new Mail($translator, 'fr'))->t('digest.subject.quiet'));
        self::assertSame('Requêtes hostiles', (new Mail($translator, 'fr'))->t('digest.hostile'));
    }

    public function testTheBreachAlarmInFrench(): void
    {
        $sent = [];
        $mailer = $this->createStub(MailerInterface::class);
        $mailer->method('send')->willReturnCallback(static function (Email $e) use (&$sent): void {
            $sent[] = $e;
        });
        $db = $this->createStub(Connection::class);
        $db->method('fetchAllAssociative')->willReturn([['created_at' => '2026-10-24 10:00:00', 'event_type' => 'breach_served', 'url' => '/.env', 'status_code' => 200, 'meta' => '{}']]);
        $item = $this->createStub(CacheItemInterface::class);
        $item->method('isHit')->willReturn(false);
        $item->method('set')->willReturnSelf();
        $item->method('expiresAfter')->willReturnSelf();
        $cache = $this->createStub(CacheItemPoolInterface::class);
        $cache->method('getItem')->willReturn($item);

        $listener = new BreachWatchListener($mailer, $this->createStub(IpBlocklist::class), new IpHistory($db), $this->createStub(SiteEventLogger::class),
            $cache, new NullLogger(), 'me@example.com', 'noreply@example.com', 'Shop', 'prod', null, ['breach'], new Mail(null, 'fr'));
        $request = Request::create('/.env', 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.5']);
        $listener->onKernelTerminate(new TerminateEvent($this->createStub(HttpKernelInterface::class), $request, new Response('APP_SECRET=x')));

        self::assertCount(1, $sent);
        self::assertSame('🔴🔴 FUITE PROBABLE — Shop : GET /.env servi (200) à 203.0.113.5', $sent[0]->getSubject());
        $html = (string) $sent[0]->getHtmlBody();
        foreach (['Un secret est parti dans la réponse : APP_SECRET=…', 'À faire maintenant', 'toutes les clés comme volées', 'Adresse NON bloquée', 'Tout ce que cette adresse a fait en 48 h', '⚠ SERVI'] as $text) {
            self::assertStringContainsString($text, $html);
        }
        self::assertSame('Shop — ALERTE', $sent[0]->getFrom()[0]->getName());
    }
}
