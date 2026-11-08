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
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

/** A page shown to the administrator may quote a secret on purpose; a sensitive file never may. */
final class BreachWatchListenerTest extends TestCase
{
    public function testASecretOnAnAdminPageIsNotABreach(): void
    {
        self::assertSame(0, $this->alarms('/admin/drafts', 'Example: DATABASE_URL=evil://', admin: true));
    }

    public function testASensitiveFileIsABreachEvenForTheAdmin(): void
    {
        self::assertSame(1, $this->alarms('/.env', 'APP_SECRET=x', admin: true));
    }

    public function testASecretServedToAnyoneElseIsABreach(): void
    {
        self::assertSame(1, $this->alarms('/admin/drafts', 'Example: DATABASE_URL=evil://', admin: false));
        self::assertSame(1, $this->alarms('/page', 'DATABASE_URL=mysql://u:p@db/x', admin: null));
    }

    public function testAnUnreadableSessionCountsAsNotAdmin(): void
    {
        $checker = $this->createStub(AuthorizationCheckerInterface::class);
        $checker->method('isGranted')->willThrowException(new \RuntimeException('no token'));
        self::assertSame(1, $this->alarms('/page', 'DATABASE_URL=mysql://u:p@db/x', checker: $checker));
    }

    /** @return int the number of breach emails sent */
    private function alarms(string $path, string $body, ?bool $admin = null, ?AuthorizationCheckerInterface $checker = null): int
    {
        $sent = 0;
        $mailer = $this->createStub(MailerInterface::class);
        $mailer->method('send')->willReturnCallback(static function () use (&$sent): void {
            ++$sent;
        });
        $db = $this->createStub(Connection::class);
        $db->method('fetchAllAssociative')->willReturn([]);
        $item = $this->createStub(CacheItemInterface::class);
        $item->method('isHit')->willReturn(false);
        $item->method('set')->willReturnSelf();
        $item->method('expiresAfter')->willReturnSelf();
        $cache = $this->createStub(CacheItemPoolInterface::class);
        $cache->method('getItem')->willReturn($item);
        if (null === $checker && null !== $admin) {
            $checker = $this->createStub(AuthorizationCheckerInterface::class);
            $checker->method('isGranted')->willReturnCallback(static fn (mixed $role): bool => $admin && 'ROLE_ADMIN' === $role);
        }

        $listener = new BreachWatchListener($mailer, $this->createStub(IpBlocklist::class), new IpHistory($db), $this->createStub(SiteEventLogger::class),
            $cache, new NullLogger(), 'me@example.com', 'noreply@example.com', 'Shop', 'prod', null, ['breach'], new Mail(), $checker, 'ROLE_ADMIN');
        $request = Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => '203.0.113.5']);
        $listener->onKernelTerminate(new TerminateEvent($this->createStub(HttpKernelInterface::class), $request, new Response($body)));

        return $sent;
    }
}
