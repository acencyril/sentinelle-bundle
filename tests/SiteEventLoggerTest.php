<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\Service\HumanPass;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\SecurityAlert;
use Acencyril\SentinelleBundle\Service\SiteEventLogger;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class SiteEventLoggerTest extends TestCase
{
    /** @var list<array<string, mixed>> */
    private array $rows = [];

    private function logger(HumanPass $pass): SiteEventLogger
    {
        $db = $this->createStub(Connection::class);
        $db->method('insert')->willReturnCallback(function (string $table, array $row): int {
            $this->rows[] = $row;

            return 1;
        });

        return new SiteEventLogger($db, new ArrayAdapter(), new NullLogger(), $this->createStub(SecurityAlert::class), $this->createStub(IpBlocklist::class), [], 3600, ['/api/webhook/'], [], [], '/admin/activity', $pass);
    }

    public function testAGrantedPassIsLoggedAsHumanPass(): void
    {
        $request = Request::create(HumanPass::PATH, 'POST', [], [], [], ['REMOTE_ADDR' => HumanPassTest::IP]);
        $request->attributes->set(HumanPass::GRANTED_ATTRIBUTE, true);
        $this->logger(HumanPassTest::pass())->logRequest($request, new Response('', 303));
        self::assertSame('human_pass', $this->rows[0]['event_type']);
    }

    public function testAnAttackThroughAPassRevokesIt(): void
    {
        $pass = HumanPassTest::pass();
        $cookie = $pass->passFor(HumanPassTest::IP);
        $request = Request::create('/search?q='.rawurlencode("' UNION SELECT password FROM users"), 'GET', [], [], [], ['REMOTE_ADDR' => HumanPassTest::IP]);
        $request->attributes->set(HumanPass::PASSED_ATTRIBUTE, true);
        $this->logger($pass)->logRequest($request, new Response('', 200));
        self::assertSame('attack_attempt', $this->rows[0]['event_type']);
        self::assertFalse($pass->isValidPass($cookie, HumanPassTest::IP));
    }

    public function testAnOrdinaryPageThroughAPassKeepsIt(): void
    {
        $pass = HumanPassTest::pass();
        $cookie = $pass->passFor(HumanPassTest::IP);
        $request = Request::create('/products', 'GET', [], [], [], ['REMOTE_ADDR' => HumanPassTest::IP]);
        $request->attributes->set(HumanPass::PASSED_ATTRIBUTE, true);
        $this->logger($pass)->logRequest($request, new Response('', 200));
        self::assertSame('page_view', $this->rows[0]['event_type']);
        self::assertTrue($pass->isValidPass($cookie, HumanPassTest::IP));
    }

    public function testTheDashboardLabelForBlockedAddressesFollowsTheTextColour(): void
    {
        $twig = (string) file_get_contents(\dirname(__DIR__).'/templates/activity.html.twig');
        self::assertStringNotContainsString('#1f2937', $twig);
        self::assertStringContainsString("'ip_blocked': 'neutral'", $twig);
        self::assertStringContainsString('.sentinelle .is-neutral { --_tone: var(--_ink); }', $twig);
    }
}
