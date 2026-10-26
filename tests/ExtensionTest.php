<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\DependencyInjection\SentinelleExtension;
use Acencyril\SentinelleBundle\Service\HumanPass;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final class ExtensionTest extends TestCase
{
    private static function load(array $config): ContainerBuilder
    {
        $container = new ContainerBuilder();
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com']] + $config], $container);

        return $container;
    }

    public function testTheHumanPassIsOnByDefaultAndSignedWithTheKernelSecret(): void
    {
        $container = self::load([]);
        self::assertTrue($container->hasDefinition(HumanPass::class));
        self::assertSame('%kernel.secret%', $container->getDefinition(HumanPass::class)->getArgument(0));
        self::assertSame(['+24 hours', '+7 days', 'permanent'], $container->getParameter('sentinelle.blocking.durations'));
        self::assertSame('%sentinelle.blocking.durations%', $container->getDefinition(IpBlocklist::class)->getArgument(7));
    }

    public function testTheHumanPassCanBeTurnedOff(): void
    {
        $container = self::load(['blocking' => ['human_pass' => false, 'durations' => ['+1 day']]]);
        self::assertFalse($container->hasDefinition(HumanPass::class));
        self::assertSame(['+1 day'], $container->getParameter('sentinelle.blocking.durations'));
    }
}
