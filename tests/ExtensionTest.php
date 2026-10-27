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

    public function testOnlyABreachIsImmediateByDefault(): void
    {
        $container = self::load([]);
        self::assertSame(['breach'], $container->getParameter('sentinelle.alert.immediate'));
        self::assertSame('%sentinelle.alert.immediate%', $container->getDefinition(\Acencyril\SentinelleBundle\Service\SecurityAlert::class)->getArgument(9));
        self::assertSame('%sentinelle.alert.immediate%', $container->getDefinition(\Acencyril\SentinelleBundle\EventListener\BreachWatchListener::class)->getArgument(11));
        self::assertSame('%sentinelle.alert.immediate%', $container->getDefinition(\Acencyril\SentinelleBundle\Command\DigestCommand::class)->getArgument(5));
    }

    public function testAllRestoresAnEmailPerAlert(): void
    {
        $container = new ContainerBuilder();
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com', 'immediate' => 'all']]], $container);
        self::assertSame(['breach', 'exploitation', 'brute_force', 'scan'], $container->getParameter('sentinelle.alert.immediate'));
    }

    public function testAnUnknownKindIsRefused(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com', 'immediate' => ['breach', 'login']]]], new ContainerBuilder());
    }

    public function testTheEmailsFollowTheAppLocaleUnlessSet(): void
    {
        self::assertSame('%kernel.default_locale%', self::load([])->getParameter('sentinelle.mail.locale'));
        $container = self::load(['mail' => ['locale' => 'fr']]);
        self::assertSame('fr', $container->getParameter('sentinelle.mail.locale'));
        self::assertSame('%sentinelle.mail.locale%', $container->getDefinition(\Acencyril\SentinelleBundle\Service\Mail::class)->getArgument(1));
        foreach ([\Acencyril\SentinelleBundle\Service\SecurityAlert::class => 10, \Acencyril\SentinelleBundle\EventListener\BreachWatchListener::class => 12, \Acencyril\SentinelleBundle\Command\DigestCommand::class => 6] as $class => $i) {
            self::assertSame(\Acencyril\SentinelleBundle\Service\Mail::class, (string) $container->getDefinition($class)->getArgument($i));
        }
    }
}
