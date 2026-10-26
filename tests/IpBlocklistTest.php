<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\DependencyInjection\Configuration;
use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\Repository\BlockedIpRepository;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpIdentifier;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;

final class IpBlocklistTest extends TestCase
{
    private ?BlockedIp $stored = null;

    /** @param string[]|null $durations */
    private function blocklist(?array $durations = null): IpBlocklist
    {
        $repo = $this->createStub(BlockedIpRepository::class);
        $repo->method('findOneByIp')->willReturnCallback(fn (): ?BlockedIp => $this->stored);
        $em = $this->createStub(EntityManagerInterface::class);
        $em->method('persist')->willReturnCallback(function (object $e): void {
            $this->stored = $e;
        });
        // No reverse DNS in tests.
        $identifier = $this->createStub(IpIdentifier::class);
        $identifier->method('identify')->willReturn(['critical' => false, 'label' => null, 'hostname' => null]);
        $args = [$repo, $em, new ArrayAdapter(), new NullLogger(), $identifier, null, false];

        return null === $durations ? new IpBlocklist(...$args) : new IpBlocklist(...[...$args, $durations]);
    }

    /** Blocks once, then lets the block expire, so the next one is a new strike. */
    private function strike(IpBlocklist $list, string $source = BlockedIp::SOURCE_AUTO): BlockedIp
    {
        $entry = $list->block('203.0.113.9', 'scan', $source);
        self::assertNotNull($entry);
        $snapshot = clone $entry;
        $entry->setExpiresAt(new \DateTimeImmutable('-1 second'));

        return $snapshot;
    }

    private static function assertExpiresIn(string $interval, BlockedIp $entry): void
    {
        self::assertNotNull($entry->getExpiresAt());
        self::assertEqualsWithDelta((new \DateTimeImmutable($interval))->getTimestamp(), $entry->getExpiresAt()->getTimestamp(), 5);
    }

    public function testDefaultIs24HoursThen7DaysThenPermanent(): void
    {
        $list = $this->blocklist();
        self::assertExpiresIn('+24 hours', $this->strike($list));
        self::assertExpiresIn('+7 days', $this->strike($list));
        $third = $this->strike($list);
        self::assertSame(3, $third->getStrikes());
        self::assertTrue($third->isPermanent());
        self::assertTrue($this->strike($list)->isPermanent());
    }

    public function testDurationsAreConfigurableAndTheLastOneRepeats(): void
    {
        $list = $this->blocklist(['1 hour', '+2 days']);
        self::assertExpiresIn('+1 hour', $this->strike($list));
        self::assertExpiresIn('+2 days', $this->strike($list));
        self::assertExpiresIn('+2 days', $this->strike($list));
        self::assertExpiresIn('+2 days', $this->strike($list));
    }

    public function testAutomaticBlocksNeverBecomePermanentWithoutPermanentInTheList(): void
    {
        $list = $this->blocklist(['+24 hours', '+7 days']);
        for ($i = 0; $i < 6; ++$i) {
            self::assertFalse($this->strike($list)->isPermanent());
        }
    }

    public function testAManualBlockIsPermanentUnlessGivenADuration(): void
    {
        $list = $this->blocklist(['+1 hour']);
        self::assertTrue($this->strike($list, BlockedIp::SOURCE_MANUAL)->isPermanent());
        $timed = $list->block('203.0.113.10', 'by hand', BlockedIp::SOURCE_MANUAL, '+3 days');
        self::assertExpiresIn('+3 days', $timed);
    }

    public function testDurationsAreNormalised(): void
    {
        self::assertSame('+24 hours', IpBlocklist::normaliseDuration('24 hours'));
        self::assertSame('+7 days', IpBlocklist::normaliseDuration(' +7 days '));
        self::assertSame('permanent', IpBlocklist::normaliseDuration('Permanent'));
        foreach (['', '-1 day', 'now', 'yesterday', 'nonsense'] as $bad) {
            self::assertNull(IpBlocklist::normaliseDuration($bad), $bad);
        }
    }

    public function testConfigurationDefaultsAndValidation(): void
    {
        $base = ['alert' => ['recipient' => 'me@example.com']];
        $config = (new Processor())->processConfiguration(new Configuration(), [$base]);
        self::assertSame(['+24 hours', '+7 days', 'permanent'], $config['blocking']['durations']);
        self::assertTrue($config['blocking']['human_pass']);

        $this->expectException(InvalidConfigurationException::class);
        (new Processor())->processConfiguration(new Configuration(), [$base + ['blocking' => ['durations' => ['+1 day', '-2 days']]]]);
    }
}
