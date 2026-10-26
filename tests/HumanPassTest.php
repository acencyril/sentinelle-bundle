<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\Service\HumanPass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class HumanPassTest extends TestCase
{
    public const IP = '203.0.113.7';

    public static function pass(int $difficulty = 8): HumanPass
    {
        return new HumanPass('test-secret', new ArrayAdapter(), difficulty: $difficulty);
    }

    /** What the browser does: the first counter whose hash starts with enough zero bits. */
    public static function solve(string $challenge, int $bits): string
    {
        for ($n = 0;; ++$n) {
            if (HumanPass::hasLeadingZeroBits(hash('sha256', $challenge.$n, true), $bits)) {
                return (string) $n;
            }
        }
    }

    public function testASolvedChallengeIsAcceptedOnce(): void
    {
        $pass = self::pass();
        $challenge = $pass->challenge(self::IP);
        $solution = self::solve($challenge, 8);
        self::assertTrue($pass->verify(self::IP, $challenge, $solution));
        self::assertFalse($pass->verify(self::IP, $challenge, $solution), 'replayed');
    }

    public function testAChallengeIsBoundToItsAddressAndItsSignature(): void
    {
        $pass = self::pass();
        $challenge = $pass->challenge(self::IP);
        $solution = self::solve($challenge, 8);
        self::assertFalse($pass->verify('198.51.100.1', $challenge, $solution));
        $forged = preg_replace('/^\d+/', (string) (time() + 30), $challenge);
        self::assertFalse($pass->verify(self::IP, $forged, self::solve($forged, 8)));
        self::assertFalse(self::pass()->verify(self::IP, 'not.a.challenge', '1'));
    }

    public function testAWrongOrLateSolutionIsRefused(): void
    {
        $pass = self::pass(16);
        $challenge = $pass->challenge(self::IP);
        $solution = self::solve($challenge, 16);
        $wrong = (string) ((int) $solution + 1);
        if (!HumanPass::hasLeadingZeroBits(hash('sha256', $challenge.$wrong, true), 16)) {
            self::assertFalse($pass->verify(self::IP, $challenge, $wrong));
        }
        $old = $pass->challenge(self::IP, time() - 3600);
        self::assertFalse($pass->verify(self::IP, $old, self::solve($old, 16)));
    }

    public function testThePassCookieIsSignedBoundToTheAddressAndExpires(): void
    {
        $pass = self::pass();
        $cookie = $pass->passFor(self::IP);
        self::assertTrue($pass->isValidPass($cookie, self::IP));
        self::assertFalse($pass->isValidPass($cookie, '203.0.113.8'), 'other address');
        self::assertFalse($pass->isValidPass(substr($cookie, 0, -1).'A' === $cookie ? substr($cookie, 0, -1).'B' : substr($cookie, 0, -1).'A', self::IP), 'tampered');
        [$expires, $sig] = explode('.', $cookie);
        self::assertFalse($pass->isValidPass(($expires + 86400).'.'.$sig, self::IP), 'extended');
        self::assertFalse($pass->isValidPass($cookie, self::IP, time() + 86401), 'expired');
        self::assertFalse((new HumanPass('other-secret', new ArrayAdapter()))->isValidPass($cookie, self::IP), 'other secret');
        self::assertFalse($pass->isValidPass(null, self::IP));
        self::assertFalse($pass->isValidPass('garbage', self::IP));
    }

    public function testARevokedAddressLosesItsPasses(): void
    {
        $pass = self::pass();
        $cookie = $pass->passFor(self::IP);
        $pass->revoke(self::IP);
        self::assertTrue($pass->isRevoked(self::IP));
        self::assertFalse($pass->isValidPass($cookie, self::IP));
    }

    public function testAttemptsAreRateLimited(): void
    {
        $pass = new HumanPass('test-secret', new ArrayAdapter(), maxAttempts: 3);
        self::assertTrue($pass->allowAttempt(self::IP));
        self::assertTrue($pass->allowAttempt(self::IP));
        self::assertTrue($pass->allowAttempt(self::IP));
        self::assertFalse($pass->allowAttempt(self::IP));
        self::assertTrue($pass->allowAttempt('203.0.113.8'));
    }

    public function testLeadingZeroBits(): void
    {
        self::assertTrue(HumanPass::hasLeadingZeroBits("\x00\x00\x7f", 17));
        self::assertFalse(HumanPass::hasLeadingZeroBits("\x00\x00\x80", 17));
        self::assertTrue(HumanPass::hasLeadingZeroBits("\x0f", 4));
        self::assertFalse(HumanPass::hasLeadingZeroBits("\x10", 4));
    }

    public function testAnEmptySecretIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new HumanPass('', new ArrayAdapter());
    }
}
