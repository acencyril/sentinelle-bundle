<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\DependencyInjection\SentinelleExtension;
use Acencyril\SentinelleBundle\EventListener\SecurityTxtListener;
use Acencyril\SentinelleBundle\Service\SecurityTxt;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class SecurityTxtTest extends TestCase
{
    private static function txt(): SecurityTxt
    {
        return new SecurityTxt(['mailto:security@example.com'], '+11 months', ['fr', 'en'], '/en/security');
    }

    private function handle(string $uri, ?SecurityTxtListener $listener = null, string $method = 'GET'): RequestEvent
    {
        $event = new RequestEvent($this->createStub(HttpKernelInterface::class), Request::create($uri, $method), HttpKernelInterface::MAIN_REQUEST);
        ($listener ?? new SecurityTxtListener(self::txt()))->onKernelRequest($event);

        return $event;
    }

    public function testTheFileFollowsRfc9116(): void
    {
        $body = self::txt()->render('https://example.com', new \DateTimeImmutable('2026-10-27T15:42:00+01:00'));

        self::assertSame(
            "Contact: mailto:security@example.com\n"
            ."Expires: 2027-09-27T00:00:00Z\n"
            ."Preferred-Languages: fr, en\n"
            ."Canonical: https://example.com/.well-known/security.txt\n"
            ."Policy: https://example.com/en/security\n",
            $body,
        );
    }

    public function testExpiresIsAlwaysAheadAndUnderAYear(): void
    {
        $now = new \DateTimeImmutable();
        $at = self::txt()->expiresAt($now);
        self::assertGreaterThan($now, $at);
        self::assertLessThan($now->modify('+1 year'), $at);
    }

    public function testOptionalFieldsAndAbsoluteUrlsAreKept(): void
    {
        $txt = new SecurityTxt(
            ['mailto:a@example.com', 'https://example.com/report'], '+6 months', [], 'https://policy.example.org/',
            ['https://example.com/.well-known/security.txt'], ['/pgp.asc'], '/thanks', 'https://jobs.example.com',
        );
        $body = $txt->render('https://example.com/', new \DateTimeImmutable('2026-01-15T00:00:00Z'));

        self::assertStringContainsString("Contact: mailto:a@example.com\nContact: https://example.com/report\n", $body);
        self::assertStringContainsString("Expires: 2026-07-15T00:00:00Z\n", $body);
        self::assertStringContainsString("Encryption: https://example.com/pgp.asc\n", $body);
        self::assertStringContainsString("Acknowledgments: https://example.com/thanks\n", $body);
        self::assertStringContainsString("Policy: https://policy.example.org/\n", $body);
        self::assertStringContainsString("Hiring: https://jobs.example.com\n", $body);
        self::assertStringNotContainsString('Preferred-Languages', $body);
    }

    public function testItIsServedAsPlainTextBeforeRouting(): void
    {
        $response = $this->handle('https://example.com/.well-known/security.txt')->getResponse();

        self::assertNotNull($response);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('text/plain; charset=utf-8', $response->headers->get('Content-Type'));
        self::assertStringContainsString('Canonical: https://example.com/.well-known/security.txt', (string) $response->getContent());
        self::assertTrue($response->headers->hasCacheControlDirective('public'));
    }

    public function testTheLegacyAddressRedirects(): void
    {
        $response = $this->handle('https://example.com/security.txt')->getResponse();
        self::assertNotNull($response);
        self::assertSame(301, $response->getStatusCode());
        self::assertSame('https://example.com/.well-known/security.txt', $response->headers->get('Location'));

        self::assertNull($this->handle('https://example.com/security.txt', new SecurityTxtListener(self::txt(), false))->getResponse());
    }

    public function testOtherRequestsAreLeftAlone(): void
    {
        self::assertNull($this->handle('https://example.com/')->getResponse());
        self::assertNull($this->handle('https://example.com/.well-known/security.txt', null, 'POST')->getResponse());
    }

    public function testOffUnlessConfigured(): void
    {
        $container = new ContainerBuilder();
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com']]], $container);
        self::assertFalse($container->hasDefinition(SecurityTxtListener::class));
    }

    public function testConfigured(): void
    {
        $container = new ContainerBuilder();
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com'], 'security_txt' => [
            'contact' => 'mailto:security@example.com', 'preferred_languages' => ['fr', 'en'], 'policy' => '/fr/securite',
        ]]], $container);

        self::assertTrue($container->hasDefinition(SecurityTxtListener::class));
        self::assertSame(310, $container->getDefinition(SecurityTxtListener::class)->getTag('kernel.event_listener')[0]['priority']);
        $args = $container->getDefinition(SecurityTxt::class)->getArguments();
        self::assertSame(['mailto:security@example.com'], $args[0]);
        self::assertSame('+11 months', $args[1]);
        self::assertSame('/fr/securite', $args[3]);
    }

    public function testAContactIsRequired(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com'], 'security_txt' => ['enabled' => true]]], new ContainerBuilder());
    }

    public function testAnExpiryOverAYearIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com'], 'security_txt' => [
            'contact' => 'mailto:a@example.com', 'expires' => '+2 years',
        ]]], new ContainerBuilder());
    }
}
