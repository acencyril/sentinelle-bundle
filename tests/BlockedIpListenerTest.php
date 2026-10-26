<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\EventListener\BlockedIpListener;
use Acencyril\SentinelleBundle\Service\HumanPass;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

final class BlockedIpListenerTest extends TestCase
{
    private const IP = HumanPassTest::IP;

    private HumanPass $pass;
    /** @var list<string> */
    public array $logs = [];

    protected function setUp(): void
    {
        $this->pass = HumanPassTest::pass(8);
        BlockedIpListener::resetProxyCheck();
    }

    private function listener(bool $humanPass = true): BlockedIpListener
    {
        $blocklist = $this->createStub(IpBlocklist::class);
        $blocklist->method('isBlocked')->willReturnCallback(static fn (string $ip): bool => self::IP === $ip);
        $loader = new FilesystemLoader();
        $loader->addPath(\dirname(__DIR__).'/templates', 'Sentinelle');
        $test = $this;
        $logger = new class($test) extends AbstractLogger {
            public function __construct(private BlockedIpListenerTest $test) {}

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->test->logs[] = $level.': '.$message;
            }
        };

        return new BlockedIpListener($blocklist, $humanPass ? $this->pass : null, new Environment($loader, ['strict_variables' => true]), null, $logger);
    }

    /** @param array<string, string> $server */
    private function handle(Request $request, ?BlockedIpListener $listener = null): RequestEvent
    {
        $event = new RequestEvent($this->createStub(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
        ($listener ?? $this->listener())->onKernelRequest($event);

        return $event;
    }

    private static function page(string $path = '/products', string $ip = self::IP, string $accept = 'text/html,application/xhtml+xml', string $lang = 'en'): Request
    {
        return Request::create($path, 'GET', [], [], [], ['REMOTE_ADDR' => $ip, 'HTTP_ACCEPT' => $accept, 'HTTP_ACCEPT_LANGUAGE' => $lang]);
    }

    private static function challengeIn(Response $response): string
    {
        self::assertSame(1, preg_match('/name="challenge" value="([^"]+)"/', (string) $response->getContent(), $m));

        return $m[1];
    }

    private function cookieFromSolving(): string
    {
        $challenge = self::challengeIn($this->handle(self::page())->getResponse());
        $post = Request::create(HumanPass::PATH, 'POST', [
            'challenge' => $challenge,
            'solution' => HumanPassTest::solve($challenge, 8),
            'return' => '/products?page=2',
        ], [], [], ['REMOTE_ADDR' => self::IP]);
        $event = $this->handle($post);
        $response = $event->getResponse();
        self::assertSame(303, $response->getStatusCode());
        self::assertSame('/products?page=2', $response->headers->get('Location'));
        self::assertTrue($post->attributes->getBoolean(HumanPass::GRANTED_ATTRIBUTE));
        self::assertFalse($post->attributes->getBoolean(BlockedIpListener::REQUEST_ATTRIBUTE));
        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies);
        $cookie = $cookies[0];
        self::assertSame(HumanPass::COOKIE, $cookie->getName());
        self::assertTrue($cookie->isHttpOnly());
        self::assertSame('lax', $cookie->getSameSite());
        self::assertEqualsWithDelta(time() + 86400, $cookie->getExpiresTime(), 5);

        return (string) $cookie->getValue();
    }

    public function testAnUnblockedAddressIsLeftAlone(): void
    {
        self::assertNull($this->handle(self::page(ip: '198.51.100.20'))->getResponse());
    }

    public function testABrowserGetsTheChallengePage(): void
    {
        $response = $this->handle(self::page())->getResponse();
        self::assertSame(403, $response->getStatusCode());
        self::assertStringStartsWith('text/html', (string) $response->headers->get('Content-Type'));
        $html = (string) $response->getContent();
        self::assertStringContainsString('Your network was blocked after suspicious requests', $html);
        self::assertStringContainsString('action="'.HumanPass::PATH.'"', $html);
        self::assertStringContainsString('name="return" value="/products"', $html);
        self::assertStringNotContainsString('src="http', $html, 'no external request');
        self::assertStringContainsString("script-src 'nonce-", (string) $response->headers->get('Content-Security-Policy'));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    public function testThePageIsInFrenchForAFrenchBrowser(): void
    {
        $html = (string) $this->handle(self::page(lang: 'fr-FR,fr;q=0.9'))->getResponse()->getContent();
        self::assertStringContainsString('Votre réseau a été bloqué après des requêtes suspectes', $html);
        self::assertStringContainsString('<html lang="fr">', $html);
    }

    public function testScriptsAndSensitivePathsGetABare403(): void
    {
        foreach ([self::page(accept: 'application/json'), self::page('/.env'), self::page('/.git/config'), Request::create('/products', 'POST', [], [], [], ['REMOTE_ADDR' => self::IP, 'HTTP_ACCEPT' => 'text/html'])] as $request) {
            $response = $this->handle($request)->getResponse();
            self::assertSame(403, $response->getStatusCode());
            self::assertSame('Forbidden', $response->getContent(), $request->getPathInfo());
            self::assertTrue($request->attributes->getBoolean(BlockedIpListener::REQUEST_ATTRIBUTE));
        }
    }

    public function testWithTheChallengeOffTheRefusalStaysBare(): void
    {
        $response = $this->handle(self::page(), $this->listener(false))->getResponse();
        self::assertSame('Forbidden', $response->getContent());
    }

    public function testAValidProofOfWorkSetsACookieThatLetsTheBrowserThrough(): void
    {
        $cookie = $this->cookieFromSolving();

        foreach (['/products', '/account/orders'] as $path) {
            $request = self::page($path);
            $request->cookies->set(HumanPass::COOKIE, $cookie);
            self::assertNull($this->handle($request)->getResponse(), $path);
            self::assertTrue($request->attributes->getBoolean(HumanPass::PASSED_ATTRIBUTE));
        }
        // A form posted from that browser goes through too.
        $post = Request::create('/contact', 'POST', [], [HumanPass::COOKIE => $cookie], [], ['REMOTE_ADDR' => self::IP]);
        self::assertNull($this->handle($post)->getResponse());
    }

    public function testAPassNeverOpensASensitivePath(): void
    {
        $cookie = $this->cookieFromSolving();
        foreach (['/.env', '/.git/config', '/backup.sql', '/vendor/autoload.php'] as $path) {
            $request = self::page($path);
            $request->cookies->set(HumanPass::COOKIE, $cookie);
            $response = $this->handle($request)->getResponse();
            self::assertNotNull($response, $path);
            self::assertSame(403, $response->getStatusCode());
            self::assertSame('Forbidden', $response->getContent());
        }
    }

    public function testATamperedOrForeignCookieIsRefused(): void
    {
        $cookie = $this->cookieFromSolving();
        [$expires, $sig] = explode('.', $cookie);
        $foreign = $this->pass->passFor('198.51.100.30');
        foreach ([($expires + 3600).'.'.$sig, $expires.'.'.strrev($sig), $foreign, 'x'] as $bad) {
            $request = self::page();
            $request->cookies->set(HumanPass::COOKIE, $bad);
            self::assertSame(403, $this->handle($request)->getResponse()->getStatusCode(), $bad);
        }
    }

    public function testAWrongSolutionShowsThePageAgain(): void
    {
        $challenge = self::challengeIn($this->handle(self::page())->getResponse());
        $n = (int) HumanPassTest::solve($challenge, 8);
        do {
            ++$n;
        } while (HumanPass::hasLeadingZeroBits(hash('sha256', $challenge.$n, true), 8));
        $post = Request::create(HumanPass::PATH, 'POST', ['challenge' => $challenge, 'solution' => (string) $n, 'return' => '//evil.example'], [], [], ['REMOTE_ADDR' => self::IP]);
        $response = $this->handle($post)->getResponse();
        self::assertSame(403, $response->getStatusCode());
        self::assertSame([], $response->headers->getCookies());
        self::assertStringContainsString('That did not work', (string) $response->getContent());
        self::assertStringContainsString('name="return" value="/"', (string) $response->getContent(), 'no open redirect');
    }

    public function testAttemptsAreRateLimited(): void
    {
        for ($i = 0; $i < 10; ++$i) {
            $this->handle(Request::create(HumanPass::PATH, 'POST', ['challenge' => 'x', 'solution' => '1'], [], [], ['REMOTE_ADDR' => self::IP]));
        }
        $response = $this->handle(Request::create(HumanPass::PATH, 'POST', ['challenge' => 'x', 'solution' => '1'], [], [], ['REMOTE_ADDR' => self::IP]))->getResponse();
        self::assertSame(429, $response->getStatusCode());
        self::assertStringNotContainsString('name="challenge"', (string) $response->getContent());
    }

    public function testARevokedAddressIsNotOfferedTheChallenge(): void
    {
        $cookie = $this->cookieFromSolving();
        $this->pass->revoke(self::IP);
        $request = self::page();
        $request->cookies->set(HumanPass::COOKIE, $cookie);
        self::assertSame('Forbidden', $this->handle($request)->getResponse()->getContent());
    }

    public function testItWarnsOnceWhenAProxyIsNotTrusted(): void
    {
        $listener = $this->listener();
        $server = ['REMOTE_ADDR' => '172.18.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.50'];
        $this->handle(Request::create('/', 'GET', [], [], [], $server), $listener);
        $this->handle(Request::create('/', 'GET', [], [], [], $server), $listener);
        $warnings = array_filter($this->logs, static fn (string $l): bool => str_contains($l, 'no trusted proxies'));
        self::assertCount(1, $warnings);
    }

    public function testNoWarningWhenTheProxyIsTrusted(): void
    {
        Request::setTrustedProxies(['172.16.0.0/12'], Request::HEADER_X_FORWARDED_FOR);
        try {
            $this->handle(Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '172.18.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.50']));
        } finally {
            Request::setTrustedProxies([], -1);
        }
        self::assertSame([], $this->logs);
    }
}
