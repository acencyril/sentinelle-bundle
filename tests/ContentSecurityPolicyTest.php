<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\DependencyInjection\SentinelleExtension;
use Acencyril\SentinelleBundle\EventListener\ContentSecurityPolicyListener;
use Acencyril\SentinelleBundle\Service\CspNonce;
use Acencyril\SentinelleBundle\Twig\CspExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

final class ContentSecurityPolicyTest extends TestCase
{
    private const POLICY = "default-src 'self';\n    script-src 'self' {nonce}; object-src 'none'";

    private function respond(ContentSecurityPolicyListener $listener, Request $request, ?Response $response = null, int $type = HttpKernelInterface::MAIN_REQUEST): Response
    {
        $response ??= new Response('<p>hi</p>');
        $listener->onKernelResponse(new ResponseEvent($this->createStub(HttpKernelInterface::class), $request, $type, $response));

        return $response;
    }

    public function testThePageNonceIsInTheHeaderAndInTheTemplate(): void
    {
        $request = Request::create('/');
        $stack = new RequestStack();
        $stack->push($request);
        $nonce = new CspNonce($stack);
        $twig = new Environment(new ArrayLoader(['page' => '<script nonce="{{ csp_nonce() }}">go()</script>']));
        $twig->addExtension(new CspExtension($nonce));

        $html = $twig->render('page');
        $response = $this->respond(new ContentSecurityPolicyListener($nonce, self::POLICY), $request, new Response($html));

        self::assertMatchesRegularExpression('/^<script nonce="([A-Za-z0-9_-]{24})">/', $html);
        preg_match('/nonce="([^"]+)"/', $html, $m);
        self::assertSame("default-src 'self'; script-src 'self' 'nonce-{$m[1]}'; object-src 'none'", $response->headers->get('Content-Security-Policy'));
    }

    public function testEachPageGetsItsOwnNonce(): void
    {
        $nonce = new CspNonce(new RequestStack());
        $a = Request::create('/a');
        $b = Request::create('/b');
        self::assertSame($nonce->get($a), $nonce->get($a));
        self::assertNotSame($nonce->get($a), $nonce->get($b));
    }

    public function testAPolicySetByTheControllerIsKept(): void
    {
        $listener = new ContentSecurityPolicyListener(new CspNonce(new RequestStack()), self::POLICY);
        $response = $this->respond($listener, Request::create('/'), new Response('', 200, ['Content-Security-Policy' => "default-src 'none'"]));
        self::assertSame("default-src 'none'", $response->headers->get('Content-Security-Policy'));
    }

    public function testReportOnlyAndSubRequests(): void
    {
        $listener = new ContentSecurityPolicyListener(new CspNonce(new RequestStack()), null, "script-src {nonce}");
        $response = $this->respond($listener, Request::create('/'));
        self::assertFalse($response->headers->has('Content-Security-Policy'));
        self::assertMatchesRegularExpression("/^script-src 'nonce-[A-Za-z0-9_-]{24}'$/", (string) $response->headers->get('Content-Security-Policy-Report-Only'));

        $sub = $this->respond($listener, Request::create('/'), null, HttpKernelInterface::SUB_REQUEST);
        self::assertFalse($sub->headers->has('Content-Security-Policy-Report-Only'));
    }

    public function testTheNonceFunctionExistsEvenWithoutAPolicy(): void
    {
        $container = new ContainerBuilder();
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com']]], $container);
        self::assertTrue($container->getDefinition(CspExtension::class)->hasTag('twig.extension'));
        self::assertFalse($container->hasDefinition(ContentSecurityPolicyListener::class));

        $container = new ContainerBuilder();
        (new SentinelleExtension())->load([['alert' => ['recipient' => 'me@example.com'], 'csp' => ['policy' => self::POLICY]]], $container);
        self::assertSame(self::POLICY, $container->getDefinition(ContentSecurityPolicyListener::class)->getArgument(1));
    }
}
