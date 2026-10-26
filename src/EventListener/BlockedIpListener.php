<?php

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\HumanPass;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\Sensitive;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Contracts\Translation\TranslatorInterface;
use Twig\Environment;

/**
 * Turns away requests coming from a blocked IP.
 *
 * Hooked very early on kernel.request, ahead of the router (priority 32) and
 * the firewall (priority 8): a banned address must consume no route
 * resolution, no session and no database query.
 *
 * Scripts get a bare 403, with no hint as to why. Telling a scanner what
 * happened only teaches it what it triggered. A browser asking for a page gets
 * the human pass page instead: an address is not a person, and the people
 * behind a shared address did nothing (see HumanPass).
 */
class BlockedIpListener
{
    /** Flag read back by SiteEventLogger to label the row "ip_blocked". */
    public const REQUEST_ATTRIBUTE = '_ip_blocked';

    private static bool $proxyChecked = false;

    public function __construct(
        private IpBlocklist $blocklist,
        private ?HumanPass $humanPass = null,
        private ?Environment $twig = null,
        private ?TranslatorInterface $translator = null,
        private LoggerInterface $logger = new NullLogger(),
    ) {}

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $this->warnAboutMissingTrustedProxies($request);

        $ip = $request->getClientIp();
        if ($ip === null || !$this->blocklist->isBlocked($ip)) {
            return;
        }

        $path = $request->getPathInfo();
        if ($this->humanPass !== null) {
            if ($path === HumanPass::PATH && $request->isMethod('POST')) {
                $event->setResponse($this->attempt($request, $ip));

                return;
            }
            // A valid pass lets the browser through, everywhere but the
            // sensitive paths: a pass is for a person reading pages, and no
            // person needs /.env.
            if (!Sensitive::isSensitivePath($path)
                && $this->humanPass->isValidPass($request->cookies->get(HumanPass::COOKIE), $ip)) {
                $request->attributes->set(HumanPass::PASSED_ATTRIBUTE, true);

                return;
            }
        }

        $request->attributes->set(self::REQUEST_ATTRIBUTE, true);
        $this->blocklist->registerHit($ip);

        if ($this->offersChallenge($request, $ip)) {
            $event->setResponse($this->challengePage($request, $ip, $request->getRequestUri(), false));

            return;
        }

        $event->setResponse(new Response('Forbidden', Response::HTTP_FORBIDDEN, [
            'Content-Type' => 'text/plain; charset=UTF-8',
            // No intermediate cache should remember this 403: the block
            // expires, and the response must not outlive it.
            'Cache-Control' => 'no-store, private',
        ]));
    }

    /**
     * A browser asking for a page: GET, wants HTML, not a sensitive path, and
     * the address has not lost its right to a pass.
     */
    private function offersChallenge(Request $request, string $ip): bool
    {
        return $this->humanPass !== null
            && $this->twig !== null
            && $request->isMethod('GET')
            && str_contains((string) $request->headers->get('Accept'), 'text/html')
            && !Sensitive::isSensitivePath($request->getPathInfo())
            && !$this->humanPass->isRevoked($ip);
    }

    /** The solved challenge comes back here. */
    private function attempt(Request $request, string $ip): Response
    {
        $request->attributes->set(self::REQUEST_ATTRIBUTE, true);
        $return = self::safeReturn($request->request->getString('return'));

        if ($this->humanPass->isRevoked($ip) || !$this->humanPass->allowAttempt($ip)) {
            return $this->challengePage($request, $ip, $return, false, false, Response::HTTP_TOO_MANY_REQUESTS);
        }
        if (!$this->humanPass->verify($ip, $request->request->getString('challenge'), $request->request->getString('solution'))) {
            return $this->challengePage($request, $ip, $return, true);
        }

        // Logged as "human_pass" rather than "ip_blocked": the dashboard counts them.
        $request->attributes->remove(self::REQUEST_ATTRIBUTE);
        $request->attributes->set(HumanPass::GRANTED_ATTRIBUTE, true);
        $this->logger->info('Sentinelle: human pass granted', ['ip' => $ip]);

        $response = new RedirectResponse($return, Response::HTTP_SEE_OTHER);
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->setCookie(Cookie::create(HumanPass::COOKIE)
            ->withValue($this->humanPass->passFor($ip))
            ->withExpires(time() + $this->humanPass->ttl())
            ->withPath('/')
            ->withSecure($request->isSecure())
            ->withHttpOnly(true)
            ->withSameSite(Cookie::SAMESITE_LAX));

        return $response;
    }

    private function challengePage(Request $request, string $ip, string $return, bool $failed, bool $allowed = true, int $status = Response::HTTP_FORBIDDEN): Response
    {
        $locale = $request->getPreferredLanguage(['en', 'fr']) ?? 'en';
        $nonce = bin2hex(random_bytes(16));
        $html = $this->twig->render('@Sentinelle/human_pass.html.twig', [
            'locale' => $locale,
            't' => $this->texts($locale),
            'nonce' => $nonce,
            'ip' => $ip,
            'allowed' => $allowed,
            'error' => $failed,
            'challenge' => $allowed ? $this->humanPass->challenge($ip) : '',
            'difficulty' => $this->humanPass->difficulty(),
            'action' => $request->getBaseUrl().HumanPass::PATH,
            'return' => $return,
        ]);

        return new Response($html, $status, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store, private',
            'X-Robots-Tag' => 'noindex',
            'Content-Security-Policy' => "default-src 'none'; script-src 'nonce-$nonce'; style-src 'nonce-$nonce'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ]);
    }

    /**
     * The page's texts, from the application's translator when there is one
     * (so a project can reword them), else from the bundle's own files.
     *
     * @return array<string, string>
     */
    private function texts(string $locale): array
    {
        $file = \dirname(__DIR__, 2).'/translations/sentinelle.'.$locale.'.php';
        $own = is_file($file) ? require $file : [];
        $texts = [];
        foreach ($own as $id => $fallback) {
            $text = $this->translator?->trans($id, [], 'sentinelle', $locale);
            $texts[substr($id, \strlen('human_pass.'))] = null === $text || $text === $id ? $fallback : $text;
        }

        return $texts;
    }

    /** Back to where the visitor was, on this site only. */
    private static function safeReturn(string $return): string
    {
        return str_starts_with($return, '/') && !str_starts_with($return, '//') && !str_contains($return, '\\')
            && 1 !== preg_match('/[\x00-\x1f]/', $return) ? $return : '/';
    }

    /**
     * Behind a reverse proxy with no `trusted_proxies`, every visitor shares
     * the proxy's address: one scanner, and everybody would be blocked. The
     * private ranges are never blocked, which is what saves the day, but then
     * nothing is blocked at all. Said once per process, in the logs.
     */
    private function warnAboutMissingTrustedProxies(Request $request): void
    {
        if (self::$proxyChecked) {
            return;
        }
        $remote = (string) $request->server->get('REMOTE_ADDR');
        if ('' === $remote || !$request->headers->has('X-Forwarded-For')) {
            return;
        }
        self::$proxyChecked = true;
        if ([] === Request::getTrustedProxies() && false === filter_var($remote, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE)) {
            $this->logger->warning(
                'Sentinelle: requests come from {remote} with an X-Forwarded-For header, but no trusted proxies are configured. '
                .'Every visitor shares the proxy\'s address, so Sentinelle cannot tell them apart and blocks nobody. '
                .'Set framework.trusted_proxies (see the "Behind a reverse proxy" section of the README).',
                ['remote' => $remote]
            );
        }
    }

    /** @internal for tests */
    public static function resetProxyCheck(): void
    {
        self::$proxyChecked = false;
    }
}
