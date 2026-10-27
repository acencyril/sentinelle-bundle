<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\SecurityTxt;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Answers /.well-known/security.txt before routing, so it needs no route import, works under
 * any locale prefix, and stays reachable even from a blocked address: whoever reports a flaw
 * may well have been probing the site a minute earlier.
 */
final class SecurityTxtListener
{
    public function __construct(
        private readonly SecurityTxt $securityTxt,
        private readonly bool $redirectLegacy = true,
    ) {
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        if (!\in_array($request->getMethod(), ['GET', 'HEAD'], true)) {
            return;
        }
        $path = $request->getPathInfo();

        if (SecurityTxt::LEGACY_PATH === $path && $this->redirectLegacy) {
            $event->setResponse(new RedirectResponse($request->getSchemeAndHttpHost().SecurityTxt::PATH, Response::HTTP_MOVED_PERMANENTLY));

            return;
        }
        if (SecurityTxt::PATH !== $path) {
            return;
        }

        $response = new Response($this->securityTxt->render($request->getSchemeAndHttpHost()), Response::HTTP_OK, [
            'Content-Type' => 'text/plain; charset=utf-8',
        ]);
        $response->setPublic();
        $response->setMaxAge(86400);
        $event->setResponse($response);
    }
}
