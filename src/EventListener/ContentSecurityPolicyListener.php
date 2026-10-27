<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\CspNonce;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * Sends the project's Content-Security-Policy, with this page's nonce in place of {nonce}.
 *
 * A response that already carries a policy keeps it: a controller that knows better (the
 * human-pass page, a file download, an embeddable widget) is never overridden.
 *
 * Why a nonce and not 'unsafe-inline': with 'unsafe-inline', an injected <script> runs; with a
 * nonce, only the scripts the template itself marked run, and an attacker cannot guess a value
 * that changes on every page.
 */
final class ContentSecurityPolicyListener
{
    public function __construct(
        private readonly CspNonce $nonce,
        private readonly ?string $policy,
        private readonly ?string $reportOnly = null,
    ) {
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $headers = $event->getResponse()->headers;
        foreach (['Content-Security-Policy' => $this->policy, 'Content-Security-Policy-Report-Only' => $this->reportOnly] as $name => $policy) {
            if (null === $policy || '' === trim($policy) || $headers->has($name)) {
                continue;
            }
            $headers->set($name, $this->expand($policy, $event));
        }
    }

    private function expand(string $policy, ResponseEvent $event): string
    {
        $policy = trim(preg_replace('/\s+/', ' ', $policy) ?? $policy);
        if (!str_contains($policy, '{nonce}')) {
            return $policy;
        }

        return str_replace('{nonce}', "'nonce-".$this->nonce->get($event->getRequest())."'", $policy);
    }
}
