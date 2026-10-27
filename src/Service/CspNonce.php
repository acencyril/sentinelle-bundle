<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * One random nonce per page, shared by the template (csp_nonce()) and the
 * Content-Security-Policy header. Kept on the main request, so a sub-request
 * (an embedded controller) gets the same one as the page around it.
 */
final class CspNonce
{
    public const ATTRIBUTE = '_sentinelle_csp_nonce';

    public function __construct(private readonly RequestStack $requests)
    {
    }

    public function get(?Request $request = null): string
    {
        $request ??= $this->requests->getMainRequest();
        if (null === $request) {
            // No HTTP request (a command rendering an email): nothing to match, any value will do.
            return bin2hex(random_bytes(16));
        }
        $nonce = $request->attributes->get(self::ATTRIBUTE);
        if (!\is_string($nonce)) {
            $nonce = rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
            $request->attributes->set(self::ATTRIBUTE, $nonce);
        }

        return $nonce;
    }
}
