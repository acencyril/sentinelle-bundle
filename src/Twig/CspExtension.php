<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Twig;

use Acencyril\SentinelleBundle\Service\CspNonce;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

/** csp_nonce(): <script nonce="{{ csp_nonce() }}"> — the value the Content-Security-Policy header allows. */
final class CspExtension extends AbstractExtension
{
    public function __construct(private readonly CspNonce $nonce)
    {
    }

    public function getFunctions(): array
    {
        return [new TwigFunction('csp_nonce', $this->nonce->get(...))];
    }
}
