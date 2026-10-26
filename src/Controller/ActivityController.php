<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Controller;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\Entity\Visit;
use Acencyril\SentinelleBundle\Repository\VisitRepository;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpIdentifier;
use Acencyril\SentinelleBundle\Service\Texts;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Contracts\Translation\TranslatorInterface;
use Twig\Environment;

/**
 * The dashboard: what happened, and what you decide to do about it.
 *
 * This deliberately does not extend `AbstractController`. That base class
 * expects a restricted container built by autoconfiguration — a mechanism
 * disabled in a bundle where every service is declared by hand. The symptoms
 * contradict each other: with no container you get "has no container set",
 * with the global one you get "SecurityBundle is not registered". Two very
 * different messages for a single cause, neither of which points at it.
 * Injecting what is actually needed — the authorization checker, Twig, the
 * router — removes the question instead of answering it.
 *
 * The role and the parent template are configuration too: a bundle that
 * hardcodes its role forces every project into a permission hierarchy it did
 * not choose.
 */
class ActivityController
{
    public function __construct(
        private VisitRepository $visits,
        private IpBlocklist $blocklist,
        private IpIdentifier $identifier,
        private AuthorizationCheckerInterface $authChecker,
        private Environment $twig,
        private UrlGeneratorInterface $router,
        private CsrfTokenManagerInterface $csrf,
        private string $role,
        private string $parentTemplate,
        private ?string $backRoute,
        private ?TranslatorInterface $translator = null,
        private bool $dryRun = false,
    ) {
    }

    public function index(Request $request): Response
    {
        $this->denyUnlessGranted();

        $filter = $request->query->getString('filter', 'all');
        $blocked = $this->blocklist->activeEntries();
        $events = $this->visits->findLatest($filter);
        $topIps = $this->visits->topSuspiciousIps(new \DateTimeImmutable('-7 days'));

        /* Order matters here. The number of reverse lookups is capped per
           render, so the addresses you are going to decide about must be named
           first, even if the cap is reached before the end of the log. An
           unnamed address is one you block at random. */
        $ips = [
            ...array_column($topIps, 'ip'),
            ...array_map(static fn (BlockedIp $b): string => $b->getIp(), $blocked),
            ...array_filter(array_map(static fn (Visit $e): ?string => $e->getIp(), $events)),
        ];

        return new Response($this->twig->render('@Sentinelle/activity.html.twig', [
            'events' => $events,
            'filter' => $filter,
            'summary' => $this->visits->summarySince(new \DateTimeImmutable('-24 hours')),
            'topIps' => $topIps,
            'blocked' => $blocked,
            'identities' => $this->identifier->identifyMany($ips),
            'blockedByIp' => array_combine(
                array_map(static fn (BlockedIp $b): string => $b->getIp(), $blocked),
                $blocked
            ),
            'parent_template' => $this->parentTemplate,
            'back_route' => $this->backRoute,
            'dry_run' => $this->dryRun,
            't' => Texts::section($this->translator, 'dashboard.', $request->getLocale()),
        ]));
    }

    /**
     * Manual block. Permanent by default: an address you block by hand is a
     * deliberate decision, not a detection.
     */
    public function block(Request $request): Response
    {
        $this->denyUnlessGranted();
        $ip = trim($request->request->getString('ip'));

        if (!$this->isTokenValid($request)) {
            $this->flash($request, 'error', 'invalid_token', $ip);
        } elseif (false === filter_var($ip, \FILTER_VALIDATE_IP)) {
            $this->flash($request, 'error', 'invalid_ip', $ip);
        } elseif ($this->blocklist->isAllowed($ip)) {
            $this->flash($request, 'error', 'allowlisted', $ip);
        } elseif (null === $this->blocklist->block($ip, 'Manual block from the dashboard', BlockedIp::SOURCE_MANUAL)) {
            /* This is where the original incident would repeat. A critical
               provider IP, recognised by reverse DNS: blocking it would break a
               working part of the site. The button refuses, and says why. */
            $this->flash($request, 'error', 'critical', $ip);
        } else {
            $this->flash($request, 'success', 'blocked', $ip);
        }

        return new RedirectResponse($this->router->generate('sentinelle_activity'));
    }

    public function unblock(Request $request): Response
    {
        $this->denyUnlessGranted();
        $ip = trim($request->request->getString('ip'));

        if (!$this->isTokenValid($request)) {
            $this->flash($request, 'error', 'invalid_token', $ip);
        } elseif ($this->blocklist->unblock($ip)) {
            $this->flash($request, 'success', 'unblocked', $ip);
        } else {
            $this->flash($request, 'error', 'not_blocked', $ip);
        }

        return new RedirectResponse($this->router->generate('sentinelle_activity'));
    }

    private function denyUnlessGranted(): void
    {
        if (!$this->authChecker->isGranted($this->role)) {
            throw new AccessDeniedException();
        }
    }

    private function isTokenValid(Request $request): bool
    {
        return $this->csrf->isTokenValid(
            new CsrfToken('sentinelle_block', $request->request->getString('_token'))
        );
    }

    /** Messages go through the session, when there is one, in the dashboard's language. */
    private function flash(Request $request, string $kind, string $key, string $ip): void
    {
        if ($request->hasSession()) {
            $texts = Texts::section($this->translator, 'dashboard.flash.', $request->getLocale());
            $request->getSession()->getFlashBag()->add('sentinelle_'.$kind, strtr($texts[$key], ['%ip%' => $ip]));
        }
    }
}