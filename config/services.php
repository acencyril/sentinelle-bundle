<?php

declare(strict_types=1);

use Acencyril\SentinelleBundle\Command\CheckCommand;
use Acencyril\SentinelleBundle\Command\DigestCommand;
use Acencyril\SentinelleBundle\EventListener\BreachWatchListener;
use Acencyril\SentinelleBundle\Service\IpHistory;
use Acencyril\SentinelleBundle\Command\PurgeCommand;
use Acencyril\SentinelleBundle\Controller\ActivityController;
use Acencyril\SentinelleBundle\EventListener\BlockedIpListener;
use Acencyril\SentinelleBundle\EventListener\SiteActivityListener;
use Acencyril\SentinelleBundle\Repository\BlockedIpRepository;
use Acencyril\SentinelleBundle\Repository\VisitRepository;
use Acencyril\SentinelleBundle\Service\HumanPass;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpIdentifier;
use Acencyril\SentinelleBundle\Service\SecurityAlert;
use Acencyril\SentinelleBundle\Service\SiteEventLogger;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator $c): void {
    $services = $c->services()->defaults()->autoconfigure(false);

    $services->set(BlockedIpRepository::class)
        ->args([service('doctrine')])
        ->tag('doctrine.repository_service');

    $services->set(VisitRepository::class)
        ->args([service('doctrine')])
        ->tag('doctrine.repository_service');

    $services->set(IpIdentifier::class)
        ->args([service('cache.app'), '%sentinelle.extra_providers%']);

    $services->set(IpBlocklist::class)
        ->args([
            service(BlockedIpRepository::class),
            service('doctrine.orm.entity_manager'),
            service('cache.app'),
            service('logger'),
            service(IpIdentifier::class),
            '%sentinelle.allowlist%',
            '%sentinelle.dry_run%',
            '%sentinelle.blocking.durations%',
        ]);

    $services->set(HumanPass::class)
        ->args([
            '%kernel.secret%',
            service('cache.app'),
            service('logger'),
        ]);

    $services->set(IpHistory::class)
        ->args([service('doctrine.dbal.default_connection')]);

    $services->set(SecurityAlert::class)
        ->args([
            service('mailer.mailer'),
            service('logger'),
            service('router'),
            '%sentinelle.alert.recipient%',
            '%sentinelle.alert.sender%',
            '%sentinelle.alert.sender_name%',
            '%sentinelle.alert.site_name%',
            service(IpHistory::class),
            '%sentinelle.alert.quiet_when_blocked%',
        ]);

    /* After the activity listener (default priority 0) on kernel.terminate: the history in
       the email includes this very request. */
    $services->set(BreachWatchListener::class)
        ->args([
            service('mailer.mailer'),
            service(IpBlocklist::class),
            service(IpHistory::class),
            service(SiteEventLogger::class),
            service('cache.app'),
            service('logger'),
            '%sentinelle.alert.recipient%',
            '%sentinelle.alert.sender%',
            '%sentinelle.alert.site_name%',
            '%kernel.environment%',
            service(HumanPass::class)->nullOnInvalid(),
        ])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.terminate', 'method' => 'onKernelTerminate', 'priority' => -64,
        ]);

    $services->set(SiteEventLogger::class)
        ->args([
            service('doctrine.dbal.default_connection'),
            service('cache.app'),
            service('logger'),
            service(SecurityAlert::class),
            service(IpBlocklist::class),
            '%sentinelle.thresholds%',
            '%sentinelle.alert.cooldown%',
            '%sentinelle.exempt_paths%',
            '%sentinelle.extra_patterns%',
            '%sentinelle.extra_ignored%',
            '%sentinelle.access.prefix%',
            service(HumanPass::class)->nullOnInvalid(),
        ]);

    /* Priority 300, ahead of the router (32) and the firewall (8). A banned
       address must consume no route resolution, no session and no database
       query. Placed later, blocking would cost almost as much as serving. */
    $services->set(BlockedIpListener::class)
        ->args([
            service(IpBlocklist::class),
            service(HumanPass::class)->nullOnInvalid(),
            service('twig'),
            service('translator')->nullOnInvalid(),
            service('logger'),
        ])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.request', 'method' => 'onKernelRequest', 'priority' => 300,
        ]);

    /* On kernel.terminate: the response has gone out, so writing costs the
       visitor nothing — and it is the only moment the status code is known. */
    $services->set(SiteActivityListener::class)
        ->args([service(SiteEventLogger::class)])
        ->tag('kernel.event_listener', [
            'event' => 'kernel.terminate', 'method' => 'onKernelTerminate',
        ]);

    /* Dependencies are injected explicitly rather than through the restricted
       container an AbstractController expects: autoconfiguration is off here,
       and that container would never be built. */
    $services->set(ActivityController::class)
        ->args([
            service(VisitRepository::class),
            service(IpBlocklist::class),
            service(IpIdentifier::class),
            service('security.authorization_checker'),
            service('twig'),
            service('router'),
            service('security.csrf.token_manager'),
            '%sentinelle.access.role%',
            '%sentinelle.access.parent_template%',
            '%sentinelle.access.back_route%',
        ])
        ->tag('controller.service_arguments');

    $services->set(CheckCommand::class)
        ->args([
            service('doctrine.dbal.default_connection'),
            service('cache.app'),
            service(IpBlocklist::class),
            '%sentinelle.allowlist%',
            '%sentinelle.dry_run%',
            '%sentinelle.alert.recipient%',
        ])
        ->tag('console.command');

    $services->set(DigestCommand::class)
        ->args([
            service('doctrine.dbal.default_connection'),
            service('mailer.mailer'),
            '%sentinelle.alert.recipient%',
            '%sentinelle.alert.sender%',
            '%sentinelle.alert.site_name%',
        ])
        ->tag('console.command');

    $services->set(PurgeCommand::class)
        ->args([service(IpBlocklist::class), service('doctrine.dbal.default_connection')])
        ->tag('console.command');
};