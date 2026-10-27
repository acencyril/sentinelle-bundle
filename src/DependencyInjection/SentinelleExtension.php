<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\DependencyInjection;

use Acencyril\SentinelleBundle\EventListener\ContentSecurityPolicyListener;
use Acencyril\SentinelleBundle\EventListener\SecurityTxtListener;
use Acencyril\SentinelleBundle\Service\CspNonce;
use Acencyril\SentinelleBundle\Service\SecurityTxt;
use Acencyril\SentinelleBundle\Twig\CspExtension;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

/**
 * Turns the project's configuration into container parameters.
 *
 * Critical patterns and protected providers declared by the project are merged
 * with the bundle's, never substituted. A project can protect its own webhook;
 * it cannot remove Log4Shell detection while believing it is simply adapting
 * its configuration.
 */
class SentinelleExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $config = $this->processConfiguration(new Configuration(), $configs);

        // Fail with an explanation rather than an "undefined array key" notice.
        // A missing recipient means the bundle detects without warning anyone,
        // which is the one failure mode nobody would notice on their own.
        if (empty($config['alert']['recipient'])) {
            throw new \InvalidArgumentException(
                'Sentinelle: "sentinelle.alert.recipient" is missing. '
                .'Without a recipient, the bundle detects without warning anyone. '
                .'Create config/packages/sentinelle.yaml — see '
                .'https://github.com/acencyril/sentinelle-bundle#installation'
            );
        }

        $loader = new PhpFileLoader($container, new FileLocator(\dirname(__DIR__, 2).'/config'));
        $loader->load('services.php');
        if (!$config['breach_watch']) {
            $container->removeDefinition(\Acencyril\SentinelleBundle\EventListener\BreachWatchListener::class);
        }
        if (!$config['blocking']['human_pass']) {
            // Every consumer takes it as optional: no service, no challenge page, a bare 403.
            $container->removeDefinition(\Acencyril\SentinelleBundle\Service\HumanPass::class);
        }

        $this->registerSecurityTxt($config['security_txt'], $container);
        $this->registerCsp($config['csp'], $container);

        foreach ([
                     'sentinelle.alert.recipient'      => $config['alert']['recipient'],
                     'sentinelle.alert.sender'           => $config['alert']['sender'],
                     'sentinelle.alert.sender_name'      => $config['alert']['sender_name'],
                     'sentinelle.alert.site_name'        => $config['alert']['site_name'],
                     'sentinelle.alert.cooldown'         => $config['alert']['cooldown'],
                     'sentinelle.alert.quiet_when_blocked' => $config['alert']['quiet_when_blocked'],
                     'sentinelle.alert.immediate'        => array_values(array_unique($config['alert']['immediate'])),
                     'sentinelle.breach_watch'           => $config['breach_watch'],
                     'sentinelle.mail.locale'            => $config['mail']['locale'] ?? '%kernel.default_locale%',

                     'sentinelle.access.role'            => $config['access']['role'],
                     'sentinelle.access.prefix'          => $config['access']['prefix'],
                     'sentinelle.access.parent_template' => $config['access']['parent_template'],
                     'sentinelle.access.back_route'      => $config['access']['back_route'],

                     'sentinelle.thresholds'             => $config['thresholds'],
                     'sentinelle.dry_run'                => $config['dry_run'],
                     'sentinelle.blocking.durations'     => array_values($config['blocking']['durations']),
                     'sentinelle.blocking.human_pass'    => $config['blocking']['human_pass'],

                     'sentinelle.allowlist'              => $config['never_block']['ips'],
                     'sentinelle.exempt_paths'           => $config['never_block']['paths'],

                     // Merged, never substituted — see the note at the top of the class.
                     'sentinelle.extra_providers'        => $config['never_block']['providers'],
                     'sentinelle.extra_patterns'         => $config['critical_patterns'],
                     'sentinelle.extra_ignored'          => $config['ignore'],
                 ] as $name => $value) {
            $container->setParameter($name, $value);
        }
    }

    /** @param array<string, mixed> $c */
    private function registerSecurityTxt(array $c, ContainerBuilder $container): void
    {
        if (!$c['enabled']) {
            return;
        }
        $container->register(SecurityTxt::class, SecurityTxt::class)->setArguments([
            array_values($c['contact']),
            $c['expires'],
            array_values($c['preferred_languages']),
            $c['policy'],
            array_values($c['canonical']),
            array_values($c['encryption']),
            $c['acknowledgments'],
            $c['hiring'],
        ]);
        /* Ahead of the IP block (300): whoever reports a flaw may have been probing a minute ago. */
        $container->register(SecurityTxtListener::class, SecurityTxtListener::class)
            ->setArguments([new Reference(SecurityTxt::class), $c['redirect_legacy']])
            ->addTag('kernel.event_listener', ['event' => 'kernel.request', 'method' => 'onKernelRequest', 'priority' => 310]);
    }

    /** @param array{policy: ?string, report_only: ?string} $c */
    private function registerCsp(array $c, ContainerBuilder $container): void
    {
        /* The nonce and csp_nonce() always exist, so a template can carry nonce="…" before
           the policy is switched on, and keeps working if it is switched off. */
        $container->register(CspNonce::class, CspNonce::class)->setArguments([new Reference('request_stack')]);
        $container->register(CspExtension::class, CspExtension::class)
            ->setArguments([new Reference(CspNonce::class)])
            ->addTag('twig.extension');
        if (null === $c['policy'] && null === $c['report_only']) {
            return;
        }
        /* Late (-64): after the controllers and listeners that set a policy of their own. */
        $container->register(ContentSecurityPolicyListener::class, ContentSecurityPolicyListener::class)
            ->setArguments([new Reference(CspNonce::class), $c['policy'], $c['report_only']])
            ->addTag('kernel.event_listener', ['event' => 'kernel.response', 'method' => 'onKernelResponse', 'priority' => -64]);
    }

    public function getAlias(): string
    {
        return 'sentinelle';
    }
}