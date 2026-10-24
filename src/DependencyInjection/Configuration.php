<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * What a project may tune, and what it may not.
 *
 * Detection patterns are extensible but never substitutable. A project can add
 * its own patterns and its own protected providers; it cannot remove the
 * bundle's. Otherwise you end up with an installation that has Log4Shell
 * detection switched off and nobody realising it, having merely "adapted the
 * configuration to the project". Whatever you make configurable, you make
 * accidentally disableable.
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $tree = new TreeBuilder('sentinelle');

        $tree->getRootNode()
            ->children()
            ->arrayNode('alert')
            ->isRequired()
            ->children()
            ->scalarNode('recipient')->isRequired()
            ->info('Where alerts are sent. Without a recipient, the bundle detects without warning anyone.')
            ->end()
            ->scalarNode('sender')->defaultValue('no-reply@localhost')->end()
            ->scalarNode('sender_name')->defaultValue('Sentinelle')->end()
            ->scalarNode('site_name')->defaultValue('the site')
            ->info('Appears in the subject line: "Security alert <name>".')
            ->end()
            ->booleanNode('quiet_when_blocked')->defaultTrue()
            ->info('No email for an address already blocked whose tries all failed (scanners): they are counted in sentinelle:digest. A sensitive answer served always alerts.')
            ->end()
            ->integerNode('cooldown')->defaultValue(3600)
            ->info('Seconds between two alerts for the same IP. One email per attack drowns the information from the first serious scan onwards.')
            ->end()
            ->end()
            ->end()

            ->arrayNode('access')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('role')->defaultValue('ROLE_ADMIN')->end()
            ->scalarNode('prefix')->defaultValue('/admin/activity')->end()
            ->scalarNode('parent_template')->defaultValue('base.html.twig')->end()
            ->scalarNode('back_route')->defaultNull()
            ->info('Route for the back link. Null means no button.')
            ->end()
            ->end()
            ->end()

            ->booleanNode('breach_watch')
            ->defaultTrue()
            ->info('Watch the ANSWERS: a sensitive file served with a 2xx, or a secret in a response, blocks the address and sends a red alert at once.')
            ->end()

            ->booleanNode('dry_run')
            ->defaultFalse()
            ->info('Dry-run: detects, alerts and logs, but NEVER blocks. '
                .'Leave it on for the first weeks on a live site — you want to see '
                .'what the bundle would have shut out before handing it the keys.')
            ->end()

            ->arrayNode('thresholds')
            ->addDefaultsIfNotSet()
            ->children()
            ->integerNode('burst')->defaultValue(15)->end()
            ->integerNode('burst_window')->defaultValue(600)->end()
            ->integerNode('bruteforce')->defaultValue(10)->end()
            ->integerNode('bruteforce_window')->defaultValue(600)->end()
            ->integerNode('flood_max')->defaultValue(5)
            ->info('Error rows per IP per window. Beyond that we stop writing but keep COUNTING — otherwise the burst threshold would never be reached and the alert would neutralise itself.')
            ->end()
            ->integerNode('flood_window')->defaultValue(3600)->end()
            ->end()
            ->end()

            ->arrayNode('never_block')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('ips')->defaultNull()
            ->info('IPs or CIDRs, comma separated. Put at least your own outbound address here.')
            ->end()
            ->arrayNode('paths')
            ->scalarPrototype()->end()
            ->defaultValue(['/api/webhook/'])
            ->info('Paths whose refusals never trigger a block. A webhook returning 401 while a key is being deployed would otherwise get the provider banned.')
            ->end()
            ->arrayNode('providers')
            ->scalarPrototype()->end()
            ->defaultValue([])
            ->info("Reverse DNS suffixes ADDED to the bundle's own. Blocking is refused for these, even by hand.")
            ->end()
            ->end()
            ->end()

            ->arrayNode('critical_patterns')
            ->useAttributeAsKey('name')
            ->scalarPrototype()->end()
            ->defaultValue([])
            ->info("Regular expressions ADDED to the bundle's own. None are ever removed.")
            ->end()

            ->arrayNode('ignore')
            ->scalarPrototype()->end()
            ->defaultValue([])
            ->info("Prefixes never logged, in addition to the bundle's own.")
            ->end()
            ->end();

        return $tree;
    }
}