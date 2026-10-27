<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\DependencyInjection;

use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\SecurityAlert;
use Acencyril\SentinelleBundle\Service\SecurityTxt;
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
            ->info('Appears in the subject line: "Sentinelle <name> — …".')
            ->end()
            ->booleanNode('quiet_when_blocked')->defaultTrue()
            ->info('No email for an address already blocked whose tries all failed (scanners): they are counted in sentinelle:digest. A sensitive answer served always alerts.')
            ->end()
            ->arrayNode('immediate')
            ->info('Alert kinds emailed at once (breach, exploitation, brute_force, scan, or "all"). '
                .'The others are counted in the daily digest (sentinelle:digest). Default: only breach, '
                .'a sensitive address actually served with a 2xx. An email per scanner trains you to ignore them.')
            ->beforeNormalization()
            ->ifString()
            ->then(static fn (string $v): array => 'all' === $v ? SecurityAlert::KINDS : [$v])
            ->end()
            ->performNoDeepMerging()
            ->enumPrototype()->values(SecurityAlert::KINDS)->end()
            ->defaultValue(SecurityAlert::IMMEDIATE_DEFAULT)
            ->end()
            ->integerNode('cooldown')->defaultValue(3600)
            ->info('Seconds between two alerts for the same IP. One email per attack drowns the information from the first serious scan onwards.')
            ->end()
            ->end()
            ->end()

            ->arrayNode('mail')
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('locale')->defaultNull()
            ->info('Language of the emails (alert, breach alarm, digest): en or fr. Default: the application\'s kernel.default_locale; any other language falls back to English.')
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

            ->arrayNode('blocking')
            ->addDefaultsIfNotSet()
            ->children()
            ->arrayNode('durations')
            ->info('Automatic block length by strike: the first value for strike 1, the second for strike 2, and so on; the last one repeats. '
                .'Each value is a relative time ("+24 hours", "+7 days") or "permanent".')
            ->scalarPrototype()->end()
            ->defaultValue(['+24 hours', '+7 days', 'permanent'])
            ->requiresAtLeastOneElement()
            ->validate()
            ->ifTrue(static function (array $durations): bool {
                foreach ($durations as $d) {
                    if (null === IpBlocklist::normaliseDuration((string) $d)) {
                        return true;
                    }
                }

                return false;
            })
            ->thenInvalid('Each blocking duration must be a relative time in the future ("+24 hours", "+7 days") or "permanent", got %s.')
            ->end()
            ->end()
            ->booleanNode('human_pass')->defaultTrue()
            ->info('A blocked address asking for an HTML page gets a 403 page with a one-click browser proof-of-work. '
                .'Solved, it sets a signed cookie bound to the IP (24 h) that lets that browser through. '
                .'Sensitive paths (.env, .git…) stay closed, and the address stays blocked for everything else.')
            ->end()
            ->end()
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

            ->arrayNode('security_txt')
            ->info('Serves /.well-known/security.txt (RFC 9116): where to report a vulnerability. '
                .'Expires is recomputed every day, so the file never goes stale.')
            ->canBeEnabled()
            ->children()
            ->arrayNode('contact')
            ->info('"mailto:security@example.com" or an https URL; at least one.')
            ->beforeNormalization()->castToArray()->end()
            ->scalarPrototype()->end()
            ->end()
            ->scalarNode('expires')->defaultValue('+11 months')
            ->info('How far ahead Expires is, from today (midnight UTC). The RFC wants less than a year.')
            ->validate()
            ->ifTrue(static fn ($v): bool => !\is_string($v) || !SecurityTxt::isValidInterval($v))
            ->thenInvalid('security_txt.expires must be a relative time in the future, at most a year ("+11 months"), got %s.')
            ->end()
            ->end()
            ->arrayNode('preferred_languages')
            ->beforeNormalization()->castToArray()->end()
            ->scalarPrototype()->end()
            ->end()
            ->scalarNode('policy')->defaultNull()
            ->info('Your disclosure policy: an absolute URL, or a path ("/en/security") made absolute against the host asked.')
            ->end()
            ->arrayNode('canonical')
            ->info('Default: the security.txt address on the host asked.')
            ->beforeNormalization()->castToArray()->end()
            ->scalarPrototype()->end()
            ->end()
            ->arrayNode('encryption')
            ->info('URL of your OpenPGP key, if you want encrypted reports.')
            ->beforeNormalization()->castToArray()->end()
            ->scalarPrototype()->end()
            ->end()
            ->scalarNode('acknowledgments')->defaultNull()->end()
            ->scalarNode('hiring')->defaultNull()->end()
            ->booleanNode('redirect_legacy')->defaultTrue()
            ->info('/security.txt answers a 301 to /.well-known/security.txt.')
            ->end()
            ->end()
            ->validate()
            ->ifTrue(static fn (array $v): bool => $v['enabled'] && [] === $v['contact'])
            ->thenInvalid('security_txt needs at least one contact ("mailto:security@example.com").')
            ->end()
            ->end()

            ->arrayNode('csp')
            ->info('Sends a Content-Security-Policy on every page that has none. {nonce} becomes '
                ."'nonce-…', the value csp_nonce() prints in your templates: <script nonce=\"{{ csp_nonce() }}\">.")
            ->addDefaultsIfNotSet()
            ->children()
            ->scalarNode('policy')->defaultNull()
            ->info("e.g. \"default-src 'self'; script-src 'self' {nonce}; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\"")
            ->end()
            ->scalarNode('report_only')->defaultNull()
            ->info('A second policy sent as Content-Security-Policy-Report-Only: try a stricter one before enforcing it.')
            ->end()
            ->end()
            ->end()
            ->end();

        return $tree;
    }
}