<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Acencyril\SentinelleBundle\Entity\Visit;
use Acencyril\SentinelleBundle\Service\Texts;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Translation\TranslatorInterface;
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;

/** The dashboard's markup: what it shows, in both languages, styled only through --sentinelle-* tokens. */
final class DashboardTest extends TestCase
{
    private static function render(array $vars = [], string $locale = 'en'): string
    {
        $files = new FilesystemLoader();
        $files->addPath(\dirname(__DIR__).'/templates', 'Sentinelle');
        $twig = new Environment(new ChainLoader([
            new ArrayLoader(['admin.html.twig' => '<title>{% block title %}{% endblock %}</title><main>{% block body %}{% endblock %}</main>']),
            $files,
        ]), ['strict_variables' => true]);
        $twig->addFunction(new TwigFunction('path', static fn (string $route, array $params = []): string => '/'.$route.($params ? '?'.http_build_query($params) : '')));
        $twig->addFunction(new TwigFunction('csrf_token', static fn (): string => 'token'));
        $twig->addGlobal('app', new class {
            public function flashes(string $type): array
            {
                return 'sentinelle_success' === $type ? ['203.0.113.9 blocked.'] : [];
            }
        });

        return $twig->render('@Sentinelle/activity.html.twig', $vars + [
            'events' => [],
            'filter' => 'all',
            'summary' => [],
            'topIps' => [],
            'blocked' => [],
            'identities' => [],
            'blockedByIp' => [],
            'parent_template' => 'admin.html.twig',
            'back_route' => null,
            'dry_run' => false,
            't' => Texts::section(null, 'dashboard.', $locale),
        ]);
    }

    private static function busy(): array
    {
        $attack = new Visit();
        $attack->setEventType('attack_attempt');
        $attack->setUrl('/');
        $attack->setIp('203.0.113.77');
        $attack->setStatusCode(403);
        $attack->setUserAgent('python-requests/2.32');
        $attack->setMeta(['pattern' => 'union\s+select', 'query' => 'id=1 UNION SELECT 1']);
        $view = new Visit();
        $view->setEventType('page_view');
        $view->setUrl('/fr');
        $view->setIp('198.51.100.4');
        $view->setStatusCode(200);
        $blocked = (new BlockedIp('203.0.113.77', 'Exploitation attempt'))->setStrikes(3);

        return [
            'events' => [$attack, $view],
            'summary' => ['page_view' => 60, 'attack_attempt' => 2, 'ip_blocked' => 5, 'human_pass' => 1, 'breach_served' => 1],
            'topIps' => [['ip' => '203.0.113.77', 'total' => 3, 'last' => new \DateTimeImmutable()], ['ip' => '192.0.2.8', 'total' => 1, 'last' => new \DateTimeImmutable()]],
            'blocked' => [$blocked],
            'blockedByIp' => ['203.0.113.77' => $blocked],
            'identities' => ['192.0.2.8' => ['hostname' => 'mx.mailgun.net', 'label' => 'Mailgun', 'critical' => true], '203.0.113.77' => ['hostname' => null, 'label' => null, 'critical' => false]],
            'back_route' => 'admin',
            'dry_run' => true,
        ];
    }

    public function testSummaryTilesTablesAndPills(): void
    {
        $html = self::render(self::busy());

        self::assertStringContainsString('<title>Site activity</title>', $html);
        self::assertStringContainsString('class="sentinelle"', $html);
        self::assertMatchesRegularExpression('#data-tile="attacks">\s*<span class="sn-tile-label">Exploitation attempts</span>\s*<span class="sn-tile-value">2</span>#', $html);
        self::assertMatchesRegularExpression('#class="sn-tile is-danger is-alert" href="[^"]*breach_served[^"]*" data-tile="breaches"#', $html);
        self::assertStringContainsString('data-tile="blocked"', $html);
        self::assertStringContainsString('href="#sn-blocked"', $html);
        self::assertSame(3, substr_count($html, 'class="sn-scroll"'), 'every table scrolls in its own frame');
        self::assertStringContainsString('<span class="sn-pill is-danger">exploitation attempt</span>', $html);
        self::assertStringContainsString('pattern: union\s+select', $html);
        self::assertStringContainsString('⛔ Mailgun — do not block', $html);
        self::assertStringContainsString('unknown (no reverse DNS)', $html);
        self::assertStringContainsString('already blocked', $html);
        self::assertStringContainsString('Dry run', $html);
        self::assertStringContainsString('role="alert">A sensitive file', $html);
        self::assertStringContainsString('<p class="sn-flash is-success" role="status">203.0.113.9 blocked.</p>', $html);
        self::assertStringContainsString('href="/admin"', $html);
    }

    public function testStyledOnlyThroughClassesAndTokens(): void
    {
        $html = self::render(self::busy());

        self::assertStringNotContainsString(' style="', $html, 'no inline colours: hosts restyle through the tokens');
        self::assertStringNotContainsString('http', preg_replace('#href="[^"]*"#', '', $html), 'no external resource');
        preg_match_all('#var\((--sentinelle-[a-z-]+)#', $html, $m);
        $tokens = array_unique($m[1]);
        self::assertContains('--sentinelle-accent', $tokens);
        self::assertContains('--sentinelle-font', $tokens);
        self::assertContains('--sentinelle-radius', $tokens);
        $readme = file_get_contents(\dirname(__DIR__).'/README.md');
        foreach ($tokens as $token) {
            self::assertStringContainsString('`'.$token.'`', $readme, $token.' is documented');
        }
    }

    public function testFrenchAndEmptyState(): void
    {
        $html = self::render([], 'fr');

        self::assertStringContainsString('<h1>Activité du site</h1>', $html);
        self::assertStringContainsString('Blocage actif', $html);
        self::assertStringContainsString('Aucune visite enregistrée.', $html);
        self::assertStringContainsString('Rien à signaler.', $html);
        self::assertStringNotContainsString('sn-blocked"', $html);
        self::assertStringContainsString('aucune servie', $html);
    }

    public function testBothLanguagesHaveTheSameKeys(): void
    {
        $en = require \dirname(__DIR__).'/translations/sentinelle.en.php';
        $fr = require \dirname(__DIR__).'/translations/sentinelle.fr.php';
        self::assertSame(array_keys($en), array_keys($fr));
    }

    public function testTheApplicationTranslatorWinsAndUnknownLocalesFallBackToEnglish(): void
    {
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturnCallback(static fn (string $id): string => 'dashboard.title' === $id ? 'Security' : $id);

        self::assertSame('Security', Texts::section($translator, 'dashboard.', 'en')['title']);
        self::assertSame('Log', Texts::section($translator, 'dashboard.', 'en')['log.title']);
        self::assertSame('Site activity', Texts::section(null, 'dashboard.', 'de')['title']);
        self::assertSame('Access blocked', Texts::section(null, 'human_pass.', 'en')['title']);
        self::assertArrayNotHasKey('dashboard.title', Texts::section(null, 'human_pass.', 'en'));
    }

    public function testARowWithoutMetaStillRenders(): void
    {
        $visit = new Visit();
        $visit->setEventType('page_view');
        (new \ReflectionProperty(Visit::class, 'meta'))->setValue($visit, null);

        self::assertSame([], $visit->getMeta());
    }
}
