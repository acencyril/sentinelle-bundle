<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Tests;

use Acencyril\SentinelleBundle\Service\Sensitive;
use PHPUnit\Framework\TestCase;

final class SensitiveTest extends TestCase
{
    public function testSensitivePaths(): void
    {
        foreach (['/.env', '/.env.local', '/.git/config', '/backup.sql', '/var/log/prod.log', '/vendor/autoload.php', '/phpinfo.php', '/%2e%65nv', '/id_rsa'] as $p) {
            self::assertTrue(Sensitive::isSensitivePath($p), $p);
        }
        foreach (['/', '/fr/', '/robots.txt', '/llms.txt', '/sitemap.xml', '/css/site.css', '/blog/environment'] as $p) {
            self::assertFalse(Sensitive::isSensitivePath($p), $p);
        }
    }

    public function testSecrets(): void
    {
        self::assertSame('APP_SECRET=', Sensitive::secretIn("APP_ENV=prod\nAPP_SECRET=abc"));
        self::assertNotNull(Sensitive::secretIn('-----BEGIN RSA PRIVATE KEY-----'));
        self::assertNotNull(Sensitive::secretIn('key: sk_live_ABCDEFGHIJKLMNOP'));
        self::assertNull(Sensitive::secretIn('<html>Our app secret sauce</html>'));
    }
}
