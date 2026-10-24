<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

/**
 * Addresses that must never be answered with a 2xx, whatever the route, and what a leaked
 * secret looks like in a response body. A probe for /.env that gets a 404 is noise; the same
 * probe that gets a 200 is a breach.
 */
final class Sensitive
{
    public const PATH = '#(^|/)\.(env|git|svn|hg|ssh|aws|docker|kube|htpasswd|npmrc|pgpass)(\b|/|\.|$)'
        .'|(^|/)(composer\.(json|lock)|symfony\.lock|docker-compose[^/]*|Dockerfile|Caddyfile)$'
        .'|(^|/)(vendor|var|config|migrations|src|docker|node_modules)/'
        .'|\.(sql|dump|bak|backup|old|orig|save|swp|pem|key|p12|pfx|crt|ini|log|sqlite3?|db|tar|tgz|gz|zip|7z|rar)$'
        .'|id_(rsa|ed25519|ecdsa)|/etc/(passwd|shadow)|/proc/self|phpinfo|server-status|adminer|phpmyadmin|/_profiler|/_wdt#i';

    public const SECRET = '#\b(APP_SECRET|DATABASE_URL|MAILER_DSN|STRIPE_SECRET_KEY|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|OPENROUTER_API_KEY)\s*='
        .'|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bsk_live_[A-Za-z0-9]{10,}|\bsk-(ant-|or-v1-|proj-)[A-Za-z0-9_-]{20,}|\bxsmtpsib-[a-f0-9]{20,}|\brepositoryformatversion\b|root:x:0:0:#';

    public static function isSensitivePath(string $path): bool
    {
        return 1 === preg_match(self::PATH, rawurldecode($path));
    }

    /** The secret found in a body (its first characters), or null. */
    public static function secretIn(string $body): ?string
    {
        return '' !== $body && preg_match(self::SECRET, substr($body, 0, 2_000_000), $m) ? $m[0] : null;
    }
}
