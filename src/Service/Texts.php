<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The bundle's texts: the application's translator first (domain "sentinelle", so a project can
 * reword any of them), else the bundle's own files. The translation component stays optional:
 * without it, the bundled English and French texts are used as they are.
 */
final class Texts
{
    public const LOCALES = ['en', 'fr'];

    /**
     * Every text whose key starts with $prefix, keyed without the prefix.
     *
     * @return array<string, string>
     */
    public static function section(?TranslatorInterface $translator, string $prefix, ?string $locale): array
    {
        $locale = \in_array($locale, self::LOCALES, true) ? $locale : 'en';
        $own = require \dirname(__DIR__, 2).'/translations/sentinelle.'.$locale.'.php';
        $texts = [];
        foreach ($own as $id => $fallback) {
            if (!str_starts_with($id, $prefix)) {
                continue;
            }
            $text = $translator?->trans($id, [], 'sentinelle', $locale);
            $texts[substr($id, \strlen($prefix))] = null === $text || $text === $id ? $fallback : $text;
        }

        return $texts;
    }
}
