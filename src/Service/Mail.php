<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The texts and the layout of every email Sentinelle sends (the alert, the breach alarm, the daily
 * digest), in the language of `mail.locale` (default: the application's `kernel.default_locale`).
 *
 * Texts: keys `mail.*`, domain "sentinelle", the application's translator first, so a project can
 * reword any of them; else the bundle's English and French files. A locale the bundle does not
 * ship falls back to English.
 *
 * Layout: one centred card, at most 600 px wide and fluid below, tables for the structure (what
 * mail clients render reliably), inline styles only, system fonts, no image, font or stylesheet
 * loaded from anywhere: a security email must read the same offline, in a client that blocks
 * remote content, and on a phone.
 */
final class Mail
{
    public const MUTED = '#64748b';
    public const LINE = '#e2e8f0';
    private const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
    private const MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";

    /** @var array<string, string>|null */
    private ?array $texts = null;

    public function __construct(
        private ?TranslatorInterface $translator = null,
        private string $locale = 'en',
    ) {
    }

    public function locale(): string
    {
        return \in_array($this->locale, Texts::LOCALES, true) ? $this->locale : 'en';
    }

    /** A text, its %placeholders% replaced (values as given: escape them first when they are HTML). */
    public function t(string $key, array $params = []): string
    {
        $this->texts ??= Texts::section($this->translator, 'mail.', $this->locale);
        $text = $this->texts[$key] ?? $key;

        return $params ? strtr($text, $params) : $text;
    }

    /** "$key.one" for 1, "$key.other" otherwise (and "$key.none" for 0 when it exists), with %count%. */
    public function n(string $key, int $count, array $params = []): string
    {
        $this->texts ??= Texts::section($this->translator, 'mail.', $this->locale);
        $form = 1 === $count ? 'one' : (0 === $count && isset($this->texts[$key.'.none']) ? 'none' : 'other');

        return $this->t($key.'.'.$form, ['%count%' => (string) $count] + $params);
    }

    public function date(\DateTimeInterface $at): string
    {
        return $at->format($this->t('date_format'));
    }

    public static function esc(mixed $v): string
    {
        return htmlspecialchars((string) ($v ?? '—'), \ENT_QUOTES, 'UTF-8');
    }

    /**
     * The whole email.
     *
     * @param string $accent the top bar and title colour
     * @param string $title  plain text, escaped here
     * @param string $lead   HTML, under the title
     * @param string $body   HTML, the sections
     * @param string $footer HTML, small print at the bottom
     */
    public function page(string $accent, string $site, string $title, string $lead, string $body, string $footer = ''): string
    {
        $font = self::FONT;
        $muted = self::MUTED;
        $title = self::esc($title);
        $brand = self::esc('Sentinelle · '.$site);
        $lang = $this->locale();
        $footer = '' !== $footer ? '<tr><td style="padding:16px 24px 24px;font-size:12px;line-height:1.5;color:'.$muted.';border-top:1px solid '.self::LINE.'">'.$footer.'</td></tr>' : '';

        return <<<HTML
            <!DOCTYPE html>
            <html lang="{$lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>{$title}</title></head>
            <body style="margin:0;padding:0;background:#f1f5f9;-webkit-text-size-adjust:100%">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9"><tr><td align="center" style="padding:24px 12px">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:12px;border-top:5px solid {$accent};font-family:{$font};color:#0f172a">
            <tr><td style="padding:20px 24px 4px;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:{$muted}">{$brand}</td></tr>
            <tr><td style="padding:0 24px 8px"><h1 style="margin:0;font-size:20px;line-height:1.3;color:{$accent}">{$title}</h1></td></tr>
            <tr><td style="padding:0 24px 8px;font-size:15px;line-height:1.5">{$lead}</td></tr>
            <tr><td style="padding:8px 24px 16px">{$body}</td></tr>
            {$footer}
            </table>
            </td></tr></table>
            </body></html>
            HTML;
    }

    /** A coloured box (the breach banner, the "nothing got through" note). */
    public static function note(string $html, string $bg, string $fg): string
    {
        return '<div style="background:'.$bg.';color:'.$fg.';padding:12px 14px;border-radius:8px;font-size:14px;line-height:1.5;margin:0 0 16px">'.$html.'</div>';
    }

    public static function heading(string $text): string
    {
        return '<h2 style="margin:20px 0 8px;font-size:15px;line-height:1.3;color:#0f172a">'.$text.'</h2>';
    }

    /**
     * A label / value table: a narrow label column that wraps, so it reads on a phone without the
     * media queries some mail clients drop.
     *
     * @param array<string, string> $rows label (escaped here) => value (HTML)
     */
    public static function facts(array $rows, ?string $hot = null): string
    {
        $out = '';
        foreach ($rows as $label => $value) {
            $out .= '<tr><td valign="top" style="padding:8px 12px 8px 0;width:30%;font-size:13px;color:'.self::MUTED.';border-bottom:1px solid '.self::LINE.'">'.self::esc($label).'</td>'
                .'<td valign="top" style="padding:8px 0;font-size:13px;font-family:'.self::MONO.';word-break:break-all;border-bottom:1px solid '.self::LINE.($hot === $label ? ';color:#b91c1c;font-weight:bold' : '').'">'.$value.'</td></tr>';
        }

        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">'.$out.'</table>';
    }

    /**
     * A table with headers. Cells are HTML; a cell is numeric (right-aligned) when its column
     * index is in $numeric.
     *
     * @param list<string>       $head  escaped here
     * @param list<list<string>> $rows
     * @param list<int>          $numeric
     * @param list<string>       $rowStyles one per row, optional
     */
    public static function table(array $head, array $rows, array $numeric = [], array $rowStyles = []): string
    {
        $th = '';
        foreach ($head as $i => $h) {
            $th .= '<th align="'.(\in_array($i, $numeric, true) ? 'right' : 'left').'" style="padding:6px 8px 6px 0;font-size:12px;font-weight:normal;color:'.self::MUTED.';border-bottom:1px solid '.self::LINE.'">'.self::esc($h).'</th>';
        }
        $tr = '';
        foreach ($rows as $r => $cells) {
            $tr .= '<tr style="'.($rowStyles[$r] ?? '').'">';
            foreach ($cells as $i => $cell) {
                $num = \in_array($i, $numeric, true);
                $tr .= '<td'.($num ? ' align="right"' : '').' valign="top" style="padding:7px 8px 7px 0;font-size:13px;border-bottom:1px solid '.self::LINE.($num ? ';font-variant-numeric:tabular-nums;white-space:nowrap' : ';word-break:break-word').'">'.$cell.'</td>';
            }
            $tr .= '</tr>';
        }

        return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 8px">'.($th ? '<tr>'.$th.'</tr>' : '').$tr.'</table>';
    }

    public static function mono(string $escaped): string
    {
        return '<span style="font-family:'.self::MONO.';word-break:break-all">'.$escaped.'</span>';
    }

    public static function muted(string $html): string
    {
        return '<span style="color:'.self::MUTED.'">'.$html.'</span>';
    }
}
