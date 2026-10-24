<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\Service;

use Acencyril\SentinelleBundle\Entity\BlockedIp;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The security alert email.
 *
 * In the original application this lived inside a general-purpose notification
 * service, next to sign-up messages that depended on the project's own business
 * entities. A bundle carrying that would have required those entities from
 * every application installing it.
 *
 * The message used to end with "add a deny rule to your web server config and
 * reload" — true before automatic blocking existed. Since then `autoBlock()`
 * runs just before the mail goes out, so the wording asked someone woken at
 * three in the morning to redo by hand what had already happened on its own.
 * It now states the actual situation: blocked until such a date, or not blocked
 * and why.
 *
 * Since 0.4: the alert carries what the address did in the last 48 hours, and it is only sent
 * when it matters. An address already blocked whose tries all failed sends nothing
 * (`alert.quiet_when_blocked`, on by default): scanners probe every site all day, and those
 * emails buried the ones that counted. When a sensitive address was answered with a 2xx, the
 * email turns red, top priority, "POSSIBLE BREACH" in the subject. The quiet blocks are
 * counted in the daily digest (sentinelle:digest).
 */
class SecurityAlert
{
    public function __construct(
        private MailerInterface $mailer,
        private LoggerInterface $logger,
        private UrlGeneratorInterface $router,
        private string $recipient,
        private string $sender,
        private string $senderName,
        private string $siteName,
        private ?IpHistory $history = null,
        private bool $quietWhenBlocked = true,
    ) {
    }

    /**
     * @param array{reason:string,detail:?string,ip:string,path:string,method:string,query:?string,status:int,user_agent:?string} $context
     */
    public function notify(array $context, ?BlockedIp $blocked = null): void
    {
        $esc = static fn (?string $v): string => htmlspecialchars((string) ($v ?? '—'), \ENT_QUOTES, 'UTF-8');
        $history = $this->history?->of($context['ip']) ?? [];
        $served = IpHistory::served($history);
        if ($this->quietWhenBlocked && null !== $blocked && !$served) {
            return;
        }

        $rows = [
            'Pattern' => $esc($context['detail'] ?? null),
            'IP' => $esc($context['ip']),
            'Request' => $esc($context['method'].' '.$context['path']),
            'Query' => $esc($context['query'] ?? null),
            'Response' => $esc((string) $context['status']),
            'User agent' => $esc($context['user_agent'] ?? null),
            'Date' => $esc((new \DateTimeImmutable())->format('Y-m-d H:i:s')),
        ];

        $rowsHtml = '';
        foreach ($rows as $label => $value) {
            $rowsHtml .= '<tr>'
                .'<td style="padding:6px 12px 6px 0;color:#64748b;white-space:nowrap;vertical-align:top">'.$label.'</td>'
                .'<td style="padding:6px 0;font-family:monospace;word-break:break-all">'.$value.'</td>'
                .'</tr>';
        }

        // The actual state of the block, not an out-of-date instruction.
        if (null === $blocked) {
            $footer = 'This IP was <strong>not</strong> blocked automatically '
                .'(allowlisted, protected provider, or exempt path).';
        } elseif ($blocked->isPermanent()) {
            $footer = 'This IP is blocked <strong>permanently</strong>.';
        } else {
            $footer = 'This IP is blocked until <strong>'
                .$blocked->getExpiresAt()->format('Y-m-d H:i').'</strong>.';
        }

        try {
            $link = $this->router->generate('sentinelle_activity', [],
                UrlGeneratorInterface::ABSOLUTE_URL);
            $footer .= ' <a href="'.$link.'">See the log and unblock it</a>.';
        } catch (\Throwable) {
            // Without a configured domain, ABSOLUTE_URL throws. An alert with
            // no link is still useful; an alert that never leaves because the
            // router does not know the hostname protects nobody.
        }

        $subject = $served
            ? sprintf('🔴🔴 POSSIBLE BREACH %s — %s (%s)', $this->siteName, $context['reason'], $context['ip'])
            : sprintf('🚨 Security alert %s — %s (%s)', $this->siteName, $context['reason'], $context['ip']);
        $banner = $served
            ? '<div style="background:#7f1d1d;color:#fff;padding:14px;text-align:center;font-weight:900;font-size:16px">🔴 '.\count($served).' sensitive address(es) answered 2xx to this IP: see the red rows below. Data may have left.</div>'
            : ($this->history ? '<div style="background:#ecfdf5;color:#065f46;padding:10px 14px;font-size:13px">✓ None of its requests to a sensitive address succeeded in the last 48 hours.</div>' : '');
        $historyHtml = $this->history ? '<h3 style="font-size:14px;margin:16px 0 6px">Its last '.\count($history).' requests (48 h)</h3>'.IpHistory::html($history) : '';

        $this->send($subject, $served ? Email::PRIORITY_HIGHEST : Email::PRIORITY_HIGH, <<<HTML
            <div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:16px">
              <div style="background:#b91c1c;color:#fff;padding:16px;border-radius:8px 8px 0 0;text-align:center">
                <strong style="font-size:18px">🚨 {$esc($context['reason'])}</strong>
              </div>
              {$banner}
              <div style="background:#fff;padding:16px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
                <table style="width:100%;font-size:13px">{$rowsHtml}</table>
                <p style="font-size:12px;color:#64748b;margin:16px 0 0">{$footer}<br>
                At most one alert per IP per hour.</p>
                {$historyHtml}
              </div>
            </div>
            HTML);
    }

    private function send(string $subject, int $priority, string $html): void
    {
        try {
            $email = (new Email())
                ->from(new Address($this->sender, $this->senderName))
                ->to($this->recipient)
                ->priority($priority)
                ->subject($subject)
                ->html($html);
            if (Email::PRIORITY_HIGHEST === $priority) {
                $email->getHeaders()->addTextHeader('Importance', 'high');
            }
            $this->mailer->send($email);
        } catch (\Throwable $e) {
            // An alarm that breaks the site destroys more than it defends.
            $this->logger->warning('Security alert not sent', [
                'subject' => $subject, 'error' => $e->getMessage(),
            ]);
        }
    }
}