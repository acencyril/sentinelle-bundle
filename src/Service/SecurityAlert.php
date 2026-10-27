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
 *
 * Since 0.6: an alert has a kind (KINDS) and only the kinds listed in `alert.immediate` leave at
 * once; by default only `breach`, a sensitive address actually answered with a 2xx. The others
 * are recorded (an `alert` row) and counted in the daily digest. An email for every scanner
 * trains you to ignore Sentinelle's emails, and then you miss the one that says it got through.
 *
 * Since 0.7.1: in the language of `mail.locale` (en, fr), laid out by Mail.
 */
class SecurityAlert
{
    /**
     * What an alert can be about. `breach`: a sensitive address was answered with a 2xx (data
     * may have left). `exploitation`: a request carrying an exploit (RCE, SQL injection,
     * traversal, Log4Shell…). `brute_force`: repeated access denials. `scan`: a burst of probes.
     */
    public const KINDS = ['breach', 'exploitation', 'brute_force', 'scan'];

    /** The default `alert.immediate`: only what actually got through. */
    public const IMMEDIATE_DEFAULT = ['breach'];

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
        /** @var list<string> kinds emailed at once; the others wait for the digest */
        private array $immediate = self::IMMEDIATE_DEFAULT,
        private Mail $mail = new Mail(),
    ) {
    }

    /** The kind of an alert from its reason, as SiteEventLogger words it. */
    public static function kindOf(string $reason): string
    {
        return match (true) {
            str_starts_with($reason, 'Exploitation') => 'exploitation',
            str_starts_with($reason, 'Likely brute force') => 'brute_force',
            str_contains($reason, 'BREACH'), str_starts_with($reason, 'Probable breach') => 'breach',
            default => 'scan',
        };
    }

    public function isImmediate(string $kind): bool
    {
        return \in_array($kind, $this->immediate, true);
    }

    /**
     * Sends the alert if its kind is immediate. Returns whether an email went out; when it did
     * not, the alert waits for the digest.
     *
     * @param array{reason:string,detail:?string,ip:string,path:string,method:string,query:?string,status:int,user_agent:?string,kind?:string} $context
     */
    public function notify(array $context, ?BlockedIp $blocked = null): bool
    {
        $kind = $context['kind'] ?? self::kindOf($context['reason']);
        // The history is only read when it can change the answer: an address whose earlier
        // requests were served sensitive answers turns any alert into a breach.
        if (!$this->isImmediate($kind) && !$this->isImmediate('breach')) {
            return false;
        }
        $history = $this->history?->of($context['ip']) ?? [];
        $served = IpHistory::served($history);
        if (!$this->isImmediate($served ? 'breach' : $kind)) {
            return false;
        }
        if ($this->quietWhenBlocked && null !== $blocked && !$served) {
            return false;
        }

        $m = $this->mail;
        $esc = Mail::esc(...);
        $kindLabel = $m->t('kind.'.$kind);
        $rows = [
            $m->t('alert.row.detail') => $esc($context['detail'] ?? null),
            $m->t('alert.row.ip') => $esc($context['ip']),
            $m->t('alert.row.request') => $esc($context['method'].' '.$context['path']),
            $m->t('alert.row.query') => $esc($context['query'] ?? null),
            $m->t('alert.row.status') => $esc((string) $context['status']),
            $m->t('alert.row.user_agent') => $esc($context['user_agent'] ?? null),
            $m->t('alert.row.date') => $esc($m->date(new \DateTimeImmutable())),
        ];

        // The actual state of the block, not an out-of-date instruction.
        if (null === $blocked) {
            $state = $m->t('alert.not_blocked');
        } elseif ($blocked->isPermanent()) {
            $state = $m->t('alert.blocked_permanently');
        } else {
            $state = $m->t('alert.blocked_until', ['%date%' => '<strong>'.$esc($m->date($blocked->getExpiresAt())).'</strong>']);
        }

        $link = '';
        try {
            $link = ' <a href="'.$esc($this->router->generate('sentinelle_activity', [],
                UrlGeneratorInterface::ABSOLUTE_URL)).'" style="color:#1d4ed8">'.$esc($m->t('alert.link')).'</a>';
        } catch (\Throwable) {
            // Without a configured domain, ABSOLUTE_URL throws. An alert with
            // no link is still useful; an alert that never leaves because the
            // router does not know the hostname protects nobody.
        }

        $params = ['%site%' => $this->siteName, '%kind%' => $kindLabel, '%ip%' => $context['ip']];
        $subject = $served ? $m->t('alert.subject_breach', $params) : $m->t('alert.subject', $params);
        $banner = $served
            ? Mail::note('🔴 '.$esc($m->n('alert.served', \count($served))), '#7f1d1d', '#ffffff')
            : ($this->history ? Mail::note('✓ '.$esc($m->t('alert.nothing_served')), '#ecfdf5', '#065f46') : '');
        $historyHtml = $this->history ? Mail::heading($esc($m->n('alert.history', \count($history)))).IpHistory::html($history, $m) : '';

        $html = $m->page(
            $served ? '#991b1b' : '#b91c1c',
            $this->siteName,
            $served ? $m->t('alert.title_breach', ['%kind%' => $kindLabel]) : $kindLabel,
            $state.$link,
            $banner.Mail::facts($rows).$historyHtml,
            $esc($m->t('alert.footer')),
        );

        return $this->send($subject, $served ? Email::PRIORITY_HIGHEST : Email::PRIORITY_HIGH, $html);
    }

    private function send(string $subject, int $priority, string $html): bool
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

            return true;
        } catch (\Throwable $e) {
            // An alarm that breaks the site destroys more than it defends.
            $this->logger->warning('Security alert not sent', [
                'subject' => $subject, 'error' => $e->getMessage(),
            ]);

            return false;
        }
    }
}