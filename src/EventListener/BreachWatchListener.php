<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\HumanPass;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpHistory;
use Acencyril\SentinelleBundle\Service\Mail;
use Acencyril\SentinelleBundle\Service\Sensitive;
use Acencyril\SentinelleBundle\Service\SiteEventLogger;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;

/**
 * The alarm that matters: not "someone tried", but "it worked".
 *
 * Looks at the ANSWER: a sensitive file (.env, .git, keys, dumps, logs, debug tools) served
 * with a 2xx, or a response carrying a secret (APP_SECRET=, a private key, a live API key).
 * Either one means data has probably left: the address is blocked 30 days at once and a red,
 * top-priority email goes out with what it did before and what to do now. Runs on
 * kernel.terminate after the activity listener, so the history includes this very request.
 * One email per address and path per 10 minutes. Off with `breach_watch: false`. The email
 * leaves only while `breach` is in `alert.immediate` (the default); otherwise the breach is
 * still blocked, logged and listed first in the daily digest.
 */
final class BreachWatchListener
{
    public function __construct(
        private MailerInterface $mailer,
        private IpBlocklist $blocklist,
        private IpHistory $history,
        private SiteEventLogger $events,
        private CacheItemPoolInterface $cache,
        private LoggerInterface $logger,
        private string $recipient,
        private string $sender,
        private string $siteName,
        private string $environment,
        private ?HumanPass $humanPass = null,
        /** @var list<string> */
        private array $immediate = ['breach'],
        private Mail $mail = new Mail(),
    ) {
    }

    public function onKernelTerminate(TerminateEvent $event): void
    {
        try {
            $this->inspect($event);
        } catch (\Throwable $e) {
            // an alarm that breaks the site protects nobody
            $this->logger->error('Sentinelle breach watch failed: '.$e->getMessage());
        }
    }

    private function inspect(TerminateEvent $event): void
    {
        $request = $event->getRequest();
        $response = $event->getResponse();
        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            return;
        }
        $path = $request->getPathInfo();
        if ('prod' !== $this->environment && preg_match('#^/(_profiler|_wdt)#', $path)) {
            return;
        }
        $sensitive = Sensitive::isSensitivePath($path);
        $leak = $response instanceof StreamedResponse || $response instanceof BinaryFileResponse ? null : Sensitive::secretIn((string) $response->getContent());
        if (!$sensitive && null === $leak) {
            return;
        }

        $ip = $request->getClientIp() ?? 'unknown';
        $this->events->log('breach_served', $path, $ip, $request->headers->get('User-Agent'), ['method' => $request->getMethod(), 'status' => $status, 'secret' => null !== $leak]);
        $blocked = $this->blocklist->block($ip, 'Probable breach: '.$path, 'auto', '+30 days');
        $this->humanPass?->revoke($ip);
        $this->logger->critical('Sentinelle: sensitive answer served', ['ip' => $ip, 'path' => $path, 'status' => $status, 'secret' => null !== $leak]);

        if (!\in_array('breach', $this->immediate, true)) {
            return;
        }
        $item = $this->cache->getItem('sentinelle_breach_'.sha1($ip.$path));
        if ($item->isHit()) {
            return;
        }
        $this->cache->save($item->set(1)->expiresAfter(600));
        $this->send($ip, $request->getMethod().' '.$path.($request->getQueryString() ? '?'.$request->getQueryString() : ''), $status, $leak, (string) $request->headers->get('User-Agent'), null !== $blocked);
    }

    private function send(string $ip, string $request, int $status, ?string $leak, string $agent, bool $blocked): void
    {
        $m = $this->mail;
        $esc = Mail::esc(...);
        $what = $leak ? $esc($m->t('breach.secret', ['%secret%' => substr($leak, 0, 24)])) : $esc($m->t('breach.file'));
        $rows = [
            $m->t('breach.row.served') => $esc($request),
            $m->t('breach.row.status') => $esc((string) $status),
            $m->t('alert.row.ip') => $esc($ip),
            $m->t('alert.row.user_agent') => $esc($agent ?: null),
            $m->t('breach.row.time') => $esc(gmdate('Y-m-d H:i:s')),
            $m->t('breach.row.block') => $esc($blocked ? $m->t('breach.blocked') : $m->t('breach.not_blocked')),
        ];
        $steps = '';
        foreach (['1', '2', '3', '4'] as $i) {
            $steps .= '<li style="margin:0 0 6px">'.$m->t('breach.step'.$i).'</li>';
        }
        $html = $m->page(
            '#b91c1c',
            $this->siteName,
            '🔴 '.$m->t('breach.title'),
            $what.'<br><strong>'.$esc($m->t('breach.not_attempt')).'</strong>',
            Mail::note('<strong>'.$esc($m->t('breach.now')).'</strong><ol style="margin:8px 0 0;padding-left:20px;line-height:1.5">'.$steps.'</ol>', '#fef2f2', '#7f1d1d')
                .Mail::facts($rows, $m->t('breach.row.served'))
                .Mail::heading($esc($m->t('breach.history')))
                .IpHistory::html($this->history->of($ip), $m),
        );
        try {
            $email = (new Email())->from(new Address($this->sender, $this->siteName.' — '.$m->t('breach.from')))->to($this->recipient)
                ->priority(Email::PRIORITY_HIGHEST)
                ->subject($m->t('breach.subject', ['%site%' => $this->siteName, '%request%' => $request, '%status%' => (string) $status, '%ip%' => $ip]))
                ->html($html);
            $email->getHeaders()->addTextHeader('Importance', 'high');
            $this->mailer->send($email);
        } catch (\Throwable $e) {
            $this->logger->critical('Sentinelle breach alert not sent: '.$e->getMessage());
        }
    }
}
