<?php

declare(strict_types=1);

namespace Acencyril\SentinelleBundle\EventListener;

use Acencyril\SentinelleBundle\Service\HumanPass;
use Acencyril\SentinelleBundle\Service\IpBlocklist;
use Acencyril\SentinelleBundle\Service\IpHistory;
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
        $esc = static fn ($v): string => htmlspecialchars((string) ($v ?? '—'), \ENT_QUOTES, 'UTF-8');
        $what = $leak ? 'A secret left in the response: '.$esc(substr($leak, 0, 24)).'…' : 'A sensitive file was served.';
        $rows = '';
        foreach (['Served' => $request, 'Answer' => (string) $status, 'IP' => $ip, 'User agent' => $agent, 'Time (UTC)' => gmdate('Y-m-d H:i:s'),
            'Block' => $blocked ? 'IP blocked for 30 days' : 'IP NOT blocked (dry run, allowlist or protected provider): block it by hand'] as $k => $v) {
            $rows .= '<tr><td style="padding:6px 10px 6px 0;color:#fecaca;white-space:nowrap;vertical-align:top">'.$k.'</td><td style="padding:6px 0;font-family:monospace;word-break:break-all;color:#fff;font-weight:bold">'.$esc($v).'</td></tr>';
        }
        $site = $esc(mb_strtoupper($this->siteName));
        $html = <<<HTML
            <div style="font-family:sans-serif;max-width:640px;margin:0 auto;background:#7f1d1d;padding:4px;border-radius:10px">
              <div style="background:#dc2626;color:#fff;padding:22px 18px;border-radius:8px 8px 0 0;text-align:center">
                <div style="font-size:22px;font-weight:900;margin-top:8px">🔴 PROBABLE BREACH — {$site}</div>
                <div style="font-size:15px;margin-top:6px">{$what}<br>Not an attempt: <strong>the answer went out</strong>.</div>
              </div>
              <div style="background:#991b1b;padding:14px 18px"><table style="width:100%;font-size:13px">{$rows}</table></div>
              <div style="background:#fff;padding:16px 18px;border-radius:0 0 8px 8px">
                <strong style="color:#b91c1c">Now</strong>
                <ol style="margin:8px 0 0;padding-left:20px;line-height:1.6">
                  <li>Open the red row below: it is what the attacker received.</li>
                  <li>Treat <strong>every key as stolen</strong>: rotate APP_SECRET, the database password and every API key in your environment.</li>
                  <li>Fix and redeploy, then check that the address answers 404.</li>
                  <li>If personal data may have left: in the EU, the authority must be notified within 72 hours.</li>
                </ol>
                <h3 style="font-size:14px;margin:18px 0 6px">Everything this IP did in 48 hours</h3>
                {$this->historyHtml($ip)}
              </div>
            </div>
            HTML;
        try {
            $email = (new Email())->from(new Address($this->sender, $this->siteName.' — ALERT'))->to($this->recipient)
                ->priority(Email::PRIORITY_HIGHEST)
                ->subject(sprintf('🔴🔴 PROBABLE BREACH — %s: %s served (%d) to %s', $this->siteName, $request, $status, $ip))
                ->html($html);
            $email->getHeaders()->addTextHeader('Importance', 'high');
            $this->mailer->send($email);
        } catch (\Throwable $e) {
            $this->logger->critical('Sentinelle breach alert not sent: '.$e->getMessage());
        }
    }

    private function historyHtml(string $ip): string
    {
        return IpHistory::html($this->history->of($ip));
    }
}
