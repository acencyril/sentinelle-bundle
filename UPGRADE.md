# Upgrading

## From 0.5 to 0.6

**Behaviour change: only breaches are emailed at once.** A breach is a sensitive
address answered with a 2xx, or a secret in a response. Automated scans,
exploitation attempts and brute force are still detected, blocked and logged,
but no longer emailed one by one: they are counted in `sentinelle:digest`.

1. Make sure `sentinelle:digest` runs once a day (cron, Symfony Scheduler,
   Messenger worker…). Without it, held alerts are only visible on the
   dashboard. It sends nothing on a day with nothing to report.
2. To keep some kinds immediate:
   `sentinelle.alert.immediate: [breach, exploitation]`.
   To restore an email per alert: `immediate: all` and
   `quiet_when_blocked: false`.

No schema change. Every alert now also writes a row of type `alert` in
`sentinelle_visit` (one per address per cooldown, like the emails it replaces).
`SecurityAlert::notify()` now returns whether an email went out (`bool`).

`quiet_when_blocked` now actually applies: the alert used to be sent without the
block it had just caused, so it always read "not blocked automatically" and was
never quiet.

## From 0.5.0 to 0.5.1

Nothing to change. The dashboard has a new look and is translated (English and
French). If you had styled its old markup (bare `table`, `h2`, inline colours) from
your admin's stylesheet, remove those rules and map the `--sentinelle-*` properties
to your palette instead (README, "The dashboard's look"). Its layout must still
define the `title` and `body` blocks.

## From 0.4 to 0.5

Nothing to change in your configuration, and no schema change.

What changes for your visitors:

- **A blocked address asking for an HTML page now gets a challenge page**
  (403, "Your network was blocked after suspicious requests") instead of a bare
  `Forbidden`. A browser that solves its proof of work gets a 24-hour cookie
  bound to the address and is let through; sensitive paths stay closed for
  everyone. Scripts and non-HTML requests still get a bare 403. This also applies
  to addresses already blocked, permanent ones included. To keep the old
  behaviour: `blocking.human_pass: false`.
- The pass cookie is signed with `kernel.secret`. Changing the secret withdraws
  every pass, which is harmless: browsers are offered the challenge again.
- If your site sends a strict `Content-Security-Policy` on every response from a
  `kernel.response` listener, make sure it does not replace the one Sentinelle
  sets on the challenge page (a nonce for its inline script and style).

What does not change:

- Automatic blocks still last 24 hours, then 7 days, then are permanent from the
  third strike. This is now configurable with `blocking.durations`, for example
  `['+24 hours', '+7 days']` to never block permanently (the last value repeats).
- Manual blocks are still permanent unless a duration is given.
- Existing blocks are left as they are.

A new event type, `human_pass`, appears in `sentinelle_visit` and on the
dashboard.

## From 0.2 to 0.3

See the 0.3.0 entry of [CHANGELOG.md](CHANGELOG.md).
