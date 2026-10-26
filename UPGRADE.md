# Upgrading

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
