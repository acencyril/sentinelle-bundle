# Changelog

All notable changes to Sentinelle.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [0.5.1] — 2026-10-27

### Changed
- **The dashboard looks good by default and blends into any admin.** Summary tiles for the last
  24 hours (addresses blocked now, requests refused, exploitation attempts, probes, sensitive
  answers served, human passes, page views), each opening the log filtered on its kind; every
  kind as a pill; readable tables with a header row, zebra rows and hover; status pills in words
  and colour; a badge saying whether Sentinelle is in dry-run.
- Every colour, font and radius is a `--sentinelle-*` custom property (documented in the README,
  "The dashboard's look"). The defaults derive from the page's text colour, so the dashboard
  reads on a light and on a dark admin alike, in the host's font. No inline colour anywhere, no
  external resource, no JavaScript.
- Tables scroll inside their own frame: no sideways page scroll on a phone.
- The dashboard is in English and French (the request's locale), domain `sentinelle`, keys
  `dashboard.*`, the application's translations first; the flash messages too. Without the
  translation component, the bundled texts are used.
- The markup can be overridden in parts: blocks `sentinelle_content` and `sentinelle_styles`.

### Fixed
- A log row whose `meta` column is NULL no longer breaks the dashboard.

## [0.5.0] — 2026-10-26

### Added
- **Human pass** (`blocking.human_pass`, on by default): a blocked address asking for an HTML
  page (GET, `Accept: text/html`, not a sensitive path) gets a small 403 page, "Your network was
  blocked after suspicious requests", with a button that runs a light proof of work in the
  browser (plain JavaScript, no third-party captcha, no external request). Solved, it sets a
  signed cookie (HMAC with `kernel.secret`, bound to the address, 24 hours, `HttpOnly`,
  `SameSite=Lax`) that lets that browser through while the address stays blocked for everything
  else. Sensitive paths (`.env`, `.git`, keys, dumps…) stay closed even with a pass. Attempts are
  rate-limited, a challenge works once, and a pass used for an attack is withdrawn from the
  address. English and French texts (domain `sentinelle`). Passes are logged as `human_pass` and
  counted on the dashboard. It protects the people behind a shared address (an office, a school,
  a mobile carrier) blocked because of one infected machine.
- `blocking.durations`: automatic block length by strike, the last value repeating. The default
  is unchanged: `['+24 hours', '+7 days', 'permanent']`.
- A warning in the logs (once per process) when requests come from a private or loopback
  address with `X-Forwarded-For` but no trusted proxies are configured.
- `SECURITY.md`: report vulnerabilities privately through GitHub.

### Changed
- README: install starts with `composer require` (the Flex recipe registers the bundle and
  creates the configuration); the manual `bundles.php` step is a "Without Flex" note. "Behind a
  reverse proxy" moved up, with the `trusted_proxies` configuration.

### Fixed
- Dashboard: the "IP blocked" label was dark grey (#1f2937), unreadable on dark admin themes; it
  now follows the text colour.

See [UPGRADE.md](UPGRADE.md).

## [0.4.1] — 2026-10-26

### Fixed
- Installs on Symfony 8: DoctrineBundle 3 is allowed (`^2.11 || ^3.0`).

## [0.4.0] — 2026-10-24

### Added
- **Breach watch** (`breach_watch`, on by default): looks at the answers, not only the attempts.
  A sensitive file served with a 2xx (.env, .git, keys, dumps, logs, debug tools) or a secret
  in a response blocks the address for 30 days and sends a red, top-priority alert at once,
  with what to do now.
- Every alert carries what the address did in the last 48 hours (`IpHistory`).
- `sentinelle:digest`: one email a day with the addresses blocked, by reason, and any
  sensitive answer served. Nothing happened: nothing is sent. Run it from cron or a scheduler.
- Tests (PHPUnit).

### Changed
- **Quiet when blocked** (`alert.quiet_when_blocked`, on by default): no email for an address
  already blocked whose tries all failed. Scanners probe every site all day; on one production
  site those emails were about 200 a week and buried the ones that mattered. They are counted
  in the digest. Set it to `false` to keep the old behaviour.
- An alert whose address got a sensitive answer is red: "🔴🔴 POSSIBLE BREACH" subject, highest
  priority, the served rows in red.

## [0.3.1] — 2026-09-01

### Fixed
- Remaining French strings in the check command, the configuration descriptions
  and the missing-configuration error.
- `branch-alias` aligned on `0.3.x-dev`.

### Note for anyone upgrading from 0.2

⚠ `SENTINELLE_ALERTE_EMAIL` became `SENTINELLE_ALERT_EMAIL`, and **Flex will not
rename it for you**. It never overwrites an existing `.env` entry, so the old
variable stays and the new one is never added. You get
`Environment variable not found: "SENTINELLE_ALERT_EMAIL"` with no hint as to
why. Rename it by hand.

## [0.3.0] — 2026-09-01

### ⚠ Breaking

The whole codebase moved to English. **Configuration keys, table names, route
names and the admin path all changed.** Upgrading from 0.2 requires editing your
configuration and running a migration.

There is no automatic upgrade path, and that is deliberate: silently renaming
tables under a running site is worse than an error message that tells you what
to do.

#### Configuration keys

| 0.2 | 0.3 |
|---|---|
| `essai` | `dry_run` |
| `alerte` | `alert` |
| `alerte.destinataire` | `alert.recipient` |
| `alerte.expediteur` | `alert.sender` |
| `alerte.nom_expediteur` | `alert.sender_name` |
| `alerte.nom_du_site` | `alert.site_name` |
| `alerte.repit` | `alert.cooldown` |
| `acces` | `access` |
| `acces.prefixe` | `access.prefix` |
| `acces.gabarit_parent` | `access.parent_template` |
| `acces.route_retour` | `access.back_route` |
| `seuils` | `thresholds` |
| `seuils.rafale` | `thresholds.burst` |
| `seuils.rafale_fenetre` | `thresholds.burst_window` |
| `seuils.bruteforce_fenetre` | `thresholds.bruteforce_window` |
| `jamais_bloquer` | `never_block` |
| `jamais_bloquer.chemins` | `never_block.paths` |
| `jamais_bloquer.prestataires` | `never_block.providers` |
| `motifs_critiques` | `critical_patterns` |
| `ignorer` | `ignore` |

#### Environment variable

`SENTINELLE_ALERTE_EMAIL` → `SENTINELLE_ALERT_EMAIL`

#### Tables

`sentinelle_visite` → `sentinelle_visit`
`sentinelle_ip_bloquee` → `sentinelle_blocked_ip`

Run `doctrine:migrations:diff` then `migrate`. **The generated migration drops
the old tables** — export your data first if you want to keep it.

#### Commands

`sentinelle:purger` → `sentinelle:purge`
`sentinelle:verifier` → `sentinelle:check`

#### Routes and admin path

`/admin/activite` → `/admin/activity`, and the route names
`sentinelle_activite`, `_bloquer`, `_debloquer` become `sentinelle_activity`,
`_block`, `_unblock`.

### Changed
- Class names: `IpBloquee` → `BlockedIp`, `Visite` → `Visit`,
  `AlerteSecurite` → `SecurityAlert`, `ActiviteController` → `ActivityController`,
  and their repositories accordingly.
- Log messages, dashboard labels, email contents and command output are now in
  English.

### Note
Inline comments remain in French. They explain *why* each safeguard exists, and
several come from real incidents — that reasoning is the most valuable part of
this code, and translating it badly would be worse than leaving it.

## [0.2.1] — 2026-08-31

### Fixed
- PHP constraint lowered to `>=8.1`. Nothing in the code required 8.2, and
  Symfony 6.4 runs on 8.1: asking for more excluded projects for no reason.
- `branch-alias` aligned on `0.2.x-dev`.

## [0.2.0] — 2026-08-31

### Added
- **Dry-run mode** (`essai: true`): Sentinelle detects, logs and alerts, but
  blocks nothing. Every avoided block is logged along with what would have been
  decided, duration included.

  > *A mechanism you cannot try without risk will not be tried — it will be
  > installed and switched off at the first incident.*

- **`sentinelle:verifier` command**: checks that the cache answers, that both
  tables exist, that the allowlist is not empty and that alerts have a valid
  recipient.

  Each of these is a way the mechanism can fail **silently** — without a cache,
  counters always return zero, no threshold ever fires, and detection is
  disarmed without anything saying so.

- `CHANGELOG.md` and `CONTRIBUTING.md`.
- Dashboard screenshot in both READMEs.

### Changed
- **Symfony 8** compatibility.
- English README by default, French in `README.fr.md`. *Packagist displays
  `README.md`, and the PHP ecosystem is English-speaking.*
- Both README hooks aligned on the package description.

## [0.1.2] — 2026-08-31

### Fixed
- An import left on the old namespace after extraction, causing a
  `ClassNotFoundError` on every request — and not a single line logged.
- The whole body of the logger is now protected, not just the write. On
  `kernel.terminate` the response has already been sent: an exception went
  nowhere, the site answered 200 and the table stayed empty.

  > *A logger that can fail silently is worse than no logger at all: you believe
  > it is running.*

- The controller no longer extends `AbstractController`, which expects a
  restricted container built by autoconfiguration — a mechanism disabled in a
  bundle where everything is declared by hand. Dependencies are now injected
  explicitly.
- Journal filter: `tout` and `all` meant the same thing without knowing about
  each other, a leftover from a partial translation.
- The matched pattern and the query string are shown in the journal. Without
  them, two exploitation attempts appeared as two identical rows.

## [0.1.1] — 2026-08-31

### Fixed
- `getPath()`: without it, `@SentinelleBundle/config/…` pointed at
  `src/config/`, and neither routes nor services would load.

## [0.1.0] — 2026-08-31

First release, extracted from an application running in production.

### Fixed before release
- `Bundle` instead of `AbstractBundle`: the latter carries its own configuration
  and **silently ignores** any extension class written alongside it. The bundle
  loaded perfectly, with an empty configuration tree.

### Features
- Logs every request on `kernel.terminate`, after the response has been sent —
  which is also the only moment the status code is known.
- Detection: code execution, SQL injection, directory traversal, Log4Shell,
  deserialisation; probes; brute force.
- Progressive blocking: 24 hours, 7 days, then permanent. Blocks expire, and
  that is deliberate — most scanning addresses are compromised machines or
  recycled cloud addresses.
- **Refuses to block a critical provider**, automatically and manually,
  recognised by reverse DNS.
- Email alert, at most one per address per hour.
- Dashboard showing each address's owner.
- `sentinelle:purger` command, without which strike counters never reset.