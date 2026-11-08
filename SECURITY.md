# Security policy

## Supported versions

Only the latest minor version receives security fixes.

Sentinelle runs on PHP 8.1 to 8.4 and Symfony 6.4, 7.x and 8.x, and every combination's oldest
and newest lines are tested on each push (see `.github/workflows/tests.yml`), as well as
`composer audit` on the dependencies.

| Version | Supported |
|---------|-----------|
| 0.7.x   | ✅        |
| < 0.7   | ❌        |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through GitHub: on this repository, open the **Security** tab
and click **Report a vulnerability**
(<https://github.com/acencyril/sentinelle-bundle/security/advisories/new>).

Include what you can: the affected version, the configuration, the steps to
reproduce, and what an attacker gains. You will get an answer within 72 hours.
Once a fix is released, the advisory is published with credit to you, unless
you prefer otherwise. A confirmed vulnerability is fixed within 7 days. This is
best effort: Sentinelle has a single maintainer, and the policy says so rather
than promise more.

## Versions

Sentinelle follows [SemVer](https://semver.org/). While it is in 0.x, a minor
version (0.7 → 0.8) may change behaviour or configuration: every such change is
in `CHANGELOG.md` and, when you have something to do, in `UPGRADE.md`. A patch
version (0.7.1 → 0.7.2) never does.

Ways around Sentinelle's own protections (getting a blocked address through,
reaching a sensitive path with a human pass, forging or replaying a pass,
blocking a protected provider) are in scope.

The disclosure policy for this bundle and for the sites that run it:
<https://mirelabs.fr/en/responsible-disclosure>.
