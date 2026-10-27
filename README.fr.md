# Sentinelle

**Il bloque les attaquants, jamais votre fournisseur de mail.**

Il journalise chaque requête, reconnaît les tentatives d'exploitation, ferme la
porte tout seul et vous prévient. Et il refuse de bannir une adresse dont votre
site dépend.

![Le tableau de bord de Sentinelle](docs/sentinelle-bundle.png)

*English documentation: [README.md](README.md)*

```bash
composer require acencyril/sentinelle-bundle
```

---

## Le problème

Un site en production reçoit des sondes en permanence. Des scanners cherchent
`/.env`, `/wp-login.php`, `/.git/config`. D'autres tentent des injections SQL,
des traversées de répertoire, du Log4Shell. La plupart n'aboutissent à rien —
mais on ne le sait qu'après coup, et seulement si on regarde.

Les réponses habituelles ont chacune leur défaut. Lire les journaux du serveur
web : personne ne le fait tous les jours. `fail2ban` : il travaille sur les
fichiers de log, hors de l'application, et ne sait rien de vos routes ni de vos
utilisateurs. Un pare-feu applicatif hébergé : il voit tout votre trafic, et il
coûte.

Sentinelle fait le travail **dans l'application**, où l'on sait qui est
authentifié, quelle route a répondu, et quel code HTTP est sorti.

---

## Ce qu'il fait

**Il enregistre tout**, pas seulement les attaques. Une tentative ne se reconnaît
pas seule : elle se reconnaît par contraste avec le trafic ordinaire. Sans les
pages vues, on n'a plus qu'une liste d'alarmes sans échelle, et l'on ne sait pas
si trois 404 sont un scan ou un lien mort.

**Il qualifie chaque requête** — page vue, page introuvable, accès refusé, sonde,
tentative d'exploitation — à partir du chemin, des paramètres et du code de
réponse.

**Il bloque tout seul**, progressivement : 24 heures au premier blocage, 7 jours
au deuxième, définitif au troisième (configurable).

**Il ne ferme jamais la porte aux personnes derrière une adresse bloquée.** Un
navigateur qui demande une page reçoit une preuve de travail en un clic au lieu
d'un refus sec, et passe ; les scripts et les chemins sensibles restent fermés.
Voir [Le laissez-passer](#le-laissez-passer--bloqué-mais-pas-enfermé).

**Il ne vous écrit tout de suite que quand quelque chose est passé** : un fichier
sensible ou un secret réellement servi avec un 2xx. Toutes les autres alertes
(scans, tentatives d'exploitation, force brute) sont comptées dans un seul
récapitulatif quotidien. Voir [Quand il vous écrit](#quand-il-vous-écrit).

**Il dit aux chercheurs où écrire** : `/.well-known/security.txt` (RFC 9116),
dont la date d'expiration se tient à jour toute seule. Et il envoie votre
Content-Security-Policy avec un nonce neuf à chaque page. Voir
[security.txt et Content-Security-Policy](#securitytxt-et-content-security-policy).

**Et il refuse de bloquer ce dont vous dépendez.** C'est la pièce qui manque
partout ailleurs, et celle qui justifie ce bundle.

---

## Quand il vous écrit

Par défaut, **un seul type d'alerte part tout de suite : `breach`**, une adresse
sensible (`.env`, `.git`, clés, dumps…) servie avec un 2xx, ou un secret trouvé
dans une réponse. Pas « quelqu'un a essayé » : la réponse est partie. Ce courriel
est rouge, en priorité maximale, et dit quoi faire maintenant.

Tout le reste est toujours détecté, bloqué et journalisé, puis **compté dans le
récapitulatif quotidien** (`sentinelle:digest`) : les alertes par type, les
requêtes hostiles, les adresses bloquées par motif et les dix adresses hostiles
les plus actives. Un jour sans rien à dire n'envoie rien.

Pourquoi : un site public est scanné toute la journée. Avec un courriel par
scanner, quelques sites font plus de cent alertes par semaine, toutes « bloquée,
rien servi ». On apprend à les ignorer, à les filtrer, à les archiver sans les
lire — et celle qui compte, *un fichier sensible a vraiment été servi*,
ressemble exactement aux cent autres. C'est la fatigue d'alerte qui fait rater
les vrais incidents. Une adresse à qui tout a été refusé ne demande rien de
vous ; une adresse à qui on a servi `.env`, si, dans l'heure.

Les types sont `breach`, `exploitation` (motifs d'exploitation : RCE, injection
SQL, traversée de répertoires, Log4Shell…), `brute_force` (refus d'accès
répétés) et `scan` (une rafale de sondages). Choisissez ceux qui vous écrivent
tout de suite :

```yaml
sentinelle:
    alert:
        immediate: [breach]                 # la valeur par défaut depuis la 0.6
        # immediate: [breach, exploitation] # aussi chaque tentative d'exploitation
        # immediate: all                    # le comportement d'avant la 0.6 : un courriel par alerte
```

Pour retrouver exactement les courriels d'avant la 0.6 : `immediate: all` et
`quiet_when_blocked: false` (sinon, une adresse déjà bloquée dont tous les essais
ont échoué reste silencieuse).

Chaque alerte, envoyée ou non, laisse une ligne `alert` dans le journal (son
type, le motif, si elle a été envoyée, si l'adresse a été bloquée) : c'est ce que
compte le récapitulatif, et le tableau de bord l'affiche comme un type à part.

**Planifiez le récapitulatif une fois par jour**, sinon les alertes retenues ne
se voient que dans le tableau de bord :

```
0 7 * * *  php /chemin/bin/console sentinelle:digest
```

`--dry-run` affiche les compteurs sans rien envoyer ; `--hours=48` élargit la
fenêtre.

Les e-mails sont en français ou en anglais : la langue `kernel.default_locale`
de l'application par défaut, ou celle que vous fixez (toute autre langue retombe
sur l'anglais) :

```yaml
sentinelle:
  mail:
    locale: fr
```

Chaque texte peut être reformulé dans vos traductions, domaine `sentinelle`, clés
`mail.*`. La mise en page est une simple carte, lisible sur téléphone, sans rien
charger de l'extérieur.

---

## Pourquoi ce dernier point compte

Ce bundle est né d'un incident. Une adresse est apparue dans le tableau de bord,
signalée comme suspecte après une erreur 401. Elle a été bloquée à la main, d'un
clic. C'était un serveur de Mailgun : **toute la réception de courriel du site
serait morte en silence**, et personne ne l'aurait su avant des heures.

Le 401 venait d'une clé de signature qui n'était pas encore arrivée dans
l'environnement du conteneur. Un incident de configuration, pas une attaque.

D'où trois garde-fous que Sentinelle applique :

**Chaque adresse porte le nom de son propriétaire**, résolu par DNS inverse.
Vous ne décidez plus devant une suite de chiffres.

**Les prestataires critiques sont refusés au blocage**, automatique *et* manuel.
Le bouton ne fonctionne pas, et il vous dit pourquoi.

**Certains chemins ne déclenchent jamais de blocage.** Un webhook qui répond 401
le temps qu'une clé arrive ne doit pas faire bannir celui qui l'appelle.

> Une protection qui casse une fonction du site détruit plus qu'elle ne défend.

---

## Le laissez-passer : bloqué, mais pas enfermé

Le blocage se fait par adresse, et **une adresse n'est pas une personne**.

**Pourquoi les blocages vont jusqu'au définitif.** La plupart des adresses qui
scannent sont des machines compromises ou des adresses cloud recyclées : le
premier blocage est donc court, 24 heures. Une adresse qui revient ensuite, puis
encore après 7 jours, le fait exprès, et le troisième blocage est définitif. Les
scanners obstinés restent dehors pour de bon, sans que personne ait à lire un
journal.

**Pourquoi cela ne suffit pas.** Beaucoup de gens partagent une même adresse
publique : un réseau d'entreprise, une école, un opérateur mobile (le CGNAT met
des milliers de téléphones derrière une poignée d'adresses). Une seule machine
infectée parmi eux sonde votre site, l'adresse est bloquée, parfois pour de bon,
et tous ceux qui sont derrière se retrouvent dehors. Ils n'ont rien fait.

**Les vrais navigateurs ont donc un passage.** Une adresse bloquée qui demande
une page (`GET`, `Accept: text/html`, hors chemin sensible) ne reçoit pas un
refus sec mais une petite page 403 : *« Votre réseau a été bloqué après des
requêtes suspectes »*, avec un bouton. Le bouton lance une preuve de travail
légère dans le navigateur (une ou deux secondes de calcul, en JavaScript simple :
pas de captcha tiers, aucune requête externe, aucun pistage). Une fois résolue,
le serveur pose un cookie :

- **signé** (HMAC avec `kernel.secret`), **lié à l'adresse**, valable
  **24 heures**, `HttpOnly`, `SameSite=Lax` ;
- il laisse passer **ce navigateur**, et lui seul : l'adresse reste bloquée pour
  tout le reste ;
- il **n'ouvre jamais un chemin sensible** : `/.env`, `/.git`, les clés, les
  dumps et le reste restent fermés pour tout le monde, laissez-passer ou non ;
- les tentatives sont limitées (10 par 10 minutes et par adresse), chaque défi ne
  sert qu'une fois, et un laissez-passer utilisé pour attaquer est retiré à toute
  l'adresse, à qui le défi n'est plus proposé.

Les scanners n'exécutent pas le script de la page et ne gardent pas son cookie :
ils restent dehors. Chaque laissez-passer est journalisé (`human_pass`) et
compté sur le tableau de bord : s'il y en a beaucoup, l'adresse est partagée et
vous voudrez peut-être la débloquer.

La page est en anglais et en français (selon `Accept-Language`) ; les textes se
redéfinissent dans vos traductions, domaine `sentinelle`, clés `human_pass.*`,
ou la page entière avec `templates/bundles/SentinelleBundle/human_pass.html.twig`.
Pour la désactiver : `blocking.human_pass: false`, et les adresses bloquées
reçoivent de nouveau un 403 sec.

---

## Installation

```bash
composer require acencyril/sentinelle-bundle
```

La recette Symfony Flex enregistre le bundle, crée
`config/packages/sentinelle.yaml` et `config/routes/sentinelle.yaml`, et ajoute
`SENTINELLE_ALERT_EMAIL` et `SENTINELLE_ALLOWLIST` à votre `.env`.

> **Sans Flex**, enregistrez le bundle à la main et créez les deux fichiers
> ci-dessous :
>
> ```php
> // config/bundles.php
> return [
>     // …
>     Acencyril\SentinelleBundle\SentinelleBundle::class => ['all' => true],
> ];
> ```

> ⚠ **Derrière un reverse-proxy** (nginx, Traefik, Caddy, un répartiteur de
> charge, un CDN), configurez d'abord `trusted_proxies`. Voir
> [Derrière un reverse-proxy](#derrière-un-reverse-proxy) : sans cela, tous les
> visiteurs partagent l'adresse du proxy.

### 1. Configurer

```yaml
# config/packages/sentinelle.yaml
sentinelle:
    # Mode d'essai : détecte, journalise et alerte, mais ne bloque rien.
    # À laisser actif les premières semaines — voir le § 5 plus bas.
    dry_run: true

    alert:
        recipient: '%env(SENTINELLE_ALERT_EMAIL)%'
        sender:    'no-reply@mon-site.fr'
        site_name: 'Mon Site'
        # Les types envoyés tout de suite ; le reste va dans le récapitulatif quotidien.
        immediate: [breach]                 # la valeur par défaut

    access:
        role:            ROLE_ADMIN
        parent_template: 'base.html.twig'
        back_route:      'tableau_de_bord'   # ou null

    blocking:
        # Durée du blocage automatique par récidive ; la dernière valeur se répète.
        durations: ['+24 hours', '+7 days', 'permanent']   # la valeur par défaut
        # La page de défi pour les navigateurs derrière une adresse bloquée.
        human_pass: true                                   # la valeur par défaut

    never_block:
        # ⚠ À REMPLIR AVANT LA MISE EN PRODUCTION.
        # Au minimum votre propre adresse de sortie : sans elle, une fausse
        # manœuvre vous ferme la porte de votre propre site.
        ips: '%env(default::SENTINELLE_ALLOWLIST)%'

        # Vos webhooks. Un 401 y est un incident de configuration, pas une attaque.
        paths: ['/api/webhook/', '/stripe/callback']

        # Vos prestataires, en plus de ceux du bundle.
        providers: ['.mon-prestataire-signature.com', '.mon-cdn.net']
```

### 2. Les routes

```yaml
# config/routes/sentinelle.yaml
sentinelle:
    resource: '@SentinelleBundle/config/routes.php'
    type: php
```

### 3. Le schéma

```bash
php bin/console doctrine:migrations:diff
php bin/console doctrine:migrations:migrate
```

Deux tables : `sentinelle_visit` et `sentinelle_blocked_ip`.

### 4. La purge

Sans elle, la table grossit sans fin **et les récidives ne se réinitialisent
jamais** : une adresse bloquée il y a six mois repasse directement en deuxième
récidive au premier scan, et écope de sept jours là où elle méritait
vingt-quatre heures.

```
0 4 * * *  php /chemin/bin/console sentinelle:purge
```

Et le récapitulatif quotidien, où finit toute alerte qui n'est pas une fuite
(voir [Quand il vous écrit](#quand-il-vous-écrit)) :

```
0 7 * * *  php /chemin/bin/console sentinelle:digest
```

### 5. Démarrer en mode d'essai

Sentinelle s'installe avec `dry_run: true` — elle détecte, journalise et alerte,
mais **ne bloque rien**. Personne ne branche un blocage automatique sur un site
en production sans savoir ce qu'il va fermer. Regarde le tableau de bord quelques
jours, demande-toi « aurais-je voulu bloquer celle-ci ? », puis passe
`dry_run: false`.

Chaque blocage évité part dans les journaux avec ce qui aurait été décidé, durée
comprise.

> Un mécanisme qu'on ne peut pas essayer sans risque ne sera pas essayé — il sera
> installé et désactivé au premier incident.

### 6. Vérifier qu'il peut faire son travail

```bash
php bin/console sentinelle:check
```

Contrôle que le cache répond, que les deux tables existent, que la liste blanche
n'est pas vide et que les alertes ont un destinataire valide. Chacun de ces
points est une façon dont le mécanisme peut échouer **en silence** — sans cache,
les compteurs rendent toujours zéro, aucun seuil ne se déclenche, et la détection
est désarmée sans que rien ne le signale.

---

## Derrière un reverse-proxy

⚠ **À lire si quoi que ce soit se trouve devant PHP** : nginx ou Caddy dans un
autre conteneur, Traefik, un répartiteur de charge, Cloudflare ou un autre CDN.

Sans `trusted_proxies`, Symfony ne croit pas l'en-tête `X-Forwarded-For` : **toutes
les requêtes semblent venir de la même adresse, celle de votre proxy**.
Sentinelle ne peut alors plus distinguer deux visiteurs. Un seul scanner, et
l'adresse du proxy serait bloquée, donc tout le monde.

Les plages privées et locales ne sont jamais bloquées, justement pour que cela
ne ferme pas votre site ; mais alors plus rien n'est bloqué du tout, et le
tableau de bord montre une seule adresse pour le monde entier. Dites à Symfony
quels proxies croire :

```yaml
# config/packages/framework.yaml
framework:
    # L'adresse ou la plage du proxy. REMOTE_ADDR convient quand seul le proxy
    # peut joindre PHP (un réseau Docker, un socket unix) ; jamais quand PHP
    # est joignable directement.
    trusted_proxies: '%env(TRUSTED_PROXIES)%'
    trusted_headers: ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-port', 'x-forwarded-host']
```

```dotenv
# .env.local
TRUSTED_PROXIES=127.0.0.1,REMOTE_ADDR
```

Derrière Cloudflare ou un autre CDN, listez plutôt ses plages publiées.
Voir [la documentation Symfony sur les proxies](https://symfony.com/doc/current/deployment/proxies.html).

Sentinelle le vérifie à l'exécution : quand une requête vient d'une adresse
privée ou locale avec un en-tête `X-Forwarded-For` et qu'aucun proxy de
confiance n'est configuré, il écrit un avertissement dans les journaux (une fois
par processus).

---

## security.txt et Content-Security-Policy

Deux choses qu'un visiteur soucieux de sécurité vérifie dans la première
minute ; les deux sont éteintes tant que vous ne les configurez pas.

### security.txt

```yaml
# config/packages/sentinelle.yaml
sentinelle:
  security_txt:
    contact: 'mailto:security@example.com'   # ou une URL https ; une liste convient
    preferred_languages: [fr, en]
    policy: '/fr/securite'                   # un chemin, ou une URL absolue
    # expires: '+11 months'                  # la valeur par défaut
    # canonical: []                          # par défaut : l'adresse demandée
    # encryption: 'https://example.com/pgp.asc'
    # acknowledgments: '/fr/merci'
    # hiring: 'https://example.com/jobs'
    # redirect_legacy: true                  # /security.txt -> 301
```

**Expires est calculé, jamais écrit en dur** : minuit UTC aujourd'hui plus
`expires`, donc toujours dans le futur et à moins d'un an, comme le demande la
RFC. La date d'un fichier statique est le champ que tout le monde oublie, et un
security.txt expiré fait penser au chercheur que l'adresse est morte elle aussi.

**Il répond avant le routeur et avant le blocage d'IP** : aucune route à
importer, aucun préfixe de langue sur le chemin, et quelqu'un qui sondait votre
site il y a une minute peut encore savoir où signaler ce qu'il a trouvé.

Les chemins (`/fr/securite`) deviennent absolus sur l'hôte demandé : une seule
configuration pour tous les environnements. La signature OpenPGP n'est pas
prise en charge : la RFC la rend facultative, et signer un fichier régénéré
chaque jour demanderait la clé sur le serveur.

### Content-Security-Policy avec nonce

```yaml
sentinelle:
  csp:
    policy: >-
      default-src 'self'; script-src 'self' {nonce}; style-src 'self' 'unsafe-inline';
      img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self';
      frame-ancestors 'none'; upgrade-insecure-requests
    # report_only: "…"   # une politique plus stricte à essayer d'abord, en Report-Only
```

```twig
<script nonce="{{ csp_nonce() }}">…</script>
```

`{nonce}` devient `'nonce-…'`, une valeur aléatoire qui change à chaque page et
que `csp_nonce()` imprime dans la même page. Seuls les scripts marqués par vos
gabarits s'exécutent ; un `<script>` injecté, non, faute de connaître la valeur.
C'est tout l'intérêt d'une CSP, et ce que `'unsafe-inline'` abandonne.

- La politique est ajoutée à toute réponse principale qui **n'en a pas** : un
  contrôleur qui pose la sienne (un téléchargement, un widget intégrable, le
  laissez-passer de Sentinelle) la garde.
- `csp_nonce()` existe même sans politique : les gabarits peuvent porter leurs
  nonces avant que vous l'activiez.
- Les gestionnaires en ligne (`onclick="…"`) ne sont pas couverts par un nonce :
  passez-les dans un script (`addEventListener`) avant d'appliquer la politique.
- Les en-têtes qui ne changent jamais (HSTS, `X-Content-Type-Options`,
  `Referrer-Policy`…) vont dans votre serveur web, où ils couvrent aussi les
  fichiers statiques que PHP ne voit pas.

---

## Le tableau de bord

`/admin/activity` — préfixe et rôle configurables.

Le journal des requêtes, filtrable sur les seules lignes suspectes. Les adresses
bloquées, avec leur motif, leur nombre de récidives et le décompte des requêtes
refusées depuis. Les adresses les plus actives sur sept jours. Et sous chacune,
**le nom de son propriétaire** quand le DNS inverse le donne. Le nombre de
laissez-passer accordés sur les dernières 24 heures.

Le blocage manuel est permanent par défaut : une adresse qu'on bloque à la main
est un choix délibéré, pas une détection.

En haut, des tuiles pour les dernières 24 heures : adresses bloquées en ce moment,
requêtes refusées venues d'elles, tentatives d'exploitation, sondages, réponses
sensibles servies (en rouge dès qu'il y en a une), laissez-passer et pages vues.
Chaque tuile ouvre le journal filtré sur ce type. La page est en français et en
anglais (la langue de la requête) ; chaque texte se redéfinit dans vos traductions,
domaine `sentinelle`, clés `dashboard.*`. Un badge indique si Sentinelle est en mode
d'essai.

### Dans votre admin

Le tableau de bord étend `access.parent_template`, le gabarit de votre admin, qui
doit définir les blocs `title` et `body`. Le tableau de bord remplace le contenu de
`body` : le cadre de votre admin (en-tête, onglets, largeur) doit donc se trouver
*autour* de ce bloc dans le gabarit, pas dedans. Si votre gabarit de base a un bloc
qui enveloppe `body`, le gabarit de l'admin redéfinit celui-là :

```twig
{# templates/admin/layout.html.twig, déclaré en access.parent_template #}
{% extends 'base.html.twig' %}
{% block main %}
  <nav class="admin-tabs">…</nav>
  <div class="admin-page">{% block body %}{% endblock %}</div>
{% endblock %}
```

### L'apparence du tableau de bord

Ni CDN, ni framework, ni couleur en ligne : le tableau de bord est habillé par un
seul bloc `<style>` dont chaque couleur, police et arrondi est une propriété CSS
personnalisée. Les valeurs par défaut partent de la couleur du texte de la page
(`currentColor`) : bordures, rayures, texte secondaire et pastilles d'état en sont
des mélanges, si bien que le tableau de bord se lit sur une admin claire comme sur
une sombre, dans votre police, sans savoir quel thème l'entoure. Les couleurs d'état
sont elles aussi mélangées à la couleur du texte, ce qui les garde lisibles des deux
côtés.

Pour reprendre votre palette, définissez celles que vous voulez sur votre admin
(`:root`, `body` ou l'enveloppe de votre gabarit) ; deux lignes suffisent en général :

```css
:root { --sentinelle-accent: #ff5a1f; --sentinelle-radius: 14px; }
```

| Propriété | Par défaut | Sert à |
|---|---|---|
| `--sentinelle-font` | `inherit` | tout le texte |
| `--sentinelle-heading-font` | `inherit` | les titres |
| `--sentinelle-mono` | `ui-monospace, …` | adresses, codes de statut |
| `--sentinelle-ink` | `currentColor` | le texte |
| `--sentinelle-muted` | 64 % de la couleur du texte | libellés, indications |
| `--sentinelle-surface` | 3 % de la couleur du texte | tuiles, cadres des tableaux |
| `--sentinelle-line` | 13 % de la couleur du texte | bordures, filets |
| `--sentinelle-stripe` | 3 % de la couleur du texte | en-tête et lignes alternées |
| `--sentinelle-hover` | 7 % de la couleur du texte | survol, pastilles neutres |
| `--sentinelle-accent` | `#2563eb` | liens, anneau de focus |
| `--sentinelle-danger` | `#dc2626` | attaques, réponses sensibles, bloquer |
| `--sentinelle-warning` | `#d97706` | sondages, accès refusés, mode d'essai |
| `--sentinelle-success` | `#16a34a` | pages vues, blocage actif |
| `--sentinelle-info` | `#0891b2` | laissez-passer, blocages manuels |
| `--sentinelle-violet` | `#7c3aed` | erreurs serveur |
| `--sentinelle-radius` | `12px` | tuiles, tableaux, messages |
| `--sentinelle-max-width` | `72rem` | la largeur du tableau de bord |

Sur une admin sombre, donnez aux tons les valeurs plus claires de votre thème (par
exemple `--sentinelle-danger: #ff6b7a`) si ceux par défaut paraissent trop sourds ;
le mélange avec la couleur du texte les garde déjà lisibles. Les tableaux défilent
dans leur propre cadre : sur un téléphone, la page ne défile jamais de côté. Pour
changer le balisage, surchargez `templates/bundles/SentinelleBundle/activity.html.twig`,
ou seulement son bloc `sentinelle_content` ou `sentinelle_styles`.

---

## Ce qu'il détecte

**Critique — bloque et alerte immédiatement.** Exécution de code (`php://input`,
`system(`), injection SQL (`UNION SELECT`, `OR 1=1`), traversée de répertoire,
Log4Shell (`${jndi:`), désérialisation PHP.

**Sondes — alertent en rafale.** Fichiers sensibles (`.env`, `.sql`, `.pem`),
répertoires de configuration (`/.git`, `/.aws`, `/.ssh`), chemins WordPress et
phpMyAdmin, injections de script. Une sonde isolée est du bruit ; quinze en dix
minutes sont un scan.

**Force brute.** Dix refus d'accès en dix minutes.

Vous pouvez **ajouter** vos propres motifs. Vous ne pouvez pas retirer ceux du
bundle : *ce qu'on rend configurable, on le rend désactivable par mégarde*, et
personne ne veut découvrir après coup que son installation avait la détection
Log4Shell désactivée.

---

## Trois décisions qui méritent d'être expliquées

### La journalisation ne coûte rien au visiteur

Elle se fait sur `kernel.terminate`, après l'envoi de la réponse. C'est aussi le
seul moment où le code HTTP est connu.

### Le blocage passe avant le routeur

L'écouteur est branché en priorité **300**, avant le routeur (32) et le pare-feu
(8). Une adresse bannie ne consomme ni résolution de route, ni session, ni
requête en base. Un script reçoit un 403 nu, sans page d'erreur : répondre en
détail à un scanner lui apprend seulement ce qu'il a déclenché. Un navigateur qui
demande une page reçoit la page du
[laissez-passer](#le-laissez-passer--bloqué-mais-pas-enfermé).

### Le quota anti-flood coupe l'écriture, pas le comptage

Un scan de 155 requêtes en 16 secondes ne doit pas produire 155 lignes. Mais le
quota ne bloque **que** l'insertion : les compteurs continuent. Sinon le seuil de
rafale, fixé à 15, ne serait jamais atteint après 5 sondes, et le mécanisme
d'alerte s'auto-neutraliserait au moment précis où il devient utile.

---

## Ce qu'il ne fait pas

**Il n'inspecte pas le corps des requêtes** — coûteux, et souvent des données
personnelles qu'on ne veut pas stocker. Seuls le chemin et les paramètres d'URL
sont examinés.

**Il ne remplace pas votre serveur web.** Les sondes les plus grossières sont
mieux arrêtées en amont, avant d'atteindre PHP.

**Il ne vous protège pas d'une faille applicative.** Il vous prévient qu'on la
cherche.

**Il masque les secrets avant écriture.** Un paramètre `?token=…` est enregistré
`token=***` : sans cela, chaque appel légitime écrirait un secret en clair dans
une table consultable depuis l'interface d'administration.

---

## Quand ça se dégrade

Toutes les défaillances vont dans le même sens : **laisser passer plutôt que tout
refuser**.

Cache indisponible, base injoignable, échec d'écriture, mail non parti — la
requête continue et l'erreur part dans les journaux. Un blocage raté est moins
grave qu'un site qui refuse tout le monde.

---

## Mettre à jour

De la 0.5 à la 0.6, voir [UPGRADE.md](UPGRADE.md) : par défaut, seules les
fuites sont envoyées tout de suite ; planifiez `sentinelle:digest` chaque jour, ou
mettez `alert.immediate: all` pour garder un courriel par alerte.

De la 0.4 à la 0.5 : rien à changer, mais les navigateurs bloqués voient
désormais une page de défi au lieu d'un 403 sec.

### Depuis la 0.2

La version 0.3 a tout renommé en anglais — clés de configuration, tables, routes
et chemin d'administration. La correspondance complète est dans
[CHANGELOG.md](CHANGELOG.md).

---

## Licence

MIT.

## Sécurité

Une vulnérabilité ? Signalez-la en privé, voir [SECURITY.md](SECURITY.md).

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md). Les motifs de détection et la liste des
prestataires connus s'améliorent par l'usage — si le vôtre manque à la liste par
défaut, c'est une pull request d'une ligne.