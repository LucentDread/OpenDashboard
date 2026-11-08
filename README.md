# OpenDashboard

Requêtes en profondeur et widgets pour **OpenCTI 6.7.x**, là où les filtres natifs s’arrêtent.

OpenCTI sait filtrer une liste d’entités avec des groupes ET/OU, mais un filtre ne peut pas porter sur le *résultat d’une autre recherche*. Par exemple :

> les modes opératoires (MOA) contenus dans des rapports dont le nom contient X **ou** qui contiennent X, **et** eux-mêmes liés à X.

OpenDashboard exécute d’abord les sous-requêtes, puis réinjecte leurs résultats (des listes d’identifiants) comme filtres natifs dans la requête parente. La requête finale envoyée à OpenCTI reste un `FilterGroup` standard.

Ce dépôt est un **POC** : une page HTML autonome, sans framework ni build. Elle fonctionne contre une vraie instance ou contre un **mock intégré** qui simule l’API GraphQL d’OpenCTI 6.7.7 dans le navigateur.

## Air-gap

Le projet est fait pour tourner sur un réseau isolé. La page ne charge **aucune ressource externe** :

- pas de CDN ;
- polices IBM Plex dans `vendor/fonts` ;
- graphql-js dans `vendor/`.

Au moment de l’exécution, seuls deux appels réseau existent, tous deux vers l’instance OpenCTI :

- les requêtes GraphQL ;
- la table des relations `schemaRelationsTypesMapping`. Si elle est indisponible, la page utilise la copie embarquée `js/opencti-relations.js`.

Pour déployer, il suffit de copier le dossier. `node_modules` n’est pas nécessaire : npm ne sert qu’aux tests et aux outils de génération. Deux façons de servir la page :

- `node tools/serve.js` (Node seul, sans dépendance) ;
- n’importe quel serveur web, par exemple derrière le même nginx qu’OpenCTI pour partager l’origine :

```nginx
location /opendashboard/ { alias /opt/opendashboard/; }
# /graphql est déjà servi par OpenCTI sur la même origine
```

Avec cette configuration, mettre l’URL de la plateforme (ex. `https://opencti.interne`) dans les Réglages.

## Démarrage

### Avec le mock (aucune instance nécessaire)

```bash
node tools/serve.js          # puis ouvrir http://localhost:8080
```

Ouvrir `index.html` directement depuis le disque marche aussi. Le mock tourne entièrement dans la page, avec un jeu de données fictif d’une centaine d’entités et de rapports.

### Avec une instance OpenCTI

```bash
node tools/serve.js --target https://opencti.exemple.fr   # --insecure si certificat auto-signé
```

Ensuite, dans **Réglages** :

1. Choisir le mode « Instance OpenCTI ».
2. Mettre l’URL `http://localhost:8080`.
3. Coller votre jeton API (Profil → Jeton d’API).

`tools/serve.js` relaie `/graphql` vers l’instance, donc la page et l’API partagent la même origine et aucune configuration CORS n’est nécessaire. Le jeton n’est transmis qu’à OpenCTI. La page ne le garde que si vous cochez « Mémoriser ».

Si vous appelez l’instance directement, sans le relais, le navigateur exigera que l’instance renvoie les en-têtes CORS adéquats.

## Composer une requête

L’**explorateur** propose un constructeur visuel et l’édition directe du JSON. Briques disponibles :

| Condition | Effet | Traduction OpenCTI |
|---|---|---|
| `field` | attribut : nom, alias, dates, confiance… | filtre natif |
| `label`, `author`, `marking` | libellé, auteur, marquage (par nom) | résolu en id → `objectLabel` / `createdBy` / `objectMarking` |
| `relatedTo` | relation avec le résultat d’une sous-requête ; `relationship` (types) et `direction` (`out` : l’entité est la source, `in` : elle est la cible, `both` par défaut) facultatifs | `both` : `regardingOf` ; `out`/`in` : `stixCoreRelationships(toId / fromId)` |
| `containedIn` | l’entité figure dans un conteneur (rapport, grouping…) issu d’une sous-requête | lecture de `objects` des conteneurs → `ids` |
| `contains` | le conteneur contient un résultat d’une sous-requête | `objects` |
| `all` / `any` | ET / OU, imbriquables | `FilterGroup` |

Chaque condition accepte `"negate": true` (exclure). Exemple, la requête de l’introduction :

```json
{
  "type": "Intrusion-Set",
  "where": { "all": [
    { "containedIn": { "type": "Report", "where": { "any": [
      { "field": "name", "op": "contains", "value": "QuartzLoader" },
      { "contains": { "type": "Stix-Domain-Object", "where": { "field": "name", "op": "eq", "value": "QuartzLoader" } } }
    ] } } },
    { "relatedTo": { "type": "Stix-Domain-Object", "where": { "field": "name", "op": "eq", "value": "QuartzLoader" } } }
  ] }
}
```

### Listes proposées par l’interface

- **Relations** : la liste ne montre que les relations prévues par le schéma OpenCTI entre le type cherché et le type de la sous-requête, groupées par sens. Par exemple « mode opératoire —uses→ malware » ou « malware —authored-by→ mode opératoire ». La table vient de `schemaRelationsTypesMapping` sur l’instance, sinon de la copie embarquée générée depuis le code source 6.7.7 (`npm run build:relations`).
- **Libellés, marquages, auteurs** : les valeurs sont celles qui existent en base. Elles viennent de `labels`, `markingDefinitions` et `identities`, avec recherche, comme dans l’interface d’OpenCTI.
- **Champs à vocabulaire** (type de rapport, motivation, type de malware…) : valeurs issues de `vocabularies(category)`.
- **Nom / alias** avec « est » : recherche parmi les entités du type courant. Une saisie libre reste possible.

Le **plan d’exécution** affiche chaque étape avec son nombre de résultats. Le **journal GraphQL** liste toutes les requêtes envoyées, copiables en JSON ou en `curl`, pour les rejouer dans le playground d’OpenCTI.

## Tableau de bord

Toute requête de l’explorateur peut devenir un widget, avec quatre vues :

- **Nombre** ;
- **Tableau** ;
- **Barres** : répartition par type, auteur, libellé, marquage, type de rapport, motivation ou confiance ;
- **Chronologie** : comptage par mois sur une date au choix.

Le tableau de bord est gardé dans le navigateur. Il s’exporte et s’importe en JSON.

## Structure

```
index.html            page, styles
js/engine.js          moteur : transport, compilation du DSL, exécution, agrégations
js/ui.js              interface
js/examples.js        requêtes d’exemple et tableau de bord par défaut
js/phrase.js          traduction d’une requête en phrase française (articles, accords, verbes des relations, négations)
js/mock-server.js     mock GraphQL (sous-ensemble du schéma OpenCTI 6.7.7 + sémantique des filtres)
js/mock-data.js       jeu de données fictif
js/opencti-relations.js  table des relations OpenCTI 6.7.7 (générée, repli hors ligne)
vendor/               graphql-js 16.9.0 (mock uniquement) et polices IBM Plex (OFL)
tools/serve.js        serveur local + relais /graphql
tests/                tests du moteur contre le mock et du générateur de phrases (npm test)
```

## Développement

```bash
npm install
npm test                 # moteur + mock, avec les deux stratégies de relation
npm run build:artifact   # dist/artifact.html pour la publication en aperçu claude.ai
npm run build:vendor     # régénère vendor/graphql-16.9.0.min.js
npm run build:fonts      # régénère vendor/fonts
npm run build:relations  # régénère js/opencti-relations.js depuis le code OpenCTI (accès GitHub requis)
```

## Points à valider sur une vraie instance

Le mock reprend les noms exacts du schéma 6.7.7 (types, arguments, clés de filtre `objects`, `regardingOf`, `ids`, `objectLabel`…). Sa sémantique reste une approximation. À vérifier en priorité :

- **`regardingOf`** : il n’est utilisé que pour « Lié à » sans contrainte de sens, car ce filtre OpenCTI ignore le sens. L’exclusion passe par l’opérateur porté par la valeur `id`, comme dans `database/engine.js`. En cas d’erreur ou de résultats inattendus, passer en « Parcours des relations » dans les Réglages. Cette stratégie n’utilise que `stixCoreRelationships(fromOrToId | fromId | toId, relationship_type)`.
- **Droits** : `vocabularies`, `labels` et `markingDefinitions` demandent les capacités KNOWLEDGE (ou équivalentes) côté OpenCTI. Un jeton trop restreint vide les listes proposées, mais les requêtes fonctionnent toujours.
- **Opérateur `eq` sur `name`** : la sensibilité à la casse peut différer du mock, qui ignore la casse.
- **Volumétrie** : les listes d’identifiants injectées dans les filtres peuvent devenir longues. Le garde-fou « éléments max. par étape » est à ajuster selon votre instance.
- **Champs par type** : seuls les types courants sont couverts par les fragments d’affichage (`js/engine.js`, `DISPLAY_FIELDS`).

## Données du mock

Les MOA, malwares, campagnes, rapports et auteurs du mock sont **fictifs**. Les techniques ATT&CK, CVE, pays et secteurs sont réels, mais leurs relations avec les entités fictives sont inventées.
