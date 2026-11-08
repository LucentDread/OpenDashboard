# OpenDashboard

Requêtes en profondeur et widgets pour **OpenCTI 6.7.x**, là où les filtres natifs s’arrêtent.

OpenCTI sait filtrer une liste d’entités avec des groupes ET/OU, mais un filtre ne peut pas porter sur le *résultat d’une autre recherche*. Par exemple :

> les modes opératoires (MOA) contenus dans des rapports dont le nom contient X **ou** qui contiennent X, **et** eux-mêmes liés à X.

OpenDashboard exécute d’abord les sous-requêtes, puis réinjecte leurs résultats (des listes d’identifiants) comme filtres natifs dans la requête parente. La requête finale envoyée à OpenCTI reste un `FilterGroup` standard.

Ce dépôt est un **POC** : une page HTML autonome, sans framework ni build. Elle fonctionne contre une vraie instance ou contre un **mock intégré** qui simule l’API GraphQL d’OpenCTI 6.7.7 dans le navigateur.

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
| `relatedTo` | relation (dans un sens ou l’autre) avec le résultat d’une sous-requête, types de relation facultatifs | `regardingOf` ou parcours de `stixCoreRelationships` |
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
js/mock-server.js     mock GraphQL (sous-ensemble du schéma OpenCTI 6.7.7 + sémantique des filtres)
js/mock-data.js       jeu de données fictif
vendor/               graphql-js 16.9.0 (utilisé par le mock uniquement)
tools/serve.js        serveur local + relais /graphql
tests/engine.test.js  tests du moteur contre le mock (npm test)
```

## Développement

```bash
npm install
npm test                 # moteur + mock, avec les deux stratégies de relation
npm run build:artifact   # dist/artifact.html pour la publication en aperçu claude.ai
npm run build:vendor     # régénère vendor/graphql-16.9.0.min.js
```

## Points à valider sur une vraie instance

Le mock reprend les noms exacts du schéma 6.7.7 (types, arguments, clés de filtre `objects`, `regardingOf`, `ids`, `objectLabel`…). Sa sémantique reste une approximation. À vérifier en priorité :

- **`regardingOf`** : c’est la stratégie par défaut pour « Lié à ». En cas d’erreur ou de résultats inattendus, passer en « Parcours des relations » dans les Réglages. Cette stratégie n’utilise que `stixCoreRelationships(fromOrToId, relationship_type)`.
- **Opérateur `eq` sur `name`** : la sensibilité à la casse peut différer du mock, qui ignore la casse.
- **Volumétrie** : les listes d’identifiants injectées dans les filtres peuvent devenir longues. Le garde-fou « éléments max. par étape » est à ajuster selon votre instance.
- **Champs par type** : seuls les types courants sont couverts par les fragments d’affichage (`js/engine.js`, `DISPLAY_FIELDS`).

## Données du mock

Les MOA, malwares, campagnes, rapports et auteurs du mock sont **fictifs**. Les techniques ATT&CK, CVE, pays et secteurs sont réels, mais leurs relations avec les entités fictives sont inventées.
