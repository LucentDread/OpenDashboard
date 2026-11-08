/*
 * Tests du générateur de phrases (français) : npm test
 */
'use strict';
const assert = require('node:assert/strict');
require('../js/phrase.js');
require('../js/examples.js');

const OD = globalThis.OD;
const P = (q) => OD.phrase.query(q);
const ex = Object.fromEntries(OD.examples.map((e) => [e.id, e.query]));
const cases = [
  ['exemple MOA / QuartzLoader (parenthèses de désambiguïsation)', P(ex['moa-quartzloader']),
    'les modes opératoires qui figurent dans des rapports (dont le nom contient « QuartzLoader » ou qui contiennent des entités dont le nom est « QuartzLoader » ou dont un alias est « QuartzLoader ») et qui sont liés à des entités dont le nom est « QuartzLoader » ou dont un alias est « QuartzLoader »'],
  ['date + verbe de relation', P({ type: 'Report', where: { all: [
    { field: 'published', op: 'gte', value: '2026-01-01T00:00:00.000Z' },
    { contains: { type: 'Intrusion-Set', where: { relatedTo: { type: 'Sector', where: { field: 'name', op: 'eq', value: ['Énergie', 'Transport'] } }, relationship: ['targets'], direction: 'out' } } },
  ] } }),
  'les rapports publiés à partir du 1er janvier 2026 et qui contiennent des modes opératoires qui ciblent des secteurs dont le nom est « Énergie » ou « Transport »'],
  ['participe après « et »', P({ type: 'Report', where: { all: [{ label: ['a'] }, { field: 'published', op: 'lt', value: '2025-03-03T00:00:00Z' }] } }),
    'les rapports qui portent le libellé « a » et qui sont publiés avant le 3 mars 2025'],
  ['passif accordé au féminin', P(ex['ttp-tlp-red']),
    'les techniques qui sont utilisées par des modes opératoires qui figurent dans des rapports dont le marquage est « TLP:RED »'],
  ['négations', P({ type: 'Attack-Pattern', where: { all: [
    { field: 'name', op: 'not_eq', value: ['A', 'B'] }, { relatedTo: { type: 'Tool' }, relationship: ['uses'], direction: 'out', negate: true },
    { field: 'confidence', op: 'gte', value: 50 }, { field: 'description', op: 'nil' }] } }),
  'les techniques dont le nom n’est ni « A » ni « B », qui n’utilisent pas d’outils, dont le niveau de confiance est supérieur ou égal à 50 et dont la description n’est pas renseignée'],
  ['groupe OU contenant un ET', P({ type: 'Campaign', where: { any: [
    { relatedTo: { type: 'Intrusion-Set' }, relationship: ['attributed-to'], direction: 'out' },
    { all: [{ field: 'created', op: 'lt', value: '2025-03-03T00:00:00Z' }, { author: ['A', 'B'] }] }] } }),
  'les campagnes qui sont attribuées à des modes opératoires ou (créées avant le 3 mars 2025 et dont l’auteur est « A » ou « B »)'],
  ['pronominal nié', P({ type: 'Intrusion-Set', where: { relatedTo: { type: 'Campaign' }, relationship: ['attributed-to'], direction: 'in', negate: true } }),
    'les modes opératoires qui ne se voient pas attribuer de campagnes'],
  ['préposition « de »', P({ type: 'Malware', where: { relatedTo: { type: 'Tool' }, relationship: ['part-of'], direction: 'out' } }),
    'les malwares qui font partie d’outils'],
  ['absent de tout conteneur', P(ex['moa-not-in-reports']),
    'les modes opératoires qui utilisent des entités (dont le nom est « QuartzLoader » ou dont un alias est « QuartzLoader ») et qui ne figurent dans aucun rapport'],
  ['relation sans type, peu importe le sens', P({ type: 'Malware', where: { relatedTo: { type: 'Campaign' } } }), 'les malwares qui sont liés à des campagnes'],
  ['relation typée, peu importe le sens', P({ type: 'Malware', where: { relatedTo: { type: 'Campaign' }, relationship: ['uses'] } }),
    'les malwares qui sont liés par une relation « uses » (dans un sens ou l’autre) à des campagnes'],
];

let failures = 0;
for (const [label, got, expected] of cases) {
  try { assert.equal(got, expected); console.log(`ok   phrase : ${label}`); }
  catch { failures++; console.error(`FAIL phrase : ${label}\n     attendu : ${expected}\n     obtenu  : ${got}`); }
}
// Toutes les relations de la table ont-elles une tournure ? (information, pas un échec)
require('../js/opencti-relations.js');
const allRels = new Set(Object.values(OD.relationsMapping.mapping).flat());
const missing = [...allRels].filter((r) => !OD.phrase.RELATIONS[r]);
console.log(`info relations sans tournure dédiée (formulation générique) : ${missing.length ? missing.join(', ') : 'aucune'}`);
if (failures) { console.error(`\n${failures} échec(s) phrase`); process.exit(1); }
