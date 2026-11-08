/*
 * Tests du moteur contre le mock (Node 18+) : npm test
 * Vérifie que chaque requête d'exemple est valide pour le schéma et que le
 * scénario de référence renvoie le résultat attendu, avec les deux stratégies
 * de résolution des relations.
 */
'use strict';
const assert = require('node:assert/strict');
const graphql = require('graphql');

require('../js/opencti-relations.js');
require('../js/mock-data.js');
require('../js/mock-server.js');
require('../js/engine.js');
require('../js/examples.js');

const OD = globalThis.OD;

async function main() {
  const mock = OD.createMockServer(graphql, OD.mockData.build(), { latency: null });
  let failures = 0;

  for (const strategy of ['regardingOf', 'relationships']) {
    const transport = new OD.Transport();
    transport.configure({ mode: 'mock', mock });
    const engine = new OD.Engine(transport, { relatedStrategy: strategy, pageSize: 7 }); // petite page = teste la pagination
    const names = async (q) => (await engine.run(q)).items.map((n) => n.name).sort();

    const check = async (label, fn) => {
      try { await fn(); console.log(`ok   [${strategy}] ${label}`); }
      catch (e) { failures++; console.error(`FAIL [${strategy}] ${label}\n     ${e.message}`); }
    };

    const ex = Object.fromEntries(OD.examples.map((e) => [e.id, e.query]));

    await check('scénario MOA / QuartzLoader', async () => {
      assert.deepEqual(await names(ex['moa-quartzloader']), ['Copper Moth', 'Crimson Heron', 'Tidal Fox']);
    });

    await check('MOA QuartzLoader absents des rapports', async () => {
      assert.deepEqual(await names(ex['moa-not-in-reports']), ['Silent Quarry']);
    });

    await check('rapports dont le nom contient QuartzLoader', async () => {
      const r = await names({ type: 'Report', where: { field: 'name', op: 'contains', value: 'quartzloader' } });
      assert.equal(r.length, 2);
    });

    await check('rapports qui contiennent QuartzLoader', async () => {
      const r = await names({ type: 'Report', where: { contains: { type: 'Malware', where: { field: 'name', op: 'eq', value: 'QuartzLoader' } } } });
      assert.equal(r.length, 3);
    });

    await check('MOA présents dans les rapports QuartzLoader (sans relation)', async () => {
      const r = await names({ type: 'Intrusion-Set', where: { containedIn: { type: 'Report', where: { any: [
        { field: 'name', op: 'contains', value: 'QuartzLoader' },
        { contains: { type: 'Malware', where: { field: 'name', op: 'eq', value: 'QuartzLoader' } } },
      ] } } } });
      assert.deepEqual(r, ['Copper Moth', 'Crimson Heron', 'Glass Viper', 'Iron Sparrow', 'Night Orchid', 'Tidal Fox', 'Velvet Kraken']);
    });

    await check('alias', async () => {
      assert.deepEqual(await names({ type: 'Malware', where: { field: 'alias', op: 'eq', value: 'QZL' } }), ['QuartzLoader']);
    });

    await check('auteur', async () => {
      const r = await engine.run({ type: 'Report', where: { author: 'CERT-Lumen' } });
      assert.ok(r.items.length > 0);
      assert.ok(r.items.every((n) => n.createdBy.name === 'CERT-Lumen'));
    });

    const QZ = { type: 'Malware', where: { field: 'name', op: 'eq', value: 'QuartzLoader' } };

    await check('sens sortant : MOA qui utilisent QuartzLoader', async () => {
      assert.deepEqual(await names({ type: 'Intrusion-Set', where: { relatedTo: QZ, relationship: ['uses'], direction: 'out' } }),
        ['Amber Gecko', 'Copper Moth', 'Crimson Heron', 'Silent Quarry', 'Tidal Fox']);
    });

    await check('sens entrant : aucun MOA ciblé par QuartzLoader via uses', async () => {
      assert.deepEqual(await names({ type: 'Intrusion-Set', where: { relatedTo: QZ, relationship: ['uses'], direction: 'in' } }), []);
    });

    await check('sens : malwares déposés par QuartzLoader (in) vs qui le déposent (out)', async () => {
      assert.deepEqual(await names({ type: 'Malware', where: { relatedTo: QZ, relationship: ['drops'], direction: 'in' } }), ['CinderLock', 'PetalRAT']);
      assert.deepEqual(await names({ type: 'Malware', where: { relatedTo: QZ, relationship: ['drops'], direction: 'out' } }), []);
    });

    await check('exclusion d’une relation (negate)', async () => {
      const r = await names({ type: 'Intrusion-Set', where: { relatedTo: QZ, relationship: ['uses'], negate: true } });
      assert.equal(r.length, 7);
      assert.ok(!r.includes('Tidal Fox'));
    });

    for (const e of OD.examples) {
      await check(`exemple « ${e.id} » s'exécute`, async () => {
        const r = await engine.run(e.query);
        assert.ok(Array.isArray(r.items));
        assert.ok(r.plan.length >= 1);
      });
    }
  }

  // Agrégations
  {
    const transport = new OD.Transport();
    transport.configure({ mode: 'mock', mock });
    const engine = new OD.Engine(transport);
    const { items } = await engine.run({ type: 'Report' });
    const tl = OD.agg.timeline(items, 'published');
    assert.equal(tl.reduce((s, x) => s + x.count, 0), items.length);
    const g = OD.agg.groupBy(items, 'author');
    assert.equal(g.reduce((s, x) => s + x.count, 0), items.length);
    console.log(`ok   agrégations (${items.length} rapports)`);
  }

  // Table des relations, suggestions, conformité du mock au schéma
  {
    const transport = new OD.Transport();
    transport.configure({ mode: 'mock', mock });
    const engine = new OD.Engine(transport);
    const { mapping, source } = await engine.relationsMapping();
    assert.equal(source, 'instance');
    assert.deepEqual(mapping, OD.relationsMapping.mapping);
    const p = OD.types.possibleRelations(mapping, 'Intrusion-Set', 'Malware');
    assert.deepEqual(p.out, ['uses']);
    assert.deepEqual(p.in, ['authored-by']);
    const p2 = OD.types.possibleRelations(mapping, 'Intrusion-Set', 'Threat-Actor-Group');
    assert.ok(p2.out.includes('attributed-to'));
    const data = OD.mockData.build();
    const byId = Object.fromEntries(data.entities.map((e) => [e.id, e]));
    data.relationships.forEach((r) => {
      const k = `${byId[r.fromId].entity_type}_${byId[r.toId].entity_type}`;
      assert.ok((mapping[k] || []).includes(r.relationship_type), `relation hors schéma dans le mock : ${k} ${r.relationship_type}`);
    });
    console.log('ok   table des relations (instance = embarquée, mock conforme)');

    assert.equal((await engine.suggest('label')).length, 7);
    assert.deepEqual((await engine.suggest('label', { search: 'ransom' })).map((o) => o.value), ['ransomware']);
    assert.ok((await engine.suggest('marking')).some((o) => o.value === 'TLP:RED'));
    assert.deepEqual((await engine.suggest('author')).map((o) => o.value).sort(), ['CERT-Lumen', 'Halcyon Threat Intel', 'SOC interne (mock)']);
    assert.ok((await engine.suggest('vocabulary', { category: 'report_types_ov' })).some((o) => o.value === 'malware-analysis'));
    assert.deepEqual((await engine.suggest('entity', { types: ['Malware'], search: 'quartz' })).map((o) => o.value), ['QuartzLoader']);
    console.log('ok   suggestions (libellés, marquages, auteurs, vocabulaires, entités)');

    // Repli sur la table embarquée si l'instance ne répond pas
    const broken = new OD.Transport();
    broken.configure({ mode: 'mock', mock: { execute: async () => ({ errors: [{ message: 'indisponible' }] }) } });
    const e2 = new OD.Engine(broken);
    assert.equal((await e2.relationsMapping()).source, 'embarquée');
    console.log('ok   repli sur la table embarquée');
  }

  if (failures) { console.error(`\n${failures} échec(s)`); process.exit(1); }
  console.log('\nTous les tests passent.');
}

main().catch((e) => { console.error(e); process.exit(1); });
