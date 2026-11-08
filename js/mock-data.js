/*
 * OpenDashboard — jeu de données fictif pour le mock OpenCTI.
 *
 * Tous les modes opératoires, malwares, campagnes, rapports et auteurs sont
 * inventés. Les techniques MITRE ATT&CK, CVE, pays et secteurs sont réels
 * mais les relations entre eux et les entités fictives ne le sont pas.
 *
 * Scénario de référence (exemple « MOA dans des rapports liés à QuartzLoader ») :
 *   - Rapports dont le nom contient « QuartzLoader » : R1, R2
 *   - Rapports qui contiennent l'entité QuartzLoader : R2, R3, R4
 *   - MOA présents dans R1..R4 : Crimson Heron, Glass Viper, Tidal Fox,
 *     Copper Moth, Night Orchid, Iron Sparrow, Velvet Kraken
 *   - MOA qui « uses » QuartzLoader : Crimson Heron, Tidal Fox, Copper Moth,
 *     Amber Gecko, Silent Quarry
 *   => résultat attendu : Crimson Heron, Tidal Fox, Copper Moth
 */
(function (root) {
  'use strict';
  const OD = (root.OD = root.OD || {});

  // Générateur pseudo-aléatoire déterministe (mulberry32) : même jeu à chaque chargement.
  function rng(seed) {
    return function () {
      seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  function uuid(r) {
    const h = () => Math.floor(r() * 16).toString(16);
    let s = '';
    for (let i = 0; i < 32; i++) s += h();
    return `${s.slice(0, 8)}-${s.slice(8, 12)}-4${s.slice(13, 16)}-a${s.slice(17, 20)}-${s.slice(20, 32)}`;
  }

  const PARENTS = {
    'Report': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Container'],
    'Grouping': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Container'],
    'Intrusion-Set': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    'Threat-Actor-Group': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Threat-Actor'],
    'Campaign': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    'Malware': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    'Tool': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    'Attack-Pattern': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    'Vulnerability': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
    'Country': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Location'],
    'Sector': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Identity'],
    'Organization': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Identity'],
    'stix-core-relationship': ['Basic-Relationship', 'Stix-Relationship', 'stix-core-relationship'],
  };

  function build() {
    const r = rng(20260707);
    const pick = (arr) => arr[Math.floor(r() * arr.length)];
    const sample = (arr, n) => {
      const copy = arr.slice();
      const out = [];
      while (out.length < n && copy.length) out.push(copy.splice(Math.floor(r() * copy.length), 1)[0]);
      return out;
    };
    const date = (y0, y1) => {
      const t0 = Date.UTC(y0, 0, 1), t1 = Date.UTC(y1, 9, 31);
      return new Date(t0 + r() * (t1 - t0)).toISOString();
    };

    const labels = [
      ['ransomware', '#c2410c'], ['espionnage', '#4338ca'], ['phishing', '#0e7490'],
      ['loader', '#a16207'], ['infra-critique', '#be123c'], ['financier', '#15803d'],
      ['à-revoir', '#6b7280'],
    ].map(([value, color]) => ({ id: uuid(r), standard_id: `label--${uuid(r)}`, entity_type: 'Label', value, color }));
    const L = Object.fromEntries(labels.map((l) => [l.value, l.id]));

    const markings = [
      ['TLP:CLEAR', '#ffffff', 1], ['TLP:GREEN', '#2e7d32', 2], ['TLP:AMBER', '#d84315', 3], ['TLP:RED', '#c62828', 4],
    ].map(([definition, color, order]) => ({
      id: uuid(r), standard_id: `marking-definition--${uuid(r)}`, entity_type: 'Marking-Definition',
      definition_type: 'TLP', definition, x_opencti_color: color, x_opencti_order: order,
    }));
    const M = Object.fromEntries(markings.map((m) => [m.definition, m.id]));

    const entities = [];
    const byName = {};
    function add(entity_type, name, extra = {}) {
      const created = extra.created || date(2024, 2026);
      const e = {
        id: uuid(r),
        standard_id: `${entity_type.toLowerCase()}--${uuid(r)}`,
        entity_type,
        parent_types: PARENTS[entity_type],
        name,
        description: extra.description || null,
        created,
        modified: created,
        created_at: created,
        updated_at: created,
        confidence: extra.confidence ?? 50 + Math.floor(r() * 50),
        createdBy: extra.createdBy || null,
        labels: extra.labels || [],
        markings: extra.markings || [M['TLP:GREEN']],
        ...extra,
      };
      entities.push(e);
      byName[name] = e;
      return e;
    }

    // Auteurs
    const authors = ['CERT-Lumen', 'Halcyon Threat Intel', 'SOC interne (mock)'].map((n) =>
      add('Organization', n, { description: 'Organisation fictive productrice de renseignement.', markings: [M['TLP:CLEAR']] }));
    const A = Object.fromEntries(authors.map((a) => [a.name, a.id]));
    const anyAuthor = () => pick(authors).id;

    // Pays et secteurs (réels)
    const countries = ['France', 'Allemagne', 'Ukraine', 'Japon', 'Brésil', 'États-Unis', 'Inde', 'Canada']
      .map((n) => add('Country', n, { markings: [M['TLP:CLEAR']] }));
    const sectors = ['Énergie', 'Finance', 'Santé', 'Administration', 'Télécommunications', 'Industrie', 'Transport']
      .map((n) => add('Sector', n, { markings: [M['TLP:CLEAR']] }));

    // Techniques ATT&CK (réelles)
    const attackPatterns = [
      ['T1566.001', 'Spearphishing Attachment'], ['T1059.001', 'PowerShell'], ['T1486', 'Data Encrypted for Impact'],
      ['T1055', 'Process Injection'], ['T1071.001', 'Web Protocols'], ['T1003.001', 'LSASS Memory'],
      ['T1190', 'Exploit Public-Facing Application'], ['T1105', 'Ingress Tool Transfer'],
      ['T1027', 'Obfuscated Files or Information'], ['T1547.001', 'Registry Run Keys / Startup Folder'],
    ].map(([x_mitre_id, n]) => add('Attack-Pattern', n, { x_mitre_id, aliases: [], markings: [M['TLP:CLEAR']] }));

    // Vulnérabilités (réelles)
    const vulns = [
      ['CVE-2021-44228', 10.0], ['CVE-2023-4966', 9.4], ['CVE-2023-34362', 9.8], ['CVE-2024-3400', 10.0],
    ].map(([n, s]) => add('Vulnerability', n, { x_opencti_cvss_base_score: s, markings: [M['TLP:CLEAR']] }));

    // Outils
    const tools = ['Cobalt Strike', 'Mimikatz', 'PsExec', 'AnyDesk']
      .map((n) => add('Tool', n, { tool_types: ['remote-access'], aliases: [] }));

    // Malwares (fictifs)
    const malwareDefs = [
      ['QuartzLoader', ['loader'], ['loader'], ['QZL', 'Quartz']],
      ['PetalRAT', ['remote-access-trojan'], ['espionnage'], ['Petal']],
      ['ShadowLoom', ['backdoor'], ['espionnage'], []],
      ['MistDrop', ['dropper'], ['phishing'], []],
      ['CinderLock', ['ransomware'], ['ransomware'], ['Cinder']],
      ['ReedShell', ['webshell'], [], []],
      ['GlassKey', ['spyware'], ['financier'], ['GK-Stealer']],
      ['Lanternfly', ['backdoor'], ['espionnage'], []],
    ];
    const malwares = malwareDefs.map(([n, types, labs, aliases]) => add('Malware', n, {
      malware_types: types, is_family: true, aliases, labels: labs.map((l) => L[l]), createdBy: anyAuthor(),
      description: `Famille de malware fictive (${types.join(', ')}).`,
    }));

    // Modes opératoires (fictifs)
    const isDefs = [
      ['Crimson Heron', ['CH-17', 'Heron Group'], 'espionage', ['espionnage']],
      ['Glass Viper', ['GV'], 'financial-gain', ['financier']],
      ['Tidal Fox', ['TA-Fox'], 'espionage', ['espionnage']],
      ['Night Orchid', [], 'ideology', []],
      ['Iron Sparrow', ['Sparrow'], 'financial-gain', ['ransomware']],
      ['Pale Lantern', [], 'espionage', ['espionnage']],
      ['Copper Moth', ['CopperMoth', 'UNC-M0TH'], 'financial-gain', ['phishing']],
      ['Velvet Kraken', [], 'financial-gain', ['ransomware']],
      ['Silent Quarry', ['SQ'], 'espionage', ['infra-critique']],
      ['Hollow Reed', [], 'dominance', []],
      ['Amber Gecko', ['Gecko Team'], 'espionage', ['espionnage']],
      ['Ashen Wren', [], 'organizational-gain', ['à-revoir']],
    ];
    const intrusionSets = isDefs.map(([n, aliases, motivation, labs]) => add('Intrusion-Set', n, {
      aliases, primary_motivation: motivation, resource_level: pick(['team', 'organization', 'government']),
      first_seen: date(2019, 2023), last_seen: date(2025, 2026), goals: [],
      labels: labs.map((l) => L[l]), createdBy: anyAuthor(),
      markings: [pick([M['TLP:GREEN'], M['TLP:AMBER'], M['TLP:AMBER'], M['TLP:RED']])],
      description: 'Mode opératoire fictif utilisé pour le mock OpenDashboard.',
    }));

    const tags = [
      add('Threat-Actor-Group', 'Quarry Collective', { threat_actor_types: ['crime-syndicate'], aliases: [], createdBy: A['CERT-Lumen'] }),
      add('Threat-Actor-Group', 'Ninefold', { threat_actor_types: ['nation-state'], aliases: [], createdBy: A['Halcyon Threat Intel'] }),
    ];

    const campaigns = [
      ['Operation Low Tide', 'Tidal Fox'], ['Operation Paper Lantern', 'Pale Lantern'], ['Operation Cold Forge', 'Iron Sparrow'],
    ].map(([n]) => add('Campaign', n, { aliases: [], first_seen: date(2025, 2025), last_seen: date(2026, 2026), objective: null, createdBy: anyAuthor() }));

    // Relations
    const relationships = [];
    const relKey = new Set();
    function rel(type, from, to, extra = {}) {
      const f = typeof from === 'string' ? byName[from] : from;
      const t = typeof to === 'string' ? byName[to] : to;
      if (!f || !t) throw new Error(`Relation inconnue ${type} ${from} -> ${to}`);
      const k = `${f.id}|${type}|${t.id}`;
      if (relKey.has(k)) return null;
      relKey.add(k);
      const created = date(2025, 2026);
      const rr = {
        id: uuid(r), standard_id: `relationship--${uuid(r)}`, entity_type: type,
        parent_types: PARENTS['stix-core-relationship'], relationship_type: type,
        fromId: f.id, toId: t.id, confidence: 40 + Math.floor(r() * 60), created, created_at: created, updated_at: created,
        start_time: null, stop_time: null, description: null, createdBy: extra.createdBy || anyAuthor(),
        labels: [], markings: [M['TLP:GREEN']],
      };
      relationships.push(rr);
      return rr;
    }

    // --- Scénario QuartzLoader (déterministe) ---
    ['Crimson Heron', 'Tidal Fox', 'Copper Moth', 'Amber Gecko', 'Silent Quarry'].forEach((n) => rel('uses', n, 'QuartzLoader'));
    rel('drops', 'QuartzLoader', 'PetalRAT');
    rel('drops', 'QuartzLoader', 'CinderLock');
    rel('uses', 'QuartzLoader', 'Spearphishing Attachment');
    rel('uses', 'QuartzLoader', 'PowerShell');
    rel('uses', 'QuartzLoader', 'Obfuscated Files or Information');

    // Relations de fond (aucune n'implique QuartzLoader pour garder le scénario lisible)
    const otherMalwares = malwares.filter((m) => m.name !== 'QuartzLoader');
    intrusionSets.forEach((is) => {
      sample(otherMalwares, 1 + Math.floor(r() * 3)).forEach((m) => rel('uses', is, m));
      sample(tools, Math.floor(r() * 3)).forEach((t) => rel('uses', is, t));
      sample(attackPatterns, 2 + Math.floor(r() * 4)).forEach((ap) => rel('uses', is, ap));
      sample(sectors, 1 + Math.floor(r() * 3)).forEach((s) => rel('targets', is, s));
      sample(countries, 1 + Math.floor(r() * 3)).forEach((c) => rel('targets', is, c));
      if (r() < 0.35) rel('targets', is, pick(vulns));
    });
    otherMalwares.forEach((m) => sample(attackPatterns, 2 + Math.floor(r() * 3)).forEach((ap) => rel('uses', m, ap)));
    rel('attributed-to', 'Silent Quarry', 'Quarry Collective');
    rel('attributed-to', 'Hollow Reed', 'Quarry Collective');
    rel('attributed-to', 'Pale Lantern', 'Ninefold');
    rel('attributed-to', 'Operation Low Tide', 'Tidal Fox');
    rel('attributed-to', 'Operation Paper Lantern', 'Pale Lantern');
    rel('attributed-to', 'Operation Cold Forge', 'Iron Sparrow');
    rel('uses', 'Operation Cold Forge', 'CinderLock');

    // Rapports du scénario
    const ids = (...names) => names.map((n) => byName[n].id);
    const report = (name, objectNames, extra = {}) => add('Report', name, {
      report_types: extra.report_types || ['threat-report'], published: extra.published || date(2025, 2026),
      objects: ids(...objectNames), createdBy: extra.createdBy || anyAuthor(), labels: (extra.labels || []).map((l) => L[l]),
      markings: [extra.marking ? M[extra.marking] : M['TLP:AMBER']],
      description: extra.description || null,
    });
    report("QuartzLoader : nouvelle chaîne d'infection via fichiers ISO", ['Crimson Heron', 'Glass Viper', 'Spearphishing Attachment', 'France'],
      { labels: ['loader', 'phishing'], createdBy: A['CERT-Lumen'], published: '2026-03-12T09:00:00.000Z' });
    report('Analyse technique de QuartzLoader v3', ['QuartzLoader', 'Tidal Fox', 'PetalRAT', 'Obfuscated Files or Information'],
      { labels: ['loader'], createdBy: A['Halcyon Threat Intel'], published: '2026-05-02T09:00:00.000Z', report_types: ['malware-analysis'] });
    report('Campagne de phishing ciblant le secteur énergétique', ['QuartzLoader', 'Copper Moth', 'Night Orchid', 'Énergie', 'France', 'MistDrop'],
      { labels: ['phishing', 'infra-critique'], createdBy: A['CERT-Lumen'], published: '2026-06-18T09:00:00.000Z' });
    report('Bilan trimestriel ransomware T2 2026', ['CinderLock', 'QuartzLoader', 'Iron Sparrow', 'Velvet Kraken', 'Data Encrypted for Impact'],
      { labels: ['ransomware'], createdBy: A['SOC interne (mock)'], published: '2026-07-05T09:00:00.000Z', marking: 'TLP:RED' });
    report('Activité cyber en Asie-Pacifique', ['Amber Gecko', 'Japon', 'Inde', 'Lanternfly'],
      { labels: ['espionnage'], createdBy: A['Halcyon Threat Intel'], published: '2026-02-20T09:00:00.000Z' });

    // Rapports de fond (sans QuartzLoader ni dans le nom ni dans le contenu)
    const subjects = [
      ['Ransomware', ['ransomware']], ['Espionnage', ['espionnage']], ['Hameçonnage', ['phishing']],
      ['Vol de données bancaires', ['financier']], ['Infrastructures critiques', ['infra-critique']],
    ];
    // Silent Quarry reste volontairement absent de tout rapport (angle mort du scénario).
    const fillerIS = intrusionSets.filter((is) => is.name !== 'Silent Quarry');
    const pool = [...fillerIS, ...otherMalwares, ...tools, ...attackPatterns, ...sectors, ...countries, ...vulns, ...campaigns];
    for (let i = 0; i < 38; i++) {
      const [subject, labs] = pick(subjects);
      const target = pick([...sectors, ...countries]);
      const anchor = pick(fillerIS);
      const objs = new Set([anchor.name, target.name, ...sample(pool, 2 + Math.floor(r() * 5)).map((e) => e.name)]);
      report(`${subject} : activité de ${anchor.name} (${target.name})`, [...objs], {
        labels: r() < 0.2 ? [...labs, 'à-revoir'] : labs,
        report_types: [pick(['threat-report', 'threat-report', 'malware-analysis', 'internal-report'])],
        published: date(2025, 2026),
        marking: pick(['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER', 'TLP:RED']),
      });
    }

    add('Grouping', 'Pistes en cours — loaders', {
      context: 'suspicious-activity', objects: ids('QuartzLoader', 'MistDrop', 'Hollow Reed', 'Ashen Wren'), createdBy: A['SOC interne (mock)'],
    });

    // Vocabulaires (listes ouvertes OpenCTI) : valeurs par défaut + valeurs utilisées dans le jeu.
    const VOCAB = {
      report_types_ov: ['threat-report', 'internal-report', 'malware-analysis', 'attack-pattern', 'campaign', 'indicator', 'threat-actor', 'vulnerability'],
      attack_motivation_ov: ['accidental', 'coercion', 'dominance', 'ideology', 'notoriety', 'organizational-gain', 'personal-gain', 'personal-satisfaction', 'revenge', 'unpredictable'],
      attack_resource_level_ov: ['club', 'contest', 'government', 'individual', 'organization', 'team'],
      malware_type_ov: ['adware', 'backdoor', 'bot', 'bootkit', 'ddos', 'downloader', 'dropper', 'exploit-kit', 'keylogger', 'ransomware', 'remote-access-trojan', 'resource-exploitation', 'rogue-security-software', 'rootkit', 'screen-capture', 'spyware', 'trojan', 'unknown', 'virus', 'webshell', 'wiper', 'worm'],
      tool_types_ov: ['denial-of-service', 'exploitation', 'information-gathering', 'network-capture', 'credential-exploitation', 'remote-access', 'vulnerability-scanning', 'unknown'],
      threat_actor_group_type_ov: ['activist', 'competitor', 'crime-syndicate', 'criminal', 'hacker', 'insider-accidental', 'insider-disgruntled', 'nation-state', 'sensationalist', 'spy', 'terrorist', 'unknown'],
      grouping_context_ov: ['suspicious-activity', 'malware-analysis', 'unspecified'],
    };
    const VOCAB_FIELDS = {
      report_types: 'report_types_ov', primary_motivation: 'attack_motivation_ov', resource_level: 'attack_resource_level_ov',
      malware_types: 'malware_type_ov', tool_types: 'tool_types_ov', threat_actor_types: 'threat_actor_group_type_ov', context: 'grouping_context_ov',
    };
    const usages = {};
    entities.forEach((e) => Object.entries(VOCAB_FIELDS).forEach(([field, cat]) => {
      [].concat(e[field] || []).forEach((v) => {
        if (!VOCAB[cat].includes(v)) VOCAB[cat].push(v);
        usages[`${cat}|${v}`] = (usages[`${cat}|${v}`] || 0) + 1;
      });
    }));
    const vocabularies = [];
    Object.entries(VOCAB).forEach(([category, names]) => names.forEach((name, order) => vocabularies.push({
      id: uuid(r), standard_id: `vocabulary--${uuid(r)}`, category, name, description: null,
      usages: usages[`${category}|${name}`] || 0, aliases: [], builtIn: true, order,
    })));

    return { entities, relationships, labels, markings, vocabularies, parents: PARENTS };
  }

  OD.mockData = { build };
})(typeof window !== 'undefined' ? window : globalThis);
