/*
 * OpenDashboard — traduction d'une requête DSL en phrase française lisible.
 *
 *   OD.phrase.query(q, { html: true })
 *   → « les rapports publiés à partir du 1er janvier 2026 et qui contiennent des
 *       modes opératoires qui ciblent des secteurs dont le nom est « Énergie » ou « Transport » »
 *
 * Gère les articles et l'élision, l'accord en genre, les verbes des relations
 * (actif / passif selon le sens), la négation (« ne … pas de », « ni … ni »,
 * « aucun des ») et les dates en toutes lettres.
 */
(function (root) {
  'use strict';
  const OD = (root.OD = root.OD || {});
  const asList = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

  // ---------------------------------------------------------------------------
  // Noms des types : [singulier, pluriel, genre]
  // ---------------------------------------------------------------------------
  const NOUNS = {
    'Intrusion-Set': ['mode opératoire', 'modes opératoires', 'm'],
    'Threat-Actor-Group': ['acteur', 'acteurs', 'm'],
    'Threat-Actor-Individual': ['acteur individuel', 'acteurs individuels', 'm'],
    'Campaign': ['campagne', 'campagnes', 'f'],
    'Malware': ['malware', 'malwares', 'm'],
    'Tool': ['outil', 'outils', 'm'],
    'Attack-Pattern': ['technique', 'techniques', 'f'],
    'Vulnerability': ['vulnérabilité', 'vulnérabilités', 'f'],
    'Indicator': ['indicateur', 'indicateurs', 'm'],
    'Infrastructure': ['infrastructure', 'infrastructures', 'f'],
    'Incident': ['incident', 'incidents', 'm'],
    'Course-Of-Action': ['contre-mesure', 'contre-mesures', 'f'],
    'Channel': ['canal', 'canaux', 'm'],
    'Narrative': ['narratif', 'narratifs', 'm'],
    'Event': ['événement', 'événements', 'm'],
    'Report': ['rapport', 'rapports', 'm'],
    'Grouping': ['grouping', 'groupings', 'm'],
    'Note': ['note', 'notes', 'f'],
    'Case-Incident': ['cas', 'cas', 'm'],
    'Container': ['conteneur', 'conteneurs', 'm'],
    'Country': ['pays', 'pays', 'm'],
    'Region': ['région', 'régions', 'f'],
    'City': ['ville', 'villes', 'f'],
    'Sector': ['secteur', 'secteurs', 'm'],
    'Organization': ['organisation', 'organisations', 'f'],
    'Individual': ['individu', 'individus', 'm'],
    'Identity': ['identité', 'identités', 'f'],
    'Stix-Domain-Object': ['entité', 'entités', 'f'],
    'Stix-Core-Object': ['entité', 'entités', 'f'],
  };
  function nounOf(type) {
    const t = asList(type)[0];
    const n = NOUNS[t] || [t, t, 'm'];
    return { sg: n[0], pl: n[1], g: n[2] };
  }
  /** Nom d'un type au singulier (n = 1) ou au pluriel. */
  const noun = (type, n = 2) => { const x = nounOf(type); return n === 1 ? x.sg : x.pl; };

  // ---------------------------------------------------------------------------
  // Outils de langue
  // ---------------------------------------------------------------------------
  const startsWithVowel = (w) => /^[aeiouyhàâäéèêëîïôöûüù]/i.test(w);
  /** {s} → s / es, {e} → '' / e, {es} → '' / es selon le genre. */
  const agree = (tpl, g) => tpl.replace(/\{s\}/g, g === 'f' ? 'es' : 's').replace(/\{es\}/g, g === 'f' ? 'es' : '').replace(/\{e\}/g, g === 'f' ? 'e' : '');
  /** Négation d'un groupe verbal : « utilisent » → « n’utilisent pas », « font partie de » → « ne font pas partie de ». */
  function negateVerb(vp) {
    const words = vp.split(' ');
    if (words[0] === 'se' && words.length > 1) return `ne se ${words[1]} pas${words.length > 2 ? ` ${words.slice(2).join(' ')}` : ''}`;
    const [first, ...rest] = words;
    return `${startsWithVowel(first) ? 'n’' : 'ne '}${first} pas${rest.length ? ` ${rest.join(' ')}` : ''}`;
  }

  function makeCtx(opts) {
    const html = !!opts.html;
    const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    return {
      html,
      b: (s) => (html ? `<b>${esc(s)}</b>` : s),
      t: (s) => (html ? esc(s) : s),
      q: (v) => `« ${html ? esc(v) : v} »`,
    };
  }

  /** « « a » », « « a » ou « b » », « « a », « b » ou « c » » */
  function joinValues(values, ctx, last = 'ou') {
    const v = values.map(ctx.q);
    if (v.length <= 1) return v[0] || '';
    return `${v.slice(0, -1).join(', ')} ${last} ${v[v.length - 1]}`;
  }
  /** « ni « a » ni « b » » */
  const neither = (values, ctx) => values.map((v) => `ni ${ctx.q(v)}`).join(' ');

  const MONTHS = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'];
  function longDate(v) {
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return String(v);
    const day = d.getUTCDate();
    return `${day === 1 ? '1er' : day} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
  }

  // ---------------------------------------------------------------------------
  // Champs : [groupe nominal, genre] ; dates : participe accordé au sujet
  // ---------------------------------------------------------------------------
  const FIELDS = {
    name: ['le nom', 'm'], alias: ['un alias', 'm'], description: ['la description', 'f'],
    confidence: ['le niveau de confiance', 'm'], primary_motivation: ['la motivation principale', 'f'],
    report_types: ['le type de rapport', 'm'], x_mitre_id: ['l’identifiant MITRE', 'm'], malware_types: ['le type de malware', 'm'],
    resource_level: ['le niveau de ressources', 'm'], tool_types: ['le type d’outil', 'm'], threat_actor_types: ['le type d’acteur', 'm'],
    context: ['le contexte', 'm'], entity_type: ['le type', 'm'],
    created: ['la date de création', 'f'], published: ['la date de publication', 'f'], created_at: ['la date d’ajout à la plateforme', 'f'],
    modified: ['la date de modification', 'f'], updated_at: ['la date de mise à jour', 'f'],
    first_seen: ['la date de première observation', 'f'], last_seen: ['la date de dernière observation', 'f'],
  };
  const DATE_PARTICIPLES = {
    created: 'créé{s}', published: 'publié{s}', created_at: 'ajouté{s} à la plateforme', modified: 'modifié{s}', updated_at: 'mis{es} à jour',
    first_seen: 'observé{s} pour la première fois', last_seen: 'observé{s} pour la dernière fois',
  };
  const DATE_KEYS = new Set(Object.keys(DATE_PARTICIPLES));
  const DATE_OPS = { eq: 'le', gt: 'après le', gte: 'à partir du', lt: 'avant le', lte: 'jusqu’au', not_eq: 'ailleurs que le' };
  const NUM_OPS = { gt: 'supérieur{e} à', gte: 'supérieur{e} ou égal{e} à', lt: 'inférieur{e} à', lte: 'inférieur{e} ou égal{e} à' };

  function fieldClause(c, subjectG, ctx) {
    const [label, fg] = FIELDS[c.field] || [`le champ ${c.field}`, 'm'];
    const op = c.op || 'eq';
    const values = asList(c.value).filter((v) => v !== '' && v !== null);
    if (op === 'nil') return `dont ${label} n’est pas renseigné${fg === 'f' ? 'e' : ''}`;
    if (op === 'not_nil') return `dont ${label} est renseigné${fg === 'f' ? 'e' : ''}`;

    if (DATE_KEYS.has(c.field) && DATE_OPS[op]) {
      const dates = values.map((v) => ctx.t(longDate(v)));
      const part = agree(DATE_PARTICIPLES[c.field], subjectG);
      // « à partir du 1er janvier » / « avant le 3 mars »
      return `${part} ${DATE_OPS[op]} ${dates.join(' ou ')}`;
    }
    if (NUM_OPS[op]) return `dont ${label} est ${agree(NUM_OPS[op], fg)} ${values.map(ctx.t).join(' ou ')}`;

    const one = values.length <= 1;
    switch (op) {
      case 'eq': return `dont ${label} est ${joinValues(values, ctx)}`;
      case 'not_eq': return one ? `dont ${label} n’est pas ${joinValues(values, ctx)}` : `dont ${label} n’est ${neither(values, ctx)}`;
      case 'contains': return `dont ${label} contient ${joinValues(values, ctx)}`;
      case 'not_contains': return one ? `dont ${label} ne contient pas ${joinValues(values, ctx)}` : `dont ${label} ne contient ${neither(values, ctx)}`;
      case 'starts_with': return `dont ${label} commence par ${joinValues(values, ctx)}`;
      case 'not_starts_with': return `dont ${label} ne commence pas par ${joinValues(values, ctx)}`;
      case 'ends_with': return `dont ${label} se termine par ${joinValues(values, ctx)}`;
      case 'not_ends_with': return `dont ${label} ne se termine pas par ${joinValues(values, ctx)}`;
      default: return `dont ${label} ${op} ${joinValues(values, ctx)}`;
    }
  }

  // ---------------------------------------------------------------------------
  // Relations : [forme active (sujet = source), forme passive (sujet = cible)]
  // {s} s'accorde avec le sujet. null = pas de tournure naturelle → formulation générique.
  // ---------------------------------------------------------------------------
  const RELATIONS = {
    'uses': ['utilisent', 'sont utilisé{s} par'],
    'targets': ['ciblent', 'sont ciblé{s} par'],
    'attributed-to': ['sont attribué{s} à', 'se voient attribuer'],
    'drops': ['déposent', 'sont déposé{s} par'],
    'delivers': ['livrent', 'sont livré{s} par'],
    'downloads': ['téléchargent', 'sont téléchargé{s} par'],
    'exploits': ['exploitent', 'sont exploité{s} par'],
    'indicates': ['signalent', 'sont signalé{s} par'],
    'located-at': ['sont localisé{s} dans', null],
    'part-of': ['font partie de', 'comprennent'],
    'authored-by': ['sont créé{s} par', 'ont créé'],
    'mitigates': ['atténuent', 'sont atténué{s} par'],
    'communicates-with': ['communiquent avec', 'communiquent avec'],
    'variant-of': ['sont des variantes de', 'ont pour variantes'],
    'derived-from': ['dérivent de', null],
    'originates-from': ['sont originaires de', null],
    'subtechnique-of': ['sont des sous-techniques de', 'ont pour sous-techniques'],
    'compromises': ['compromettent', 'sont compromis{es} par'],
    'hosts': ['hébergent', 'sont hébergé{s} par'],
    'owns': ['possèdent', 'sont possédé{s} par'],
    'controls': ['contrôlent', 'sont contrôlé{s} par'],
    'belongs-to': ['appartiennent à', 'possèdent'],
    'impersonates': ['usurpent l’identité de', null],
    'based-on': ['sont fondé{s} sur', 'servent de base à'],
    'consists-of': ['se composent de', 'composent'],
    'characterizes': ['caractérisent', 'sont caractérisé{s} par'],
    'analysis-of': ['analysent', 'sont analysé{s} par'],
    'static-analysis-of': ['analysent (statiquement)', 'sont analysé{s} statiquement par'],
    'dynamic-analysis-of': ['analysent (dynamiquement)', 'sont analysé{s} dynamiquement par'],
    'remediates': ['corrigent', 'sont corrigé{s} par'],
    'detects': ['détectent', 'sont détecté{s} par'],
    'cooperates-with': ['coopèrent avec', 'coopèrent avec'],
    'participates-in': ['participent à', 'impliquent'],
    'employed-by': ['sont employé{s} par', 'emploient'],
    'reports-to': ['rendent compte à', 'supervisent'],
    'supports': ['soutiennent', 'sont soutenu{s} par'],
    'amplifies': ['amplifient', 'sont amplifié{s} par'],
    'publishes': ['publient', 'sont publié{s} par'],
    'related-to': ['sont lié{s} à', 'sont lié{s} à'],
    'revoked-by': ['sont révoqué{s} par', 'révoquent'],
    'investigates': ['enquêtent sur', 'font l’objet d’enquêtes de'],
    'has': ['ont', 'appartiennent à'],
    'beacons-to': ['émettent des balises vers', 'reçoivent des balises de'],
    'exfiltrates-to': ['exfiltrent des données vers', 'reçoivent des données exfiltrées par'],
    'should-cover': ['devraient couvrir', 'devraient être couvert{s} par'],
    'obs_belongs-to': ['appartiennent à', 'possèdent'],
    'obs_resolves-to': ['se résolvent en', null],
    'resolves-to': ['se résolvent en', null],
  };
  const SYMMETRIC = new Set(['communicates-with', 'cooperates-with', 'related-to']);
  const PREPOSITIONS = new Set(['à', 'de', 'par', 'avec', 'sur', 'dans', 'pour', 'vers', 'en']);

  /**
   * Complément après un groupe verbal : « utilisent des X » / « n’utilisent pas de X »,
   * « font partie de X », « sont attribués à des X ».
   */
  function objectAfter(vp, objNoun, plainNoun, negative) {
    const de = startsWithVowel(plainNoun) ? `d’${objNoun}` : `de ${objNoun}`;
    const last = vp.split(' ').pop();
    if (last === 'de') return { vp: vp.slice(0, -3), obj: de };
    if (PREPOSITIONS.has(last) || ['variantes', 'sous-techniques'].includes(last)) return { vp, obj: `des ${objNoun}` };
    return { vp, obj: negative ? de : `des ${objNoun}` };
  }

  // ---------------------------------------------------------------------------
  // Conditions
  // ---------------------------------------------------------------------------
  const isGroup = (c) => c && (Array.isArray(c.all) || Array.isArray(c.any));

  function joinClauses(parts, mode) {
    if (parts.length <= 1) return parts[0] || '';
    const word = mode === 'and' ? 'et' : 'ou';
    return `${parts.slice(0, -1).join(', ')} ${word} ${parts[parts.length - 1]}`;
  }

  function groupClause(c, subject, ctx, parentMode, trailing) {
    const mode = c.all ? 'and' : 'or';
    const list = c.all || c.any;
    const kids = list.map((k, i) => {
      const txt = condClause(k, subject, ctx, mode, trailing && i === list.length - 1);
      // Un participe (« publiés à partir du … ») qui n'ouvre pas le groupe devient « qui sont publiés … »
      const participle = k && k.field && DATE_KEYS.has(k.field) && DATE_OPS[k.op || 'eq'];
      return participle && i > 0 && txt ? `qui sont ${txt}` : txt;
    }).filter(Boolean);
    const text = joinClauses(kids, mode);
    // Parenthèses seulement quand un groupe change de mode à l'intérieur d'un autre
    return parentMode && parentMode !== mode && kids.length > 1 ? `(${text})` : text;
  }

  /**
   * Sous-requête comme complément : « modes opératoires qui ciblent … » (sans article).
   * Si la phrase continue après elle (trailing = false), ses conditions sont mises
   * entre parenthèses pour qu'on sache à quoi se rattache la suite.
   */
  function subQuery(q, ctx, trailing = true) {
    const n = nounOf(q.type);
    let s = ctx.b(n.pl);
    if (q.search) s += ` contenant le mot-clé ${ctx.q(q.search)}`;
    const w = q.where ? condClause(q.where, n, ctx, null, true) : '';
    if (!w) return s;
    return trailing ? `${s} ${w}` : `${s} (${w})`;
  }

  function relationClause(c, subject, ctx, trailing) {
    const rels = asList(c.relationship);
    const dir = c.direction || 'both';
    const neg = !!c.negate;
    const objNoun = subQuery(c.relatedTo, ctx, trailing);
    const g = subject.g;

    if (rels.length === 1 && RELATIONS[rels[0]]) {
      const [act, pass] = RELATIONS[rels[0]];
      let tpl = null;
      if (dir === 'out' || SYMMETRIC.has(rels[0])) tpl = act;
      else if (dir === 'in') tpl = pass;
      if (tpl) {
        const vp0 = agree(tpl, g);
        const { vp, obj } = objectAfter(vp0, objNoun, nounOf(c.relatedTo.type).pl, neg);
        return `qui ${neg ? negateVerb(vp) : vp} ${obj}`;
      }
    }
    const relText = rels.length ? `par une relation ${rels.map(ctx.q).join(' ou ')} ` : '';
    if (dir === 'in' && rels.length) {
      return `qui ${neg ? 'ne sont pas' : 'sont'} la cible d’une relation ${rels.map(ctx.q).join(' ou ')} depuis des ${objNoun}`;
    }
    if (dir === 'out' && rels.length) {
      return `qui ${neg ? 'n’ont pas' : 'ont'} de relation ${rels.map(ctx.q).join(' ou ')} vers des ${objNoun}`;
    }
    const sens = rels.length && dir === 'both' ? '(dans un sens ou l’autre) ' : '';
    const lie = agree('lié{s}', g);
    return `qui ${neg ? `ne sont pas ${lie}` : `sont ${lie}`} ${relText}${sens}à des ${objNoun}`;
  }

  function condClause(c, subject, ctx, parentMode, trailing = true) {
    if (!c) return '';
    if (isGroup(c)) return groupClause(c, subject, ctx, parentMode, trailing);
    if (c.field) return fieldClause(c, subject.g, ctx);
    const neg = !!c.negate || c.op === 'not_eq';
    if (c.label !== undefined) {
      const v = asList(c.label);
      const what = v.length > 1 ? `l’un des libellés ${joinValues(v, ctx)}` : `le libellé ${joinValues(v, ctx)}`;
      return `qui ${neg ? 'ne portent pas' : 'portent'} ${what}`;
    }
    if (c.author !== undefined) {
      const v = asList(c.author);
      return neg ? `dont l’auteur n’est ${v.length > 1 ? neither(v, ctx) : `pas ${joinValues(v, ctx)}`}` : `dont l’auteur est ${joinValues(v, ctx)}`;
    }
    if (c.marking !== undefined) {
      const v = asList(c.marking);
      return neg ? `dont le marquage n’est ${v.length > 1 ? neither(v, ctx) : `pas ${joinValues(v, ctx)}`}` : `dont le marquage est ${joinValues(v, ctx)}`;
    }
    if (c.relatedTo) return relationClause(c, subject, ctx, trailing);
    if (c.containedIn) {
      const cn = nounOf(c.containedIn.type);
      const aucun = cn.g === 'f' ? 'aucune' : 'aucun';
      if (c.negate && !c.containedIn.where && !c.containedIn.search) return `qui ne figurent dans ${aucun} ${ctx.b(cn.sg)}`;
      if (c.negate) return `qui ne figurent dans ${aucun} des ${subQuery(c.containedIn, ctx, trailing)}`;
      return `qui figurent dans des ${subQuery(c.containedIn, ctx, trailing)}`;
    }
    if (c.contains) {
      const sq = subQuery(c.contains, ctx, trailing);
      const plain = nounOf(c.contains.type).pl;
      return c.negate ? `qui ne contiennent pas ${startsWithVowel(plain) ? 'd’' : 'de '}${sq}` : `qui contiennent des ${sq}`;
    }
    if (c.ids) return `${c.negate ? 'hors' : 'parmi'} ${asList(c.ids).length} identifiant(s) désigné(s)`;
    return '';
  }

  /** Phrase complète : « les rapports publiés … ». */
  function query(q, opts = {}) {
    const ctx = makeCtx(opts);
    return `les ${subQuery(q, ctx)}`;
  }

  OD.phrase = { query, noun, nounOf, longDate, RELATIONS };
})(typeof window !== 'undefined' ? window : globalThis);
