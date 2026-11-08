/*
 * OpenDashboard — interface : constructeur de requêtes, tableau de bord,
 * journal GraphQL et réglages. Aucune dépendance hormis graphql-js, chargé
 * à la demande depuis jsDelivr pour le mock uniquement.
 */
(function () {
  'use strict';
  const OD = window.OD;
  // graphql-js (mock uniquement) : copie locale dans vendor/, aucun accès réseau.
  const GRAPHQL_LOCAL = 'vendor/graphql-16.9.0.min.js';
  function loadGraphql() {
    if (window.graphql && window.graphql.buildSchema) return Promise.resolve(window.graphql);
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = GRAPHQL_LOCAL;
      s.onload = () => (window.graphql ? resolve(window.graphql) : reject(new Error('graphql absent')));
      s.onerror = () => reject(new Error(`${GRAPHQL_LOCAL} introuvable`));
      document.head.append(s);
    });
  }

  // ---------------------------------------------------------------------------
  // Utilitaires
  // ---------------------------------------------------------------------------
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  function h(tag, props, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k === 'style') e.setAttribute('style', v);
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'value') e.value = v;
      else if (k === 'checked') e.checked = !!v;
      else e.setAttribute(k, v === true ? '' : v);
    }
    kids.flat(Infinity).forEach((c) => { if (c !== null && c !== undefined && c !== false) e.append(c.nodeType ? c : String(c)); });
    return e;
  }
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* stockage indisponible */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* idem */ } },
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const asList = OD.dsl.asList;
  const fmtDate = (d) => (d ? new Date(d).toLocaleDateString('fr-FR', { year: 'numeric', month: 'short', day: '2-digit' }) : '—');
  const parseList = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
  let toastTimer;
  function toast(msg) {
    let t = $('.toast');
    if (!t) { t = h('div', { class: 'toast', role: 'status' }); document.body.append(t); }
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast('Copié dans le presse-papiers'); return true; }
    catch { toast('Copie refusée par le navigateur : sélectionnez le texte manuellement'); return false; }
  }

  // ---------------------------------------------------------------------------
  // Vocabulaire OpenCTI
  // ---------------------------------------------------------------------------
  const TYPES = [
    ['Intrusion-Set', 'Modes opératoires (Intrusion-Set)'],
    ['Threat-Actor-Group', 'Acteurs de la menace (groupe)'],
    ['Campaign', 'Campagnes'],
    ['Malware', 'Malwares'],
    ['Tool', 'Outils'],
    ['Attack-Pattern', 'Techniques (Attack-Pattern)'],
    ['Threat-Actor-Individual', 'Acteurs de la menace (individu)'],
    ['Vulnerability', 'Vulnérabilités'],
    ['Indicator', 'Indicateurs'],
    ['Infrastructure', 'Infrastructures'],
    ['Incident', 'Incidents'],
    ['Course-Of-Action', 'Contre-mesures'],
    ['Channel', 'Canaux'],
    ['Narrative', 'Narratifs'],
    ['Event', 'Événements'],
    ['Report', 'Rapports'],
    ['Grouping', 'Groupings'],
    ['Note', 'Notes'],
    ['Case-Incident', 'Cas (incident)'],
    ['Container', 'Tous conteneurs'],
    ['Country', 'Pays'],
    ['Region', 'Régions'],
    ['City', 'Villes'],
    ['Sector', 'Secteurs'],
    ['Organization', 'Organisations'],
    ['Individual', 'Individus'],
    ['Identity', 'Identités'],
    ['Stix-Domain-Object', 'Toutes entités (SDO)'],
  ];
  const TYPE_PLURAL = {
    'Intrusion-Set': ['mode opératoire', 'modes opératoires'], 'Threat-Actor-Group': ['acteur', 'acteurs'], 'Campaign': ['campagne', 'campagnes'],
    'Malware': ['malware', 'malwares'], 'Tool': ['outil', 'outils'], 'Attack-Pattern': ['technique', 'techniques'],
    'Vulnerability': ['vulnérabilité', 'vulnérabilités'], 'Report': ['rapport', 'rapports'], 'Grouping': ['grouping', 'groupings'],
    'Container': ['conteneur', 'conteneurs'], 'Country': ['pays', 'pays'], 'Sector': ['secteur', 'secteurs'],
    'Organization': ['organisation', 'organisations'], 'Identity': ['identité', 'identités'], 'Stix-Domain-Object': ['entité', 'entités'],
    'Threat-Actor-Individual': ['acteur individuel', 'acteurs individuels'], 'Indicator': ['indicateur', 'indicateurs'],
    'Infrastructure': ['infrastructure', 'infrastructures'], 'Incident': ['incident', 'incidents'], 'Course-Of-Action': ['contre-mesure', 'contre-mesures'],
    'Channel': ['canal', 'canaux'], 'Narrative': ['narratif', 'narratifs'], 'Event': ['événement', 'événements'], 'Note': ['note', 'notes'],
    'Case-Incident': ['cas', 'cas'], 'Region': ['région', 'régions'], 'City': ['ville', 'villes'], 'Individual': ['individu', 'individus'],
  };
  const noun = (t, n = 2) => (TYPE_PLURAL[t] || [t, t])[n > 1 || n === 0 ? 1 : 0];
  const CONTAINER_TYPES = ['Report', 'Grouping', 'Note', 'Case-Incident', 'Container'];
  const FIELDS = [
    ['name', 'Nom'], ['alias', 'Alias'], ['description', 'Description'], ['confidence', 'Confiance (0-100)'],
    ['created', 'Date de création'], ['published', 'Date de publication'], ['created_at', 'Ajouté à la plateforme'],
    ['primary_motivation', 'Motivation principale'], ['report_types', 'Type de rapport'], ['x_mitre_id', 'ID MITRE'],
    ['malware_types', 'Type de malware'], ['resource_level', 'Niveau de ressources'], ['tool_types', 'Type d’outil'],
    ['threat_actor_types', 'Type d’acteur'], ['context', 'Contexte (grouping)'], ['entity_type', 'Type d’entité'],
  ];
  // Champs à valeurs ouvertes (vocabulaires OpenCTI) → catégorie de vocabulaire
  const VOCAB_FIELDS = {
    report_types: 'report_types_ov', primary_motivation: 'attack_motivation_ov', resource_level: 'attack_resource_level_ov',
    malware_types: 'malware_type_ov', tool_types: 'tool_types_ov', threat_actor_types: 'threat_actor_group_type_ov', context: 'grouping_context_ov',
  };
  const DATE_KEYS = new Set(['created', 'published', 'created_at', 'modified', 'updated_at', 'first_seen', 'last_seen']);
  const OPS = [
    ['eq', 'est'], ['not_eq', 'n’est pas'], ['contains', 'contient'], ['not_contains', 'ne contient pas'],
    ['starts_with', 'commence par'], ['ends_with', 'finit par'], ['gt', '>'], ['gte', '≥'], ['lt', '<'], ['lte', '≤'],
    ['nil', 'est vide'], ['not_nil', 'est renseigné'],
  ];
  const OP_LABEL = Object.fromEntries(OPS);
  const DATE_OPS = { gt: 'après le', gte: 'à partir du', lt: 'avant le', lte: 'jusqu’au' };

  // Table des relations : copie embarquée (OpenCTI 6.7.7) en attendant celle de l'instance.
  let relMap = { mapping: (OD.relationsMapping || {}).mapping || {}, source: 'embarquée' };
  function loadRelMap() {
    engine.relationsMapping().then((m) => { relMap = m; if (draft) renderBuilder(); }).catch(() => {});
  }

  // ---------------------------------------------------------------------------
  // Réglages et transport
  // ---------------------------------------------------------------------------
  const settings = Object.assign(
    { mode: 'mock', url: '', token: '', remember: false, strategy: 'regardingOf', pageSize: 500, maxItems: 5000 },
    store.get('od.settings', {}),
  );
  const transport = new OD.Transport();
  const engine = new OD.Engine(transport);
  let mockPromise = null;

  function applySettings() {
    transport.configure({ mode: settings.mode, url: settings.url, token: settings.token });
    Object.assign(engine.options, {
      relatedStrategy: settings.strategy,
      pageSize: Number(settings.pageSize) || 500,
      maxItems: Number(settings.maxItems) || 5000,
    });
    renderSource();
  }

  function saveSettings() {
    const persisted = { ...settings };
    if (!settings.remember) persisted.token = '';
    store.set('od.settings', persisted);
  }

  async function ensureReady() {
    if (settings.mode !== 'mock') return;
    if (!mockPromise) {
      setSource('busy', 'Chargement du mock…');
      mockPromise = (async () => {
        const graphql = await loadGraphql();
        const server = OD.createMockServer(graphql, OD.mockData.build());
        transport.configure({ mock: server });
        return server;
      })();
      mockPromise.then(renderSource, (e) => {
        mockPromise = null;
        setSource('err', 'Mock indisponible');
        toast(`Impossible de charger graphql-js : ${e.message}`);
      });
    }
    await mockPromise;
  }

  function setSource(state, label) {
    $('#source-dot').className = `dot ${state}`;
    $('#source-label').textContent = label;
  }

  function renderSource() {
    if (settings.mode === 'mock') {
      if (!mockPromise) return setSource('', 'Mock');
      mockPromise.then((s) => setSource('ok', `Mock 6.7.7 · ${s.stats.entities} entités · ${s.stats.relationships} relations`)).catch(() => {});
    } else {
      let host = settings.url;
      try { host = new URL(settings.url).host; } catch { /* URL incomplète */ }
      setSource(settings.url ? 'ok' : 'err', settings.url ? `OpenCTI · ${host}` : 'OpenCTI · URL manquante');
    }
  }

  // ---------------------------------------------------------------------------
  // Routage par onglets
  // ---------------------------------------------------------------------------
  const TABS = ['tableau', 'explorateur', 'journal', 'reglages'];
  function route() {
    const tab = TABS.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'tableau';
    $$('[data-view]').forEach((s) => { s.hidden = s.dataset.view !== tab; });
    $$('.tabs a').forEach((a) => { if (a.dataset.tab === tab) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    if (tab === 'journal') renderLog();
  }
  function go(tab) { if (location.hash !== `#${tab}`) location.hash = tab; else route(); window.scrollTo({ top: 0 }); }

  // ---------------------------------------------------------------------------
  // Constructeur de requêtes
  // ---------------------------------------------------------------------------
  let draft = null;       // requête en cours d'édition (DSL)
  let lastRun = null;     // dernier résultat de l'explorateur
  let editingWidget = null;

  const isGroup = (c) => c && (Array.isArray(c.all) || Array.isArray(c.any));
  function normalize(q) {
    if (!q.where) q.where = { all: [] };
    else if (!isGroup(q.where)) q.where = { all: [q.where] };
    return q;
  }

  function cleanCond(c) {
    if (isGroup(c)) {
      const key = c.all ? 'all' : 'any';
      const kids = c[key].map(cleanCond).filter(Boolean);
      if (!kids.length) return null;
      if (kids.length === 1) return kids[0];
      return { [key]: kids };
    }
    const out = clone(c);
    if (out.relatedTo) out.relatedTo = cleanQuery(out.relatedTo);
    if (out.containedIn) out.containedIn = cleanQuery(out.containedIn);
    if (out.contains) out.contains = cleanQuery(out.contains);
    if ('relationship' in out && !asList(out.relationship).length) delete out.relationship;
    if (out.negate === false) delete out.negate;
    if (out.field && !['nil', 'not_nil'].includes(out.op) && !asList(out.value).filter((v) => v !== '').length) return null;
    if (out.label !== undefined && !asList(out.label).length) return null;
    if (out.author !== undefined && !asList(out.author).length) return null;
    if (out.marking !== undefined && !asList(out.marking).length) return null;
    return out;
  }

  function cleanQuery(q) {
    const out = { type: q.type };
    if (q.search && q.search.trim()) out.search = q.search.trim();
    const w = q.where ? cleanCond(q.where) : null;
    if (w) out.where = w;
    return out;
  }

  function sel(options, current, onchange, attrs = {}) {
    return h('select', { ...attrs, onchange: (e) => onchange(e.target.value) },
      options.map(([v, l]) => h('option', { value: v, selected: v === current ? 'selected' : null }, l)));
  }

  // Sélecteur multi-valeurs alimenté par la base (libellés, marquages, vocabulaires…)
  function picker({ values, load, onChange, placeholder, freeText = false, single = false, preload = false, validate = null }) {
    const missing = new Set();
    let selected = asList(values).filter((v) => v !== '' && v !== null && v !== undefined);
    const colors = new Map();
    let opts = [], loading = false, error = null, timer = null, reqId = 0;
    const root = h('div', { class: 'picker' });
    const input = h('input', { type: 'text', autocomplete: 'off', 'aria-label': placeholder, 'aria-autocomplete': 'list' });
    const box = h('div', { class: 'picker-box', onclick: () => input.focus() });
    const list = h('div', { class: 'picker-list', role: 'listbox', hidden: true });
    root.append(box, list);

    const emit = () => { onChange(selected.slice()); renderChips(); renderList(); check(); };
    // Signale les valeurs qui n'existent pas en base (ex. nom inconnu pour le type choisi)
    async function check() {
      if (!validate) return;
      try {
        await ensureReady();
        const res = await validate(selected.slice());
        missing.clear(); res.forEach((v) => missing.add(v));
        renderChips();
      } catch { /* ignorer : simple aide à la saisie */ }
    }
    function toggle(v) {
      if (selected.includes(v)) selected = selected.filter((x) => x !== v);
      else selected = single ? [v] : [...selected, v];
      if (single) close();
      emit();
    }
    function renderChips() {
      box.replaceChildren(...selected.map((v) => h('span', { class: `pchip${missing.has(v) ? ' missing' : ''}`, title: missing.has(v) && validate ? validate.message(v) : null },
        colors.get(v) ? h('i', { style: `background:${colors.get(v)}` }) : null, missing.has(v) ? '⚠ ' : null, v,
        h('button', { type: 'button', 'aria-label': `Retirer ${v}`, onclick: (e) => { e.stopPropagation(); toggle(v); } }, '✕'))), input);
      input.placeholder = selected.length ? '' : placeholder;
    }
    function renderList() {
      const typed = input.value.trim();
      const items = opts.map((o) => h('button', {
        type: 'button', role: 'option', 'aria-selected': String(selected.includes(o.value)),
        onclick: (e) => { e.stopPropagation(); toggle(o.value); },
      }, h('span', { class: 'pcheck' }, selected.includes(o.value) ? '✓' : ''),
      o.color ? h('i', { style: `background:${o.color}` }) : null,
      h('span', { class: 'plabel' }, o.label), o.hint ? h('small', {}, o.hint) : null));
      if (freeText && typed && !opts.some((o) => o.value === typed)) {
        items.push(h('button', { type: 'button', class: 'pfree', onclick: (e) => { e.stopPropagation(); input.value = ''; toggle(typed); } }, `Utiliser « ${typed} »`));
      }
      if (!items.length) items.push(h('div', { class: 'pempty' }, loading ? 'Chargement…' : error ? `Erreur : ${error}` : 'Aucune valeur correspondante en base.'));
      list.replaceChildren(...items);
    }
    async function refresh() {
      const id = ++reqId;
      loading = true; error = null; renderList();
      try {
        await ensureReady();
        const r = await load(input.value.trim());
        if (id !== reqId) return;
        opts = r;
        r.forEach((o) => o.color && colors.set(o.value, o.color));
        renderChips();
      } catch (e) { if (id === reqId) { opts = []; error = e.message; } }
      loading = false;
      if (id === reqId) renderList();
    }
    function open() { if (!list.hidden) return; closePickers(root); list.hidden = false; root.classList.add('open'); refresh(); }
    function close() { list.hidden = true; root.classList.remove('open'); }
    root._close = close;
    input.addEventListener('focus', open);
    input.addEventListener('click', open);
    input.addEventListener('input', () => { list.hidden = false; clearTimeout(timer); timer = setTimeout(refresh, 180); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { close(); input.blur(); }
      else if (e.key === 'Enter') {
        e.preventDefault();
        const typed = input.value.trim();
        const match = opts.find((o) => o.value.toLowerCase() === typed.toLowerCase()) || (typed ? opts[0] : null);
        if (match) { input.value = ''; toggle(match.value); } else if (freeText && typed) { input.value = ''; toggle(typed); }
      } else if (e.key === 'Backspace' && !input.value && selected.length) toggle(selected[selected.length - 1]);
    });
    renderChips();
    check();
    if (preload && selected.length) {
      Promise.resolve().then(ensureReady).then(() => load('')).then((r) => { r.forEach((o) => o.color && colors.set(o.value, o.color)); renderChips(); }).catch(() => {});
    }
    return root;
  }
  function closePickers(except) { $$('.picker.open').forEach((p) => { if (p !== except && p._close) p._close(); }); }
  document.addEventListener('click', (e) => { if (!e.target.closest('.picker')) closePickers(); });

  const setValue = (c) => (arr) => { c.value = arr.length > 1 ? arr : (arr[0] || ''); syncDraft(); };

  function valueEditor(c, ctxType) {
    if (['nil', 'not_nil'].includes(c.op)) return null;
    if (DATE_KEYS.has(c.field)) {
      return h('input', {
        type: 'date', value: String(asList(c.value)[0] || '').slice(0, 10), 'aria-label': 'Date',
        oninput: (e) => { c.value = e.target.value ? `${e.target.value}T00:00:00.000Z` : ''; syncDraft(); },
      });
    }
    const exact = ['eq', 'not_eq', undefined].includes(c.op);
    if (exact && VOCAB_FIELDS[c.field]) {
      return picker({ values: c.value, onChange: setValue(c), placeholder: 'choisir dans le vocabulaire…', freeText: true,
        load: (q) => engine.suggest('vocabulary', { search: q, category: VOCAB_FIELDS[c.field] }) });
    }
    if (exact && (c.field === 'name' || c.field === 'alias')) {
      let validate = null;
      if (c.field === 'name') {
        validate = async (vals) => {
          const out = [];
          for (const v of vals) {
            const found = await engine.suggest('entity', { search: v, types: [ctxType] });
            if (!found.some((o) => String(o.value).toLowerCase() === String(v).toLowerCase())) out.push(v);
          }
          return out;
        };
        validate.message = (v) => `Aucun(e) ${noun(ctxType, 1)} nommé(e) « ${v} » en base : changez le type de ce bloc ou le nom.`;
      }
      return picker({ values: c.value, onChange: setValue(c), placeholder: `chercher parmi les ${noun(ctxType)}…`, freeText: true, validate,
        load: (q) => engine.suggest('entity', { search: q, types: [ctxType] }) });
    }
    if (exact && c.field === 'entity_type') {
      return picker({ values: c.value, onChange: setValue(c), placeholder: 'type…',
        load: async (q) => TYPES.filter(([v, l]) => !q || `${v} ${l}`.toLowerCase().includes(q.toLowerCase())).map(([v, l]) => ({ value: v, label: v, hint: l })) });
    }
    return h('input', {
      type: 'text', value: asList(c.value).join(', '), placeholder: 'valeur (plusieurs : séparées par des virgules)', 'aria-label': 'Valeur',
      oninput: (e) => { const l = parseList(e.target.value); c.value = l.length > 1 ? l : (l[0] || ''); syncDraft(); },
    });
  }

  // Sélecteur de relation : uniquement les relations permises entre les deux types, avec le sens.
  function relationSelect(c, srcType, tgtType) {
    const { out, in: inn } = OD.types.possibleRelations(relMap.mapping, srcType, tgtType);
    const S = noun(srcType, 1), T = noun(tgtType, 1);
    const rels = asList(c.relationship);
    const dir = c.direction || 'both';
    const current = rels.length === 0 ? `*|${dir}` : rels.length === 1 ? `${rels[0]}|${dir}` : `${rels.join(',')}|${dir}`;
    const groups = [
      ['Tout type de relation', [['*|both', 'Toute relation, peu importe le sens'], ['*|out', `Toute relation ${S} → ${T}`], ['*|in', `Toute relation ${T} → ${S}`]]],
      [`Sortantes : ${S} → ${T}`, out.map((r) => [`${r}|out`, `${S} —${r}→ ${T}`])],
      [`Entrantes : ${T} → ${S}`, inn.map((r) => [`${r}|in`, `${T} —${r}→ ${S}`])],
      ['Peu importe le sens', [...new Set([...out, ...inn, 'related-to'])].sort().map((r) => [`${r}|both`, `${r} (dans un sens ou l’autre)`])],
    ];
    const known = groups.some(([, opts]) => opts.some(([v]) => v === current));
    const select = h('select', {
      'aria-label': 'Relation', class: 'rel-select',
      onchange: (e) => {
        const [r, d] = e.target.value.split('|');
        c.relationship = r === '*' ? [] : r.split(',');
        c.direction = d;
        if (d === 'both') delete c.direction;
        syncDraft();
      },
    },
    known ? null : h('option', { value: current, selected: 'selected' }, `${rels.join(', ')} (${dir}) — hors schéma`),
    groups.map(([label, opts]) => h('optgroup', { label },
      opts.length ? opts.map(([v, l]) => h('option', { value: v, selected: v === current ? 'selected' : null }, l))
        : h('option', { disabled: true, value: '' }, 'aucune relation prévue par le schéma'))));
    return select;
  }

  function renderBuilder() {
    const root = $('#builder');
    root.replaceChildren(renderQueryBox(draft, { nested: false, verb: 'Chercher' }));
    syncDraft();
  }

  function syncDraft() {
    const q = cleanQuery(draft);
    $('#sentence').innerHTML = `Recherche : ${phraseQuery(q, true)}.`;
    if (document.activeElement !== $('#json')) $('#json').value = JSON.stringify(q, null, 2);
    store.set('od.draft', draft);
  }

  function renderQueryBox(q, { nested, verb, help }) {
    normalize(q);
    const types = nested === 'container' ? TYPES.filter(([v]) => CONTAINER_TYPES.includes(v)) : TYPES;
    return h('div', { class: `qbox${nested ? ' nested' : ''}` },
      help ? h('div', { class: 'qhelp' }, help) : null,
      h('div', { class: 'qhead' },
        h('span', { class: 'verb' }, verb),
        sel(types, q.type, (v) => { q.type = v; renderBuilder(); }, { 'aria-label': 'Type d’entité' }),
        h('input', { type: 'text', value: q.search || '', placeholder: 'mot-clé (facultatif)', 'aria-label': 'Recherche plein texte', oninput: (e) => { q.search = e.target.value; syncDraft(); } })),
      renderGroup(q.where, true, q.type));
  }

  function renderGroup(g, isRoot, ctxType) {
    const key = g.all ? 'all' : 'any';
    const list = g[key];
    const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Combinaison' },
      h('button', { type: 'button', 'aria-pressed': String(key === 'all'), onclick: () => { if (key !== 'all') { g.all = g.any; delete g.any; renderBuilder(); } } }, 'Toutes'),
      h('button', { type: 'button', 'aria-pressed': String(key === 'any'), onclick: () => { if (key !== 'any') { g.any = g.all; delete g.all; renderBuilder(); } } }, 'Au moins une'));
    const kids = h('div', { class: `children${key === 'any' ? ' or' : ''}` },
      list.map((c, i) => renderCond(c, list, i, ctxType)));
    return h('div', { class: 'group' },
      h('div', { class: 'group-bar' },
        list.length > 1 || !isRoot ? seg : null,
        h('span', { class: 'hint' }, list.length ? (key === 'all' ? 'des conditions suivantes' : 'des conditions suivantes') : (isRoot ? 'Aucune condition : toutes les entités du type.' : 'Groupe vide.')),
        addMenu(list)),
      list.length ? kids : null);
  }

  const ADD_ITEMS = [
    ['Attribut', 'Nom, alias, date, confiance…', () => ({ field: 'name', op: 'contains', value: '' })],
    ['Libellé', 'Porte un ou plusieurs libellés', () => ({ label: [] })],
    ['Auteur', 'Créé par une organisation', () => ({ author: [] })],
    ['Marquage', 'TLP ou autre marquage', () => ({ marking: [] })],
    ['Lié à…', 'A une relation avec le résultat d’une sous-requête', () => ({ relatedTo: { type: 'Malware', where: { all: [{ field: 'name', op: 'eq', value: '' }] } }, relationship: [] })],
    ['Contenu dans…', 'Figure dans un rapport / conteneur filtré', () => ({ containedIn: { type: 'Report', where: { all: [{ field: 'name', op: 'contains', value: '' }] } } })],
    ['Contient…', 'Conteneur qui contient le résultat d’une sous-requête', () => ({ contains: { type: 'Intrusion-Set', where: { all: [] } } })],
    ['Groupe de conditions', 'Imbriquer des « toutes » / « au moins une »', () => ({ any: [] })],
  ];

  function addMenu(list) {
    const wrap = h('div', { class: 'addmenu' });
    const btn = h('button', { type: 'button', class: 'btn small', 'aria-expanded': 'false' }, '+ Condition');
    const menu = h('div', { class: 'addmenu-list', role: 'menu', hidden: true },
      ADD_ITEMS.map(([title, sub, make]) => h('button', {
        type: 'button', role: 'menuitem',
        onclick: () => { list.push(make()); closeMenus(); renderBuilder(); },
      }, h('b', {}, title), h('small', {}, sub))));
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = menu.hidden;
      closeMenus();
      menu.hidden = !open;
      btn.setAttribute('aria-expanded', String(open));
    });
    wrap.append(btn, menu);
    return wrap;
  }
  function closeMenus() { $$('.addmenu-list').forEach((m) => { m.hidden = true; }); $$('.addmenu > .btn').forEach((b) => b.setAttribute('aria-expanded', 'false')); }
  document.addEventListener('click', (e) => { if (!e.target.closest('.addmenu')) closeMenus(); });

  function removeBtn(list, i) {
    return h('button', { type: 'button', class: 'btn small ghost x', 'aria-label': 'Supprimer la condition', onclick: () => { list.splice(i, 1); renderBuilder(); } }, '✕');
  }

  function negateBox(c, label) {
    return h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: !!c.negate, onchange: (e) => { c.negate = e.target.checked; syncDraft(); } }), label);
  }

  function renderCond(c, list, i, ctxType) {
    if (isGroup(c)) {
      return h('div', { class: 'cond' }, h('div', { class: 'cond-row' }, h('span', { class: 'cond-kind' }, 'groupe'), removeBtn(list, i)), renderGroup(c, false, ctxType));
    }
    if (c.field) {
      const editor = valueEditor(c, ctxType);
      return h('div', { class: 'cond' },
        h('div', { class: 'cond-row' },
          h('span', { class: 'cond-kind' }, 'attribut'),
          sel(FIELDS, c.field, (v) => { const wasDate = DATE_KEYS.has(c.field); c.field = v; if (wasDate !== DATE_KEYS.has(v) || VOCAB_FIELDS[v]) c.value = ''; renderBuilder(); }, { 'aria-label': 'Champ' }),
          sel(OPS, c.op || 'eq', (v) => { c.op = v; renderBuilder(); }, { 'aria-label': 'Opérateur' }),
          removeBtn(list, i)),
        editor);
    }
    const DYN = {
      label: ['libellé', 'choisir des libellés…', (q) => engine.suggest('label', { search: q })],
      author: ['auteur', 'choisir des auteurs…', (q) => engine.suggest('author', { search: q })],
      marking: ['marquage', 'choisir des marquages…', (q) => engine.suggest('marking', { search: q })],
    };
    for (const [key, [kind, ph, load]] of Object.entries(DYN)) {
      if (c[key] !== undefined) {
        return h('div', { class: 'cond' },
          h('div', { class: 'cond-row' }, h('span', { class: 'cond-kind' }, kind), negateBox(c, 'exclure'), removeBtn(list, i)),
          picker({ values: c[key], load, placeholder: ph, preload: key !== 'author', onChange: (arr) => { c[key] = arr; syncDraft(); } }));
      }
    }
    if (c.relatedTo) {
      normalize(c.relatedTo);
      return h('div', { class: 'cond' },
        h('div', { class: 'cond-row' },
          h('span', { class: 'cond-kind' }, 'lié à'),
          relationSelect(c, ctxType, c.relatedTo.type),
          negateBox(c, 'exclure'),
          removeBtn(list, i)),
        h('div', { class: 'rel-src muted' }, `Relations proposées d’après la table ${relMap.source === 'instance' ? 'de l’instance' : 'embarquée (OpenCTI 6.7.7)'}.`),
        renderQueryBox(c.relatedTo, { nested: true, verb: 'avec des', help: `Ce bloc décrit l’entité à l’autre bout de la relation (le « X »), pas les ${noun(ctxType)} recherchés.` }));
    }
    if (c.containedIn) {
      return h('div', { class: 'cond' },
        h('div', { class: 'cond-row' }, h('span', { class: 'cond-kind' }, 'contenu dans'), negateBox(c, 'exclure (absent de ces conteneurs)'), removeBtn(list, i)),
        renderQueryBox(c.containedIn, { nested: 'container', verb: 'dans des', help: 'Ce bloc décrit les conteneurs (rapports…) dans lesquels l’entité doit figurer.' }));
    }
    if (c.contains) {
      return h('div', { class: 'cond' },
        h('div', { class: 'cond-row' }, h('span', { class: 'cond-kind' }, 'contient'), negateBox(c, 'exclure'), removeBtn(list, i)),
        renderQueryBox(c.contains, { nested: true, verb: 'contenant des', help: 'Ce bloc décrit ce que le conteneur doit contenir (le « X »), pas le résultat.' }));
    }
    if (c.ids) {
      return h('div', { class: 'cond' }, h('div', { class: 'cond-row' },
        h('span', { class: 'cond-kind' }, 'ids'),
        h('input', { type: 'text', value: asList(c.ids).join(', '), 'aria-label': 'Identifiants', oninput: (e) => { c.ids = parseList(e.target.value); syncDraft(); } }),
        negateBox(c, 'exclure'), removeBtn(list, i)));
    }
    return h('div', { class: 'cond' }, h('div', { class: 'cond-row' }, h('code', {}, JSON.stringify(c)), removeBtn(list, i)));
  }

  // Phrase en français décrivant la requête
  const esc = (s) => String(s).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));
  function phraseQuery(q, top) {
    const t = `<b>${esc(asList(q.type).map((x) => noun(x)).join(' ou '))}</b>`;
    let s = top ? `les ${t}` : t;
    if (q.search) s += ` (mot-clé « ${esc(q.search)} »)`;
    if (q.where) s += ` ${phraseCond(q.where)}`;
    return s;
  }
  function phraseCond(c) {
    if (isGroup(c)) {
      const key = c.all ? 'all' : 'any';
      const parts = c[key].map(phraseCond);
      return parts.length > 1 ? `(${parts.join(key === 'all' ? ' <b>et</b> ' : ' <b>ou</b> ')})` : parts[0] || '';
    }
    const not = c.negate ? 'ne ' : '';
    const pas = c.negate ? ' pas' : '';
    if (c.field) {
      const label = (FIELDS.find(([v]) => v === c.field) || [c.field, c.field])[1].toLowerCase();
      if (c.op === 'nil') return `dont ${label} est vide`;
      if (c.op === 'not_nil') return `dont ${label} est renseigné`;
      const val = asList(c.value).map((v) => `« ${esc(DATE_KEYS.has(c.field) ? fmtDate(v) : v)} »`).join(' ou ');
      const op = DATE_KEYS.has(c.field) && DATE_OPS[c.op] ? DATE_OPS[c.op] : OP_LABEL[c.op || 'eq'];
      return `dont ${label} ${op} ${val}`;
    }
    if (c.label) return `qui ${not}portent${pas} le libellé ${asList(c.label).map((l) => `« ${esc(l)} »`).join(' ou ')}`;
    if (c.author) return `qui ${c.negate ? 'ne sont pas' : 'sont'} créés par ${asList(c.author).map((l) => `« ${esc(l)} »`).join(' ou ')}`;
    if (c.marking) return `qui ${c.negate ? 'ne sont pas' : 'sont'} marqués ${asList(c.marking).map((l) => esc(l)).join(' ou ')}`;
    if (c.relatedTo) {
      const rels = asList(c.relationship);
      const rel = rels.length ? `« ${rels.map(esc).join(' » ou « ')} »` : '';
      if (c.direction === 'out') return `qui ${c.negate ? 'n’ont pas' : 'ont'} de relation ${rel} vers des ${phraseQuery(c.relatedTo)}`.replace('relation  vers', 'relation vers');
      if (c.direction === 'in') return `qui ${c.negate ? 'ne sont pas' : 'sont'} la cible d’une relation ${rel} depuis des ${phraseQuery(c.relatedTo)}`.replace('relation  depuis', 'relation depuis');
      return `qui ${c.negate ? 'ne sont pas' : 'sont'} liés${rel ? ` (${rel})` : ''} à des ${phraseQuery(c.relatedTo)}`;
    }
    if (c.containedIn) return `qui ${c.negate ? 'ne figurent dans aucun' : 'figurent dans des'} ${phraseQuery(c.containedIn)}`;
    if (c.contains) return `qui ${not}contiennent${pas} des ${phraseQuery(c.contains)}`;
    if (c.ids) return `parmi ${asList(c.ids).length} identifiant(s)`;
    return '';
  }

  // ---------------------------------------------------------------------------
  // Exécution dans l'explorateur
  // ---------------------------------------------------------------------------
  function renderPlan(plan) {
    const ICO = { sub: '↳', lookup: '⌕', rel: '⇄', final: '■' };
    $('#plan').replaceChildren(...plan.map((s) => h('li', { class: `${s.status}${s.kind === 'final' ? ' final' : ''}` },
      h('span', { class: 'ico' }, s.status === 'running' ? '…' : ICO[s.kind] || '·'),
      h('span', { style: `padding-left:${s.depth * 14}px` }, s.label,
        s.warn ? h('span', { class: 'warn' }, `⚠ ${s.warn}`) : null,
        s.sample && s.sample.length ? h('span', { class: 'sample' }, s.sample.filter(Boolean).join(' · ') + (s.count > s.sample.length ? ' …' : '')) : null),
      h('span', { class: 'n' }, s.count === null ? '' : s.count.toLocaleString('fr-FR')))));
  }

  async function runExplorer() {
    const q = cleanQuery(draft);
    const btn = $('#run');
    btn.disabled = true; btn.textContent = 'Exécution…';
    $('#run-error').hidden = true;
    $('#run-stats').replaceChildren();
    $('#results').replaceChildren(h('div', { class: 'empty' }, 'Exécution en cours…'));
    try {
      await ensureReady();
      const res = await engine.run(q, { onStep: (_s, plan) => renderPlan(plan) });
      lastRun = { query: q, ...res };
      renderPlan(res.plan);
      $('#run-stats').replaceChildren(
        h('span', {}, h('b', {}, res.items.length.toLocaleString('fr-FR')), 'résultats'),
        h('span', {}, h('b', {}, res.stats.requests), 'requêtes'),
        h('span', {}, h('b', {}, res.stats.ms.toLocaleString('fr-FR')), 'ms'));
      $('#final-filters').textContent = JSON.stringify(res.filters, null, 2);
      $('#result-count').textContent = `(${res.items.length})`;
      $('#results').replaceChildren(resultsTable(res.items, 500));
      if (!res.items.length && res.emptySubqueries.length) {
        $('#results').prepend(h('div', { class: 'note', style: 'margin:12px' },
          `Aucun résultat parce qu’une sous-requête ne trouve rien : ${res.emptySubqueries.map((d) => `« ${d} »`).join(', ')}. `,
          'Vérifiez le type choisi dans ce bloc : il décrit l’entité à l’autre bout de la relation ou du conteneur, pas le résultat (ex. QuartzLoader est un malware, pas un mode opératoire).'));
      }
      $('#save-widget').disabled = false;
    } catch (e) {
      $('#run-error').hidden = false;
      $('#run-error').textContent = `La requête a échoué : ${e.message}. Le journal GraphQL montre la requête fautive.`;
      $('#results').replaceChildren(h('div', { class: 'empty' }, 'Pas de résultat.'));
    } finally {
      btn.disabled = false; btn.textContent = 'Exécuter';
    }
  }

  function tlpChip(m) {
    const d = (m.definition || '').toUpperCase();
    const cls = d.includes('RED') ? 'red' : d.includes('AMBER') ? 'amber' : d.includes('GREEN') ? 'green' : d.includes('CLEAR') || d.includes('WHITE') ? 'clear' : null;
    return cls ? h('span', { class: `tlp ${cls}` }, d) : h('span', { class: 'chip' }, m.definition);
  }

  function resultsTable(items, limit, compact) {
    if (!items.length) return h('div', { class: 'empty' }, 'Aucune entité ne correspond.');
    const rows = items.slice(0, limit);
    const showPublished = items.some((n) => n.published);
    const table = h('table', {},
      h('thead', {}, h('tr', {},
        h('th', {}, 'Nom'), h('th', {}, 'Type'),
        compact ? null : h('th', {}, 'Auteur'),
        compact ? null : h('th', {}, 'Libellés'),
        h('th', {}, 'Marquage'),
        compact ? null : h('th', {}, showPublished ? 'Publié' : 'Créé'))),
      h('tbody', {}, rows.map((n) => h('tr', {},
        h('td', { class: 'name' }, n.name || n.representative?.main,
          n.aliases && n.aliases.length ? h('small', {}, n.aliases.join(', ')) : n.x_mitre_id ? h('small', {}, n.x_mitre_id) : null),
        h('td', {}, h('span', { class: 'etype' }, n.entity_type)),
        compact ? null : h('td', {}, n.createdBy?.name || '—'),
        compact ? null : h('td', {}, h('div', { class: 'chips' }, (n.objectLabel || []).map((l) => h('span', { class: 'chip' }, h('i', { style: `background:${l.color || 'var(--ink-3)'}` }), l.value)))),
        h('td', {}, h('div', { class: 'chips' }, (n.objectMarking || []).map(tlpChip))),
        compact ? null : h('td', { class: 'date' }, fmtDate(showPublished ? n.published || n.created : n.created || n.created_at))))));
    const wrap = h('div', {}, table);
    if (items.length > limit) wrap.append(h('div', { class: 'empty' }, `… et ${items.length - limit} autre(s)`));
    return wrap;
  }

  // ---------------------------------------------------------------------------
  // Tableau de bord
  // ---------------------------------------------------------------------------
  let dashboard = store.get('od.dashboard', null);
  // Un tableau de bord d'une version antérieure du POC est remplacé par le nouveau tableau par défaut.
  if (!dashboard || !Array.isArray(dashboard.widgets) || (dashboard.version || 1) < OD.defaultDashboard.version) dashboard = clone(OD.defaultDashboard);
  const saveDashboard = () => store.set('od.dashboard', dashboard);

  function renderDashboard() {
    $('#dash-title').textContent = dashboard.title || 'Tableau de bord';
    const grid = $('#dash-grid');
    if (!dashboard.widgets.length) {
      grid.replaceChildren(h('div', { class: 'panel', style: 'grid-column:span 12' }, h('div', { class: 'empty' },
        'Aucun widget. Composez une requête dans l’explorateur puis « Enregistrer comme widget ».')));
      return;
    }
    grid.replaceChildren(...dashboard.widgets.map(widgetCard));
    dashboard.widgets.forEach(runWidget);
  }

  function widgetCard(w) {
    let confirmDel = false;
    const del = h('button', { type: 'button', class: 'btn small ghost danger', onclick: () => {
      if (!confirmDel) { confirmDel = true; del.textContent = 'Confirmer ?'; setTimeout(() => { confirmDel = false; del.textContent = 'Supprimer'; }, 3000); return; }
      dashboard.widgets = dashboard.widgets.filter((x) => x.id !== w.id); saveDashboard(); renderDashboard(); toast('Widget supprimé');
    } }, 'Supprimer');
    return h('article', { class: `panel w ${w.size || 'm'}`, id: `w-${w.id}` },
      h('div', { class: 'panel-head' },
        h('h3', {}, w.title),
        h('div', { class: 'btn-row', style: 'gap:2px' },
          h('button', { type: 'button', class: 'btn small ghost', 'aria-label': 'Rafraîchir', title: 'Rafraîchir', onclick: () => runWidget(w) }, '↻'),
          h('button', { type: 'button', class: 'btn small ghost', onclick: () => editWidget(w) }, 'Modifier'),
          del)),
      h('div', { class: 'panel-body' }, h('div', { class: 'loading' }, 'Chargement…')),
      h('div', { class: 'w-meta' }, h('span', { class: 'q', html: null }, '')));
  }

  async function runWidget(w) {
    const card = $(`#w-${w.id}`);
    if (!card) return;
    const body = $('.panel-body', card);
    const meta = $('.w-meta', card);
    body.replaceChildren(h('div', { class: 'loading' }, 'Exécution…'));
    try {
      await ensureReady();
      const res = await engine.run(w.query);
      body.replaceChildren(renderWidgetView(w, res.items));
      meta.replaceChildren(h('span', {}, `${res.stats.requests} requêtes · ${res.stats.ms} ms`), h('span', { class: 'q' }, `· ${stripTags(phraseQuery(w.query, true))}`));
    } catch (e) {
      body.replaceChildren(h('div', { class: 'err-box' }, `Échec : ${e.message}`));
    }
  }
  const stripTags = (s) => { const d = document.createElement('div'); d.innerHTML = s; return d.textContent; };

  function renderWidgetView(w, items) {
    if (w.view === 'number') {
      const t = asList(w.query.type)[0];
      return h('div', {},
        h('div', { class: 'big' }, items.length.toLocaleString('fr-FR')),
        h('div', { class: 'big-sub' }, noun(t, items.length)),
        items.length ? h('div', { class: 'big-names' }, items.slice(0, 5).map((n) => n.name || n.representative?.main).join(' · ') + (items.length > 5 ? ' …' : '')) : null);
    }
    if (w.view === 'table') return h('div', { class: 'table-wrap', style: 'margin:-14px' }, resultsTable(items, 8, w.size !== 'l'));
    if (w.view === 'bars') return barsView(OD.agg.groupBy(items, w.groupBy || 'entity_type'), items.length);
    if (w.view === 'timeline') return timelineView(OD.agg.timeline(items, w.dateField || 'created'), w.dateField || 'created');
    return h('div', {}, `Vue inconnue : ${w.view}`);
  }

  function barsView(groups, total) {
    if (!groups.length) return h('div', { class: 'empty' }, 'Aucune donnée.');
    const top = groups.slice(0, 9);
    const rest = groups.slice(9).reduce((s, g) => s + g.count, 0);
    if (rest) top.push({ key: 'Autres', count: rest });
    const max = Math.max(...top.map((g) => g.count));
    return h('div', { class: 'bars' }, top.map((g) => {
      const row = h('div', { class: 'bar' },
        h('span', { class: 'lbl', title: g.key }, g.key),
        h('span', { class: 'track' }, h('span', { class: 'fill', style: `width:${(g.count / max) * 100}%` })),
        h('span', { class: 'v' }, g.count));
      bindTip(row, () => `<b>${esc(g.key)}</b> : ${g.count} sur ${total} (${Math.round((g.count / total) * 100)} %)`);
      return row;
    }));
  }

  function niceMax(v) {
    if (v <= 4) return Math.max(1, v);
    const p = 10 ** Math.floor(Math.log10(v));
    const n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
  }

  function timelineView(series, field) {
    if (!series.length) return h('div', { class: 'empty' }, 'Aucune date disponible.');
    const W = 560, H = 190, padL = 28, padB = 22, padT = 8, padR = 4;
    const max = niceMax(Math.max(...series.map((d) => d.count)));
    const ticks = max <= 4 ? Array.from({ length: max + 1 }, (_, i) => i) : [0, max / 2, max];
    const iw = W - padL - padR, ih = H - padT - padB;
    const bw = iw / series.length;
    const gap = Math.min(2, bw * 0.25);
    const y = (v) => padT + ih - (v / max) * ih;
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', `Nombre par mois (${OD.agg.DATE_FIELDS[field] || field})`);
    const add = (tag, attrs, text) => { const e = document.createElementNS(ns, tag); Object.entries(attrs).forEach(([k, v]) => e.setAttribute(k, v)); if (text !== undefined) e.textContent = text; svg.append(e); return e; };
    ticks.forEach((t) => {
      add('line', { class: 'grid-l', x1: padL, x2: W - padR, y1: y(t), y2: y(t) });
      add('text', { class: 'axis-t', x: padL - 6, y: y(t) + 3.5, 'text-anchor': 'end' }, t);
    });
    const every = Math.ceil(series.length / 8);
    const MONTHS = ['janv.', 'févr.', 'mars', 'avr.', 'mai', 'juin', 'juil.', 'août', 'sept.', 'oct.', 'nov.', 'déc.'];
    const label = (k) => { const [yy, mm] = k.split('-'); return mm ? `${MONTHS[Number(mm) - 1]} ${yy.slice(2)}` : yy; };
    series.forEach((d, i) => {
      const x = padL + i * bw;
      const hgt = Math.max(d.count ? 2 : 0, padT + ih - y(d.count));
      const w = Math.max(1, bw - gap);
      const r = Math.min(4, w / 2, hgt);
      const top = padT + ih - hgt;
      // Colonne à coins supérieurs arrondis, ancrée sur la ligne de base
      if (hgt > 0) add('path', { class: 'col', d: `M${x},${padT + ih} V${top + r} Q${x},${top} ${x + r},${top} H${x + w - r} Q${x + w},${top} ${x + w},${top + r} V${padT + ih} Z` });
      const hit = add('rect', { class: 'hit', x, y: padT, width: bw, height: ih });
      bindTip(hit, () => `<b>${label(d.key)}</b> : ${d.count}`);
      if (i % every === 0) add('text', { class: 'axis-t', x: x + bw / 2, y: H - 6, 'text-anchor': 'middle' }, label(d.key));
    });
    return h('div', { class: 'tl' }, svg, h('div', { class: 'muted', style: 'margin-top:4px' }, `Par mois · ${OD.agg.DATE_FIELDS[field] || field}`));
  }

  // Infobulle (souris et toucher)
  let tip;
  function bindTip(node, html) {
    const show = (e) => {
      if (!tip) { tip = h('div', { class: 'tip', role: 'tooltip' }); document.body.append(tip); }
      tip.innerHTML = html();
      tip.hidden = false;
      const x = Math.min(e.clientX + 12, window.innerWidth - tip.offsetWidth - 8);
      tip.style.left = `${Math.max(8, x)}px`;
      tip.style.top = `${Math.max(8, e.clientY - tip.offsetHeight - 10)}px`;
    };
    node.addEventListener('pointermove', show);
    node.addEventListener('pointerdown', show);
    node.addEventListener('pointerleave', () => { if (tip) tip.hidden = true; });
  }
  document.addEventListener('scroll', () => { if (tip) tip.hidden = true; }, { passive: true });

  function editWidget(w) {
    editingWidget = w.id;
    draft = normalize(clone(w.query));
    $('#example-select').value = '';
    renderBuilder();
    $('#save-widget').textContent = 'Mettre à jour le widget';
    go('explorateur');
    runExplorer();
    toast(`Édition du widget « ${w.title} »`);
  }

  // Dialogue widget
  function openWidgetDialog() {
    const w = editingWidget ? dashboard.widgets.find((x) => x.id === editingWidget) : null;
    $('#widget-dialog-title').textContent = w ? 'Mettre à jour le widget' : 'Nouveau widget';
    $('#wd-ok').textContent = w ? 'Mettre à jour' : 'Ajouter au tableau de bord';
    $('#wd-title').value = w ? w.title : stripTags(phraseQuery(lastRun.query, true)).replace(/^les /, '').slice(0, 80);
    $('#wd-view').value = w ? w.view : 'table';
    $('#wd-size').value = w ? w.size || 'm' : 'm';
    $('#wd-group').value = w?.groupBy || 'entity_type';
    $('#wd-date').value = w?.dateField || (lastRun.query.type === 'Report' ? 'published' : 'created');
    syncWidgetDialog();
    $('#widget-dialog').showModal();
  }
  function syncWidgetDialog() {
    $('#wd-group-wrap').hidden = $('#wd-view').value !== 'bars';
    $('#wd-date-wrap').hidden = $('#wd-view').value !== 'timeline';
  }

  // ---------------------------------------------------------------------------
  // Journal GraphQL
  // ---------------------------------------------------------------------------
  let logScheduled = false;
  transport.onLog(() => {
    $('#log-count').textContent = transport.log.length;
    if (logScheduled || $('[data-view="journal"]').hidden) return;
    logScheduled = true;
    requestAnimationFrame(() => { logScheduled = false; renderLog(); });
  });

  function renderLog() {
    const box = $('#log');
    $('#log-count').textContent = transport.log.length;
    if (!transport.log.length) { box.replaceChildren(h('div', { class: 'empty' }, 'Aucune requête pour l’instant.')); return; }
    const open = new Set($$('details[open]', box).map((d) => d.dataset.id));
    box.replaceChildren(...transport.log.slice(0, 120).map((e) => {
      const payload = JSON.stringify({ query: e.query, variables: e.variables }, null, 2);
      const d = h('details', { 'data-id': e.id, open: open.has(String(e.id)) ? 'open' : null },
        h('summary', {},
          h('span', { class: 'num' }, `#${e.id}`),
          h('span', { class: 'lbl' }, e.label || 'Requête'),
          h('span', { class: `status ${e.status}` }, e.status === 'ok' ? 'OK' : e.status === 'error' ? 'ERREUR' : '…'),
          h('span', { class: 'ms' }, e.ms !== undefined ? `${e.ms} ms` : '')),
        h('div', { class: 'body' },
          e.error ? h('div', { class: 'err-box' }, e.error) : null,
          h('div', { class: 'btn-row' },
            h('button', { type: 'button', class: 'btn small', onclick: () => copy(payload) }, 'Copier (JSON)'),
            h('button', { type: 'button', class: 'btn small', onclick: () => copy(curl(e)) }, 'Copier en curl')),
          h('h4', {}, 'Requête'), h('pre', {}, e.query),
          h('h4', {}, 'Variables'), h('pre', {}, JSON.stringify(e.variables, null, 2)),
          e.response ? [h('h4', {}, 'Réponse (extrait)'), h('pre', {}, truncate(JSON.stringify(e.response, null, 2), 4000))] : null));
      return d;
    }));
  }
  const truncate = (s, n) => (s.length > n ? `${s.slice(0, n)}\n… (${s.length - n} caractères de plus)` : s);
  function curl(e) {
    const url = (settings.url || 'https://opencti.exemple.fr').replace(/\/+$/, '') + '/graphql';
    const body = JSON.stringify({ query: e.query.replace(/\s+/g, ' '), variables: e.variables }).replace(/'/g, "'\\''");
    return `curl -s '${url}' -H 'Content-Type: application/json' -H "Authorization: Bearer $OPENCTI_TOKEN" --data '${body}'`;
  }

  // ---------------------------------------------------------------------------
  // Réglages
  // ---------------------------------------------------------------------------
  function fillSettings() {
    $(`#mode-${settings.mode === 'live' ? 'live' : 'mock'}`).checked = true;
    $('#set-url').value = settings.url;
    $('#set-token').value = settings.token;
    $('#set-remember').checked = settings.remember;
    $('#set-strategy').value = settings.strategy;
    $('#set-page').value = settings.pageSize;
    $('#set-max').value = settings.maxItems;
    $('#live-note').hidden = settings.mode !== 'live';
  }
  function readSettings() {
    settings.mode = $('#mode-live').checked ? 'live' : 'mock';
    settings.url = $('#set-url').value.trim();
    settings.token = $('#set-token').value.trim();
    settings.remember = $('#set-remember').checked;
    settings.strategy = $('#set-strategy').value;
    settings.pageSize = Number($('#set-page').value) || 500;
    settings.maxItems = Number($('#set-max').value) || 5000;
  }

  // ---------------------------------------------------------------------------
  // Initialisation
  // ---------------------------------------------------------------------------
  function loadExample(id) {
    const ex = OD.examples.find((e) => e.id === id);
    if (!ex) return;
    draft = normalize(clone(ex.query));
    editingWidget = null;
    $('#save-widget').textContent = 'Enregistrer comme widget';
    renderBuilder();
  }

  function init() {
    // Exemples
    $('#example-select').replaceChildren(
      h('option', { value: '' }, 'Exemples de requêtes…'),
      ...OD.examples.map((e) => h('option', { value: e.id }, e.title)));
    $('#example-select').addEventListener('change', (e) => { if (e.target.value) { loadExample(e.target.value); runExplorer(); } });

    const saved = store.get('od.draft', null);
    if (saved && saved.type) { draft = normalize(saved); renderBuilder(); }
    else { $('#example-select').value = OD.examples[0].id; loadExample(OD.examples[0].id); }

    $('#run').addEventListener('click', runExplorer);
    $('#json-apply').addEventListener('click', () => {
      try {
        const q = JSON.parse($('#json').value);
        if (!q.type) throw new Error('le champ "type" est obligatoire');
        draft = normalize(q);
        $('#json-error').hidden = true;
        renderBuilder();
        toast('JSON appliqué');
      } catch (e) { $('#json-error').hidden = false; $('#json-error').textContent = `JSON invalide : ${e.message}`; }
    });
    $('#json-copy').addEventListener('click', () => copy($('#json').value));

    // Widgets
    $('#save-widget').addEventListener('click', () => lastRun && openWidgetDialog());
    $('#wd-view').addEventListener('change', syncWidgetDialog);
    $('#wd-group').replaceChildren(...Object.entries(OD.agg.GROUP_BY).map(([k, v]) => h('option', { value: k }, v.label)));
    $('#wd-date').replaceChildren(...Object.entries(OD.agg.DATE_FIELDS).map(([k, v]) => h('option', { value: k }, v)));
    $('#widget-dialog').addEventListener('close', () => {
      if ($('#widget-dialog').returnValue !== 'ok' || !lastRun) return;
      const props = {
        title: $('#wd-title').value.trim() || 'Widget', view: $('#wd-view').value, size: $('#wd-size').value,
        groupBy: $('#wd-group').value, dateField: $('#wd-date').value, query: lastRun.query,
      };
      const existing = editingWidget && dashboard.widgets.find((x) => x.id === editingWidget);
      if (existing) Object.assign(existing, props);
      else dashboard.widgets.push({ id: `w${Date.now().toString(36)}`, ...props });
      saveDashboard();
      editingWidget = null;
      $('#save-widget').textContent = 'Enregistrer comme widget';
      go('tableau');
      renderDashboard();
      toast(existing ? 'Widget mis à jour' : 'Widget ajouté au tableau de bord');
    });

    // Tableau de bord
    $('#dash-refresh').addEventListener('click', () => dashboard.widgets.forEach(runWidget));
    let confirmReset = false;
    $('#dash-reset').addEventListener('click', (e) => {
      if (!confirmReset) { confirmReset = true; e.target.textContent = 'Confirmer la réinitialisation'; setTimeout(() => { confirmReset = false; e.target.textContent = 'Réinitialiser'; }, 3000); return; }
      dashboard = clone(OD.defaultDashboard); saveDashboard(); renderDashboard(); toast('Tableau de bord réinitialisé');
      confirmReset = false; e.target.textContent = 'Réinitialiser';
    });
    $('#dash-export').addEventListener('click', () => {
      $('#io-text').value = JSON.stringify(dashboard, null, 2);
      $('#io-error').hidden = true;
      $('#io-dialog').showModal();
    });
    $('#io-copy').addEventListener('click', () => copy($('#io-text').value));
    $('#io-import').addEventListener('click', () => {
      try {
        const d = JSON.parse($('#io-text').value);
        if (!Array.isArray(d.widgets)) throw new Error('"widgets" doit être une liste');
        d.widgets.forEach((w, i) => { if (!w.query || !w.query.type) throw new Error(`widget ${i + 1} sans requête valide`); w.id = w.id || `w${i}${Date.now().toString(36)}`; });
        dashboard = d; saveDashboard(); $('#io-dialog').close(); renderDashboard(); toast(`${d.widgets.length} widget(s) importé(s)`);
      } catch (e) { $('#io-error').hidden = false; $('#io-error').textContent = `Import impossible : ${e.message}`; }
    });

    // Journal
    $('#log-clear').addEventListener('click', () => { transport.log.length = 0; renderLog(); });

    // Réglages
    fillSettings();
    $$('input[name="mode"]').forEach((r) => r.addEventListener('change', () => { $('#live-note').hidden = !$('#mode-live').checked; }));
    $('#settings-form').addEventListener('submit', (e) => {
      e.preventDefault();
      const before = settings.mode;
      readSettings(); saveSettings(); applySettings();
      engine.resetCaches(); ensureReady().then(loadRelMap).catch(() => {});
      toast('Réglages enregistrés');
      if (before !== settings.mode) { ensureReady().catch(() => {}); renderDashboard(); }
    });
    $('#test-conn').addEventListener('click', async () => {
      readSettings(); applySettings();
      const out = $('#conn-result');
      out.textContent = 'Test…';
      try {
        await ensureReady();
        const d = await transport.request('query ODAbout { about { version } }', {}, 'Test de connexion');
        out.textContent = `Connecté · OpenCTI ${d.about.version}`;
      } catch (e) {
        out.textContent = `Échec : ${e.message}${settings.mode === 'live' ? ' (vérifiez l’URL, le jeton et la configuration CORS)' : ''}`;
      }
    });
    $('#source-pill').addEventListener('click', () => go('reglages'));

    window.addEventListener('hashchange', route);
    route();
    applySettings();
    renderDashboard();
    ensureReady().then(() => { loadRelMap(); runExplorer(); }).catch(() => {});
  }

  init();
})();
