/*
 * OpenDashboard — moteur de requêtes en profondeur sur l'API GraphQL d'OpenCTI.
 *
 * OpenCTI sait filtrer une liste d'entités avec un FilterGroup (ET/OU imbriqués),
 * mais un filtre ne peut pas porter sur le résultat d'une autre recherche.
 * Le moteur comble ce manque : chaque sous-requête est exécutée d'abord, son
 * résultat (une liste d'identifiants) est réinjecté comme filtre natif dans la
 * requête parente. La requête finale reste un unique FilterGroup OpenCTI.
 *
 * ---------------------------------------------------------------------------
 * DSL (JSON)
 * ---------------------------------------------------------------------------
 * Requête :  { "type": "Intrusion-Set" | ["Malware","Tool"], "where": Condition?, "search": "texte"? }
 *
 * Condition :
 *   { "all": [Condition, ...] }                       ET
 *   { "any": [Condition, ...] }                       OU
 *   { "field": "name", "op": "contains", "value": "X" }
 *        champ natif OpenCTI (name, description, alias, confidence, created,
 *        published, report_types, x_mitre_id, ...). value peut être une liste.
 *        op : eq, not_eq, contains, not_contains, starts_with, ends_with,
 *             gt, gte, lt, lte, nil, not_nil
 *   { "label": ["ransomware"], "op": "eq" }           libellés (résolus en id)
 *   { "author": ["CERT-Lumen"] }                      auteur (createdBy, résolu en id)
 *   { "marking": ["TLP:RED"], "op": "eq" }            marquage (résolu en id)
 *   { "relatedTo": Requête, "relationship": ["uses"], "direction": "out" | "in" | "both" }
 *        l'entité a une relation avec un résultat de la sous-requête.
 *        relationship est facultatif. direction : "out" = l'entité est la source
 *        (entité → résultat), "in" = l'entité est la cible, "both" (défaut) = peu importe.
 *   { "containedIn": Requête }                         l'entité figure dans un conteneur
 *                                                      (rapport, grouping…) résultat de la sous-requête
 *   { "contains": Requête }                            (conteneurs) contient un résultat de la sous-requête
 *   { "ids": ["…"] }                                   identifiants explicites
 *   Toute condition accepte "negate": true pour les clés à base d'ids.
 */
(function (root) {
  'use strict';
  const OD = (root.OD = root.OD || {});

  const NONE = '00000000-0000-0000-0000-000000000000';

  // ---------------------------------------------------------------------------
  // Transport : vraie instance OpenCTI ou mock, avec journal des requêtes
  // ---------------------------------------------------------------------------
  class Transport {
    constructor() {
      this.mode = 'mock';
      this.url = '';
      this.token = '';
      this.mock = null;
      this.log = [];
      this.listeners = new Set();
    }

    configure({ mode, url, token, mock }) {
      if (mode) this.mode = mode;
      if (url !== undefined) this.url = url;
      if (token !== undefined) this.token = token;
      if (mock) this.mock = mock;
    }

    onLog(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }

    async request(query, variables = {}, label = '') {
      const entry = { id: this.log.length + 1, label, query: query.trim(), variables, start: performance.now(), status: 'pending' };
      this.log.unshift(entry);
      if (this.log.length > 200) this.log.pop();
      this.listeners.forEach((fn) => fn(entry));
      try {
        let payload;
        if (this.mode === 'mock') {
          if (!this.mock) throw new Error('Le mock n’est pas encore chargé.');
          payload = await this.mock.execute(query, variables);
        } else {
          if (!this.url) throw new Error('URL OpenCTI manquante (Réglages).');
          const res = await fetch(this.url.replace(/\/+$/, '') + '/graphql', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}) },
            body: JSON.stringify({ query, variables }),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
          payload = await res.json();
        }
        if (payload.errors && payload.errors.length) {
          throw new Error(payload.errors.map((e) => e.message).join(' | '));
        }
        entry.status = 'ok';
        entry.response = payload.data;
        return payload.data;
      } catch (err) {
        entry.status = 'error';
        entry.error = err.message || String(err);
        throw err;
      } finally {
        entry.ms = Math.round(performance.now() - entry.start);
        this.listeners.forEach((fn) => fn(entry));
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Fragments GraphQL
  // ---------------------------------------------------------------------------
  const DISPLAY_FIELDS = `
    id
    standard_id
    entity_type
    parent_types
    created_at
    updated_at
    representative { main secondary }
    createdBy { id name entity_type }
    objectLabel { id value color }
    objectMarking { id definition x_opencti_color }
    ... on StixDomainObject { created modified confidence }
    ... on Report { name description published report_types }
    ... on Grouping { name description context }
    ... on IntrusionSet { name description aliases first_seen last_seen primary_motivation resource_level }
    ... on ThreatActorGroup { name description aliases threat_actor_types }
    ... on Campaign { name description aliases first_seen last_seen }
    ... on Malware { name description aliases malware_types is_family }
    ... on Tool { name description aliases tool_types }
    ... on AttackPattern { name description x_mitre_id }
    ... on Vulnerability { name description x_opencti_cvss_base_score }
    ... on Country { name description }
    ... on Sector { name description }
    ... on Organization { name description }
  `;

  const Q_OBJECTS = (fields) => `
    query ODStixCoreObjects($types: [String], $filters: FilterGroup, $search: String, $first: Int, $after: ID) {
      stixCoreObjects(types: $types, filters: $filters, search: $search, first: $first, after: $after) {
        edges { node { ${fields} } }
        pageInfo { endCursor hasNextPage globalCount }
      }
    }`;

  const Q_CONTAINERS_OBJECTS = `
    query ODContainersObjects($filters: FilterGroup, $search: String, $first: Int, $after: ID, $objectTypes: [String], $objectsFirst: Int) {
      containers(filters: $filters, search: $search, first: $first, after: $after) {
        edges { node {
          id entity_type representative { main }
          objects(types: $objectTypes, first: $objectsFirst) {
            edges { node { ... on StixCoreObject { id entity_type } } }
            pageInfo { endCursor hasNextPage globalCount }
          }
        } }
        pageInfo { endCursor hasNextPage globalCount }
      }
    }`;

  const Q_CONTAINER_OBJECTS_PAGE = `
    query ODContainerObjectsPage($id: String, $objectTypes: [String], $first: Int, $after: ID) {
      container(id: $id) {
        id
        objects(types: $objectTypes, first: $first, after: $after) {
          edges { node { ... on StixCoreObject { id entity_type } } }
          pageInfo { endCursor hasNextPage globalCount }
        }
      }
    }`;

  const Q_RELATIONSHIPS = `
    query ODRelationships($fromOrToId: [String], $fromId: [String], $toId: [String], $relationship_type: [String], $first: Int, $after: ID) {
      stixCoreRelationships(fromOrToId: $fromOrToId, fromId: $fromId, toId: $toId, relationship_type: $relationship_type, first: $first, after: $after) {
        edges { node {
          id relationship_type
          from { ... on StixCoreObject { id entity_type } }
          to { ... on StixCoreObject { id entity_type } }
        } }
        pageInfo { endCursor hasNextPage globalCount }
      }
    }`;

  const Q_LABELS = `
    query ODLabels($filters: FilterGroup, $first: Int) {
      labels(filters: $filters, first: $first) { edges { node { id value } } }
    }`;

  const Q_REL_MAPPING = `query ODRelationsMapping { schemaRelationsTypesMapping { key values } }`;

  const Q_SUGGEST = {
    label: `query ODSuggestLabels($search: String, $first: Int) {
      labels(search: $search, first: $first) { edges { node { id value color } } } }`,
    marking: `query ODSuggestMarkings($search: String, $first: Int) {
      markingDefinitions(search: $search, first: $first) { edges { node { id definition x_opencti_color } } } }`,
    author: `query ODSuggestAuthors($search: String, $first: Int, $types: [String]) {
      identities(search: $search, first: $first, types: $types) { edges { node { id name entity_type } } } }`,
    entity: `query ODSuggestEntities($search: String, $first: Int, $types: [String]) {
      stixCoreObjects(search: $search, first: $first, types: $types) { edges { node { id entity_type representative { main } } } } }`,
    vocabulary: `query ODSuggestVocabulary($search: String, $first: Int, $category: VocabularyCategory) {
      vocabularies(search: $search, first: $first, category: $category) { edges { node { id name description usages } } } }`,
  };

  const Q_MARKINGS = `
    query ODMarkings($filters: FilterGroup, $first: Int) {
      markingDefinitions(filters: $filters, first: $first) { edges { node { id definition } } }
    }`;

  // ---------------------------------------------------------------------------
  // Helpers DSL
  // ---------------------------------------------------------------------------
  const asList = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
  const fg = (mode, filters = [], filterGroups = []) => ({ mode, filters, filterGroups });

  // ---------------------------------------------------------------------------
  // Types abstraits → types concrets (pour croiser avec la table des relations)
  // ---------------------------------------------------------------------------
  const CONTAINERS = ['Report', 'Grouping', 'Note', 'Opinion', 'Observed-Data', 'Case-Incident', 'Case-Rfi', 'Case-Rft', 'Feedback', 'Task'];
  const IDENTITIES = ['Individual', 'Organization', 'Sector', 'System', 'SecurityPlatform'];
  const LOCATIONS = ['City', 'Country', 'Region', 'Position', 'Administrative-Area'];
  const THREAT_ACTORS = ['Threat-Actor-Group', 'Threat-Actor-Individual'];
  const SDOS = ['Attack-Pattern', 'Campaign', 'Course-Of-Action', 'Indicator', 'Infrastructure', 'Intrusion-Set', 'Malware', 'Tool',
    'Vulnerability', 'Incident', 'Event', 'Channel', 'Narrative', 'Language', 'Data-Component', 'Data-Source', 'Malware-Analysis',
    ...CONTAINERS, ...IDENTITIES, ...LOCATIONS, ...THREAT_ACTORS];
  const TYPE_TREE = {
    'Stix-Domain-Object': SDOS, 'Stix-Core-Object': SDOS, 'Container': CONTAINERS, 'Identity': IDENTITIES,
    'Location': LOCATIONS, 'Threat-Actor': THREAT_ACTORS,
  };
  const expandTypes = (types) => [...new Set(asList(types).flatMap((t) => TYPE_TREE[t] || [t]))];

  /** Relations possibles entre deux (ensembles de) types, selon la table OpenCTI. */
  function possibleRelations(mapping, sourceTypes, targetTypes) {
    const S = expandTypes(sourceTypes), T = expandTypes(targetTypes);
    const out = new Set(), inn = new Set();
    S.forEach((s) => T.forEach((t) => {
      (mapping[`${s}_${t}`] || []).forEach((r) => out.add(r));
      (mapping[`${t}_${s}`] || []).forEach((r) => inn.add(r));
    }));
    return { out: [...out].sort(), in: [...inn].sort() };
  }

  function describeQuery(q) {
    const t = asList(q.type).join(' | ') || 'Entités';
    return q.where ? `${t} filtrés` : t;
  }

  function describeCond(c) {
    if (!c) return '';
    if (c.all) return `ET(${c.all.length})`;
    if (c.any) return `OU(${c.any.length})`;
    if (c.field) return `${c.field} ${c.op || 'eq'} ${asList(c.value).join(', ')}`;
    if (c.label) return `libellé ${asList(c.label).join(', ')}`;
    if (c.author) return `auteur ${asList(c.author).join(', ')}`;
    if (c.marking) return `marquage ${asList(c.marking).join(', ')}`;
    if (c.relatedTo) return `lié à [${describeQuery(c.relatedTo)}]${c.relationship ? ` via ${asList(c.relationship).join('/')}` : ''}${c.direction && c.direction !== 'both' ? ` (${c.direction === 'out' ? 'sortante' : 'entrante'})` : ''}`;
    if (c.containedIn) return `contenu dans [${describeQuery(c.containedIn)}]`;
    if (c.contains) return `contient [${describeQuery(c.contains)}]`;
    if (c.ids) return `ids (${asList(c.ids).length})`;
    return JSON.stringify(c);
  }

  // ---------------------------------------------------------------------------
  // Moteur
  // ---------------------------------------------------------------------------
  class Engine {
    constructor(transport, options = {}) {
      this.t = transport;
      this.options = {
        pageSize: 500,          // taille de page pour les listes paginées
        maxItems: 5000,         // garde-fou : nb max d'éléments récupérés par étape
        containerPage: 50,      // conteneurs par page lorsqu'on lit leur contenu
        objectsPerContainer: 500,
        relatedStrategy: 'regardingOf', // 'regardingOf' (1 requête) | 'relationships' (parcourt les relations)
        ...options,
      };
    }

    /**
     * Exécute une requête DSL. Retourne { items, plan, filters, stats }.
     * onStep(step) est appelé à chaque étape (pour l'affichage du plan).
     */
    async run(query, { onStep, fields } = {}) {
      const ctx = { plan: [], cache: new Map(), onStep: onStep || (() => {}), requests: 0, t0: performance.now(), depth: 0 };
      const types = asList(query.type);
      const filters = await this.compileWhere(query.where, ctx, types);
      const step = this.step(ctx, 'final', `Requête finale : ${describeQuery(query)}`);
      const items = await this.fetchAll(Q_OBJECTS(fields || DISPLAY_FIELDS), 'stixCoreObjects',
        { types: types.length ? types : null, filters, search: query.search || null }, ctx, 'Résultat final');
      this.done(ctx, step, items.length);
      return {
        items,
        plan: ctx.plan,
        filters,
        stats: { requests: ctx.requests, ms: Math.round(performance.now() - ctx.t0) },
      };
    }

    step(ctx, kind, label) {
      const s = { kind, label, depth: ctx.depth, status: 'running', count: null, warn: null };
      ctx.plan.push(s);
      ctx.onStep(s, ctx.plan);
      return s;
    }

    done(ctx, s, count, warn) {
      s.status = 'done';
      s.count = count;
      if (warn) s.warn = warn;
      ctx.onStep(s, ctx.plan);
    }

    async gql(ctx, query, variables, label) {
      ctx.requests++;
      return this.t.request(query, variables, label);
    }

    /** Parcourt toutes les pages d'une connexion racine. */
    async fetchAll(query, rootField, variables, ctx, label) {
      const out = [];
      let after = null;
      let page = 0;
      do {
        const data = await this.gql(ctx, query, { ...variables, first: this.options.pageSize, after }, `${label}${page ? ` (page ${page + 1})` : ''}`);
        const conn = data[rootField];
        conn.edges.forEach((e) => e && e.node && out.push(e.node));
        after = conn.pageInfo.hasNextPage ? conn.pageInfo.endCursor : null;
        page++;
        if (out.length >= this.options.maxItems) {
          ctx.truncated = true;
          break;
        }
      } while (after);
      return out;
    }

    /** Résout une sous-requête en liste d'identifiants (avec cache). */
    async resolveIds(query, ctx) {
      const key = JSON.stringify(query);
      if (ctx.cache.has(key)) return ctx.cache.get(key);
      ctx.depth++;
      const types = asList(query.type);
      const filters = await this.compileWhere(query.where, ctx, types);
      const s = this.step(ctx, 'sub', `Sous-requête : ${describeQuery(query)}`);
      const nodes = await this.fetchAll(Q_OBJECTS('id entity_type representative { main }'), 'stixCoreObjects',
        { types: types.length ? types : null, filters, search: query.search || null }, ctx, `Sous-requête ${describeQuery(query)}`);
      const ids = nodes.map((n) => n.id);
      s.sample = nodes.slice(0, 6).map((n) => n.representative?.main);
      this.done(ctx, s, ids.length, ids.length >= this.options.maxItems ? 'tronqué' : null);
      ctx.depth--;
      ctx.cache.set(key, ids);
      return ids;
    }

    /** Compile une condition en FilterGroup OpenCTI (en exécutant les sous-requêtes). */
    async compileWhere(where, ctx, types) {
      const groups = [];
      const filters = [];
      if (where) {
        const compiled = await this.compileCond(where, ctx, types);
        if (compiled.group) groups.push(compiled.group);
        else filters.push(compiled.filter);
      }
      return fg('and', filters, groups);
    }

    async compileCond(c, ctx, types) {
      if (c.all || c.any) {
        const mode = c.all ? 'and' : 'or';
        const children = c.all || c.any;
        const filters = [];
        const groups = [];
        for (const child of children) {
          const r = await this.compileCond(child, ctx, types);
          if (r.group) groups.push(r.group);
          else filters.push(r.filter);
        }
        return { group: fg(mode, filters, groups) };
      }

      if (c.field) {
        const op = c.op || 'eq';
        const values = ['nil', 'not_nil'].includes(op) ? [] : asList(c.value);
        return { filter: { key: [c.field], values, operator: op, mode: c.mode || (op.startsWith('not_') ? 'and' : 'or') } };
      }

      if (c.label) {
        const names = asList(c.label);
        const s = this.step(ctx, 'lookup', `Libellés : ${names.join(', ')}`);
        const data = await this.gql(ctx, Q_LABELS, { first: 500, filters: fg('and', [{ key: ['value'], values: names, operator: 'eq', mode: 'or' }]) }, 'Résolution libellés');
        const ids = data.labels.edges.map((e) => e.node.id);
        this.done(ctx, s, ids.length, ids.length < names.length ? 'libellé introuvable' : null);
        return { filter: this.idFilter('objectLabel', ids, c.op === 'not_eq' || c.negate) };
      }

      if (c.marking) {
        const names = asList(c.marking);
        const s = this.step(ctx, 'lookup', `Marquages : ${names.join(', ')}`);
        const data = await this.gql(ctx, Q_MARKINGS, { first: 500, filters: fg('and', [{ key: ['definition'], values: names, operator: 'eq', mode: 'or' }]) }, 'Résolution marquages');
        const ids = data.markingDefinitions.edges.map((e) => e.node.id);
        this.done(ctx, s, ids.length, ids.length < names.length ? 'marquage introuvable' : null);
        return { filter: this.idFilter('objectMarking', ids, c.op === 'not_eq' || c.negate) };
      }

      if (c.author) {
        const names = asList(c.author);
        const ids = await this.resolveIds({ type: 'Identity', where: { field: 'name', op: 'eq', value: names } }, ctx);
        return { filter: this.idFilter('createdBy', ids, c.negate) };
      }

      if (c.ids) return { filter: this.idFilter('ids', asList(c.ids), c.negate) };

      if (c.contains) {
        const ids = await this.resolveIds(c.contains, ctx);
        return { filter: this.idFilter('objects', ids, c.negate) };
      }

      if (c.relatedTo) {
        const ids = await this.resolveIds(c.relatedTo, ctx);
        const relTypes = asList(c.relationship);
        const direction = c.direction || 'both';
        // regardingOf ignore le sens : on ne l'utilise que pour « peu importe le sens ».
        if (direction === 'both' && this.options.relatedStrategy === 'regardingOf') {
          // Contrat OpenCTI : la négation se met sur l'opérateur de la valeur « id ».
          const values = [{ key: 'id', values: ids.length ? ids : [NONE], operator: c.negate ? 'not_eq' : 'eq' }];
          if (relTypes.length) values.push({ key: 'relationship_type', values: relTypes });
          return { filter: { key: ['regardingOf'], values, operator: 'eq', mode: 'or' } };
        }
        const other = await this.walkRelationships(ids, relTypes, direction, ctx);
        return { filter: this.idFilter('ids', other, c.negate) };
      }

      if (c.containedIn) {
        const ids = await this.containerObjects(c.containedIn, types, ctx);
        return { filter: this.idFilter('ids', ids, c.negate) };
      }

      throw new Error(`Condition inconnue : ${JSON.stringify(c)}`);
    }

    idFilter(key, ids, negate) {
      return { key: [key], values: ids.length ? ids : [NONE], operator: negate ? 'not_eq' : 'eq', mode: negate ? 'and' : 'or' };
    }

    /**
     * Parcourt les relations des entités `ids` (résultat de la sous-requête) et
     * collecte l'autre extrémité. direction : 'out' = l'entité cherchée est la
     * source (ids en cible), 'in' = l'entité cherchée est la cible, 'both' = les deux.
     */
    async walkRelationships(ids, relTypes, direction, ctx) {
      const arrow = direction === 'out' ? '→' : direction === 'in' ? '←' : '↔';
      const s = this.step(ctx, 'rel', `Relations ${arrow} ${relTypes.join('/') || '(tous types)'} avec ${ids.length} entité(s)`);
      const other = new Set();
      const chunk = 200;
      for (let i = 0; i < ids.length; i += chunk) {
        const part = ids.slice(i, i + chunk);
        const partSet = new Set(part);
        const vars = { relationship_type: relTypes.length ? relTypes : null, fromOrToId: null, fromId: null, toId: null };
        if (direction === 'out') vars.toId = part;
        else if (direction === 'in') vars.fromId = part;
        else vars.fromOrToId = part;
        const rels = await this.fetchAll(Q_RELATIONSHIPS, 'stixCoreRelationships', vars, ctx, `Parcours des relations ${arrow}`);
        rels.forEach((r) => {
          if (!r.from || !r.to) return;
          if (direction === 'out') other.add(r.from.id);
          else if (direction === 'in') other.add(r.to.id);
          else {
            if (partSet.has(r.from.id)) other.add(r.to.id);
            if (partSet.has(r.to.id)) other.add(r.from.id);
          }
        });
      }
      this.done(ctx, s, other.size);
      return [...other];
    }

    /** Table des relations : celle de l'instance (schemaRelationsTypesMapping), sinon la copie embarquée. */
    async relationsMapping() {
      if (this._mapping) return this._mapping;
      try {
        const data = await this.t.request(Q_REL_MAPPING, {}, 'Table des relations (schéma)');
        const mapping = {};
        data.schemaRelationsTypesMapping.forEach((e) => { mapping[e.key] = e.values; });
        this._mapping = { mapping, source: 'instance' };
      } catch (e) {
        this._mapping = { mapping: (root.OD.relationsMapping || {}).mapping || {}, source: 'embarquée', error: e.message };
      }
      return this._mapping;
    }

    resetCaches() { this._mapping = null; this._suggest = new Map(); }

    /**
     * Valeurs existantes en base pour les listes dynamiques, comme l'UI OpenCTI.
     * kind : label | marking | author | entity | vocabulary. Renvoie [{ value, label, color?, hint? }].
     */
    async suggest(kind, { search = '', types = null, category = null } = {}) {
      if (!this._suggest) this._suggest = new Map();
      const key = JSON.stringify([kind, search, types, category]);
      if (this._suggest.has(key)) return this._suggest.get(key);
      const vars = { search: search || null, first: kind === 'vocabulary' ? 200 : 50 };
      if (kind === 'author') vars.types = ['Organization', 'Individual', 'System'];
      if (kind === 'entity') { vars.types = types && types.length ? types : null; vars.first = 30; }
      if (kind === 'vocabulary') vars.category = category;
      const data = await this.t.request(Q_SUGGEST[kind], vars, `Suggestions : ${kind}${search ? ` « ${search} »` : ''}`);
      const edges = Object.values(data)[0].edges.map((e) => e.node);
      const map = {
        label: (n) => ({ value: n.value, label: n.value, color: n.color }),
        marking: (n) => ({ value: n.definition, label: n.definition, color: n.x_opencti_color }),
        author: (n) => ({ value: n.name, label: n.name, hint: n.entity_type }),
        entity: (n) => ({ value: n.representative?.main, label: n.representative?.main, hint: n.entity_type }),
        vocabulary: (n) => ({ value: n.name, label: n.name, hint: n.usages ? `${n.usages} usage${n.usages > 1 ? 's' : ''}` : null }),
      };
      const seen = new Set();
      const res = edges.map(map[kind]).filter((o) => o.value && !seen.has(o.value) && seen.add(o.value));
      this._suggest.set(key, res);
      if (this._suggest.size > 300) this._suggest.delete(this._suggest.keys().next().value);
      return res;
    }

    /** Liste les objets (des types cibles) contenus dans les conteneurs qui satisfont la sous-requête. */
    async containerObjects(containerQuery, targetTypes, ctx) {
      ctx.depth++;
      const cTypes = asList(containerQuery.type);
      const where = await this.compileWhere(containerQuery.where, ctx, cTypes);
      if (cTypes.length) where.filters.push({ key: ['entity_type'], values: cTypes, operator: 'eq', mode: 'or' });
      const s = this.step(ctx, 'sub', `Conteneurs : ${describeQuery(containerQuery)} → contenu ${targetTypes.join(' | ') || ''}`);
      const ids = new Set();
      let after = null;
      let containers = 0;
      const samples = [];
      do {
        const data = await this.gql(ctx, Q_CONTAINERS_OBJECTS, {
          filters: where, search: containerQuery.search || null, first: this.options.containerPage, after,
          objectTypes: targetTypes.length ? targetTypes : null, objectsFirst: this.options.objectsPerContainer,
        }, 'Conteneurs et leur contenu');
        const conn = data.containers;
        for (const edge of conn.edges) {
          const c = edge.node;
          containers++;
          if (samples.length < 6) samples.push(c.representative?.main);
          (c.objects?.edges || []).forEach((e) => e?.node?.id && ids.add(e.node.id));
          let objAfter = c.objects?.pageInfo?.hasNextPage ? c.objects.pageInfo.endCursor : null;
          while (objAfter) {
            const more = await this.gql(ctx, Q_CONTAINER_OBJECTS_PAGE, {
              id: c.id, objectTypes: targetTypes.length ? targetTypes : null, first: this.options.objectsPerContainer, after: objAfter,
            }, `Contenu de ${c.representative?.main || c.id} (suite)`);
            const oc = more.container.objects;
            oc.edges.forEach((e) => e?.node?.id && ids.add(e.node.id));
            objAfter = oc.pageInfo.hasNextPage ? oc.pageInfo.endCursor : null;
          }
        }
        after = conn.pageInfo.hasNextPage ? conn.pageInfo.endCursor : null;
      } while (after);
      s.sample = samples;
      s.label += ` (${containers} conteneur${containers > 1 ? 's' : ''})`;
      this.done(ctx, s, ids.size);
      ctx.depth--;
      return [...ids];
    }
  }

  // ---------------------------------------------------------------------------
  // Agrégations pour les widgets
  // ---------------------------------------------------------------------------
  const GROUP_BY = {
    entity_type: { label: 'Type', get: (n) => [n.entity_type] },
    author: { label: 'Auteur', get: (n) => [n.createdBy?.name || '(aucun)'] },
    label: { label: 'Libellé', get: (n) => (n.objectLabel?.length ? n.objectLabel.map((l) => l.value) : ['(aucun)']) },
    marking: { label: 'Marquage', get: (n) => (n.objectMarking?.length ? n.objectMarking.map((m) => m.definition) : ['(aucun)']) },
    report_types: { label: 'Type de rapport', get: (n) => (n.report_types?.length ? n.report_types : ['(aucun)']) },
    motivation: { label: 'Motivation', get: (n) => [n.primary_motivation || '(aucune)'] },
    confidence: { label: 'Confiance', get: (n) => [n.confidence == null ? '(n/a)' : `${Math.floor(n.confidence / 20) * 20}–${Math.floor(n.confidence / 20) * 20 + 19}`] },
  };

  const DATE_FIELDS = {
    created: 'Création (STIX)',
    created_at: 'Création (plateforme)',
    published: 'Publication',
    updated_at: 'Mise à jour',
  };

  function groupBy(items, key) {
    const g = GROUP_BY[key] || GROUP_BY.entity_type;
    const counts = new Map();
    items.forEach((n) => g.get(n).forEach((k) => counts.set(k, (counts.get(k) || 0) + 1)));
    return [...counts.entries()].map(([k, v]) => ({ key: k, count: v })).sort((a, b) => b.count - a.count || String(a.key).localeCompare(String(b.key)));
  }

  function timeline(items, field = 'created', unit = 'month') {
    const counts = new Map();
    items.forEach((n) => {
      const d = n[field] || n.created_at;
      if (!d) return;
      const k = unit === 'year' ? d.slice(0, 4) : d.slice(0, 7);
      counts.set(k, (counts.get(k) || 0) + 1);
    });
    const keys = [...counts.keys()].sort();
    if (!keys.length) return [];
    // Remplit les mois vides
    const out = [];
    if (unit === 'month') {
      let [y, m] = keys[0].split('-').map(Number);
      const [y1, m1] = keys[keys.length - 1].split('-').map(Number);
      while (y < y1 || (y === y1 && m <= m1)) {
        const k = `${y}-${String(m).padStart(2, '0')}`;
        out.push({ key: k, count: counts.get(k) || 0 });
        m++; if (m > 12) { m = 1; y++; }
      }
      return out;
    }
    return keys.map((k) => ({ key: k, count: counts.get(k) }));
  }

  OD.Transport = Transport;
  OD.Engine = Engine;
  OD.dsl = { describeQuery, describeCond, asList };
  OD.types = { TYPE_TREE, expandTypes, possibleRelations };
  OD.agg = { GROUP_BY, DATE_FIELDS, groupBy, timeline };
  OD.queries = { DISPLAY_FIELDS, Q_OBJECTS, Q_CONTAINERS_OBJECTS, Q_RELATIONSHIPS };
})(typeof window !== 'undefined' ? window : globalThis);
