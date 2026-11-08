/*
 * OpenDashboard — serveur GraphQL simulé, exécuté dans le navigateur.
 *
 * Le schéma ci-dessous est un SOUS-ENSEMBLE du schéma OpenCTI 6.7.7 : mêmes
 * noms de types, de champs, d'arguments et même format FilterGroup. Une requête
 * qui passe la validation ici a donc de bonnes chances de passer sur une vraie
 * instance (sans garantie : seuls les champs utiles au POC sont repris).
 *
 * La sémantique des filtres reproduit celle d'OpenCTI pour les clés utilisées
 * par le moteur : entity_type, ids, name/description/…, objectLabel,
 * objectMarking, createdBy, objects, regardingOf, fromOrToId, relationship_type.
 *
 * Usage : const server = OD.createMockServer(graphqlLib, OD.mockData.build());
 *         const { data, errors } = await server.execute(query, variables);
 */
(function (root) {
  'use strict';
  const OD = (root.OD = root.OD || {});

  const TYPE_NAMES = {
    'Report': 'Report', 'Grouping': 'Grouping', 'Intrusion-Set': 'IntrusionSet',
    'Threat-Actor-Group': 'ThreatActorGroup', 'Campaign': 'Campaign', 'Malware': 'Malware',
    'Tool': 'Tool', 'Attack-Pattern': 'AttackPattern', 'Vulnerability': 'Vulnerability',
    'Country': 'Country', 'Sector': 'Sector', 'Organization': 'Organization',
  };

  const COMMON = `
    id: ID!
    standard_id: String!
    entity_type: String!
    parent_types: [String]!
    representative: Representative!
    is_inferred: Boolean!
    created_at: DateTime!
    updated_at: DateTime!
    createdBy: Identity
    objectMarking: [MarkingDefinition!]
    objectLabel: [Label!]
    containers(first: Int, entityTypes: [String!]): ContainerConnection
    stixCoreRelationships(first: Int, after: ID, relationship_type: String, fromTypes: [String], toTypes: [String], filters: FilterGroup): StixCoreRelationshipConnection
    confidence: Int
    created: DateTime
    modified: DateTime`;
  const OBJECTS_FIELD = `objects(first: Int, after: ID, orderMode: OrderingMode, filters: FilterGroup, search: String, types: [String], all: Boolean): StixObjectOrStixRelationshipRefConnection`;
  const LIST_ARGS = `first: Int, after: ID, orderMode: OrderingMode, filters: FilterGroup, search: String`;

  const SDL = `
    scalar DateTime
    scalar Any
    scalar StixRef
    enum FilterMode { and or }
    enum FilterOperator { eq not_eq lt lte gt gte match wildcard contains not_contains ends_with not_ends_with starts_with not_starts_with script nil not_nil search within }
    enum OrderingMode { asc desc }
    input FilterGroup { mode: FilterMode! filters: [Filter!]! filterGroups: [FilterGroup!]! }
    input Filter { key: [String!]! values: [Any!]! operator: FilterOperator mode: FilterMode }

    type AppInfo { version: String! }
    type PageInfo { startCursor: String! endCursor: String! hasNextPage: Boolean! hasPreviousPage: Boolean! globalCount: Int! }
    type Representative { main: String! secondary: String }
    type Label { id: ID! standard_id: String! entity_type: String! value: String color: String }
    type MarkingDefinition { id: ID! standard_id: String! entity_type: String! definition_type: String definition: String x_opencti_color: String x_opencti_order: Int! }

    interface StixCoreObject { ${COMMON} }
    interface StixDomainObject { ${COMMON} }
    interface Container { ${COMMON} ${OBJECTS_FIELD} }
    interface Identity { ${COMMON} name: String! description: String }
    interface Location { ${COMMON} name: String! description: String }
    interface ThreatActor { ${COMMON} name: String! description: String aliases: [String] }

    type Report implements StixCoreObject & StixDomainObject & Container { ${COMMON} name: String! description: String report_types: [String] published: DateTime! ${OBJECTS_FIELD} }
    type Grouping implements StixCoreObject & StixDomainObject & Container { ${COMMON} name: String! description: String context: String! ${OBJECTS_FIELD} }
    type IntrusionSet implements StixCoreObject & StixDomainObject { ${COMMON} name: String! description: String aliases: [String] first_seen: DateTime last_seen: DateTime goals: [String] resource_level: String primary_motivation: String }
    type ThreatActorGroup implements StixCoreObject & StixDomainObject & ThreatActor { ${COMMON} name: String! description: String aliases: [String] threat_actor_types: [String] }
    type Campaign implements StixCoreObject & StixDomainObject { ${COMMON} name: String! description: String aliases: [String] first_seen: DateTime last_seen: DateTime objective: String }
    type Malware implements StixCoreObject & StixDomainObject { ${COMMON} name: String! description: String aliases: [String] malware_types: [String] is_family: Boolean }
    type Tool implements StixCoreObject & StixDomainObject { ${COMMON} name: String! description: String aliases: [String] tool_types: [String] }
    type AttackPattern implements StixCoreObject & StixDomainObject { ${COMMON} name: String! description: String aliases: [String] x_mitre_id: String }
    type Vulnerability implements StixCoreObject & StixDomainObject { ${COMMON} name: String! description: String x_opencti_cvss_base_score: Float }
    type Country implements StixCoreObject & StixDomainObject & Location { ${COMMON} name: String! description: String }
    type Sector implements StixCoreObject & StixDomainObject & Identity { ${COMMON} name: String! description: String }
    type Organization implements StixCoreObject & StixDomainObject & Identity { ${COMMON} name: String! description: String }

    type StixCoreRelationship {
      id: ID! standard_id: String! entity_type: String! parent_types: [String]! relationship_type: String!
      description: String confidence: Int start_time: DateTime stop_time: DateTime created: DateTime created_at: DateTime! updated_at: DateTime!
      is_inferred: Boolean!
      from: StixObjectOrStixRelationshipOrCreator
      to: StixObjectOrStixRelationshipOrCreator
      createdBy: Identity objectMarking: [MarkingDefinition!] objectLabel: [Label!]
    }

    union StixObjectOrStixRelationship = MarkingDefinition | Label | Report | Grouping | IntrusionSet | ThreatActorGroup | Campaign | Malware | Tool | AttackPattern | Vulnerability | Country | Sector | Organization | StixCoreRelationship
    union StixObjectOrStixRelationshipOrCreator = MarkingDefinition | Label | Report | Grouping | IntrusionSet | ThreatActorGroup | Campaign | Malware | Tool | AttackPattern | Vulnerability | Country | Sector | Organization | StixCoreRelationship

    type StixCoreObjectEdge { cursor: String! node: StixCoreObject! }
    type StixCoreObjectConnection { pageInfo: PageInfo! edges: [StixCoreObjectEdge!]! }
    type StixDomainObjectEdge { cursor: String! node: StixDomainObject! }
    type StixDomainObjectConnection { pageInfo: PageInfo! edges: [StixDomainObjectEdge!]! }
    type ContainerEdge { cursor: String! node: Container! }
    type ContainerConnection { pageInfo: PageInfo! edges: [ContainerEdge!]! }
    type ReportEdge { cursor: String! node: Report! }
    type ReportConnection { pageInfo: PageInfo! edges: [ReportEdge!]! }
    type IntrusionSetEdge { cursor: String! node: IntrusionSet! }
    type IntrusionSetConnection { pageInfo: PageInfo! edges: [IntrusionSetEdge!]! }
    type MalwareEdge { cursor: String! node: Malware! }
    type MalwareConnection { pageInfo: PageInfo! edges: [MalwareEdge!]! }
    type StixCoreRelationshipEdge { cursor: String! node: StixCoreRelationship! }
    type StixCoreRelationshipConnection { pageInfo: PageInfo! edges: [StixCoreRelationshipEdge!]! }
    type LabelEdge { cursor: String! node: Label! }
    type LabelConnection { pageInfo: PageInfo! edges: [LabelEdge!]! }
    type MarkingDefinitionEdge { cursor: String! node: MarkingDefinition! }
    type MarkingDefinitionConnection { pageInfo: PageInfo! edges: [MarkingDefinitionEdge!]! }
    type StixObjectOrStixRelationshipRefEdge { cursor: String! types: [String]! node: StixObjectOrStixRelationship! }
    type StixObjectOrStixRelationshipRefConnection { pageInfo: PageInfo! edges: [StixObjectOrStixRelationshipRefEdge] }

    type Query {
      about: AppInfo
      stixCoreObject(id: String!): StixCoreObject
      stixCoreObjects(${LIST_ARGS}, types: [String]): StixCoreObjectConnection
      stixDomainObjects(${LIST_ARGS}, types: [String]): StixDomainObjectConnection
      container(id: String): Container
      containers(${LIST_ARGS}, toStix: Boolean): ContainerConnection
      reports(${LIST_ARGS}, toStix: Boolean): ReportConnection
      intrusionSets(${LIST_ARGS}, toStix: Boolean): IntrusionSetConnection
      malwares(${LIST_ARGS}, toStix: Boolean): MalwareConnection
      stixCoreRelationships(
        first: Int, after: ID, orderMode: OrderingMode,
        fromOrToId: [String], elementWithTargetTypes: [String],
        fromId: [String], fromRole: String, fromTypes: [String],
        toId: [String], toRole: String, toTypes: [String],
        relationship_type: [String], search: String, filters: FilterGroup
      ): StixCoreRelationshipConnection
      labels(${LIST_ARGS}): LabelConnection
      markingDefinitions(${LIST_ARGS}): MarkingDefinitionConnection
    }
  `;

  // ---------------------------------------------------------------------------
  // Évaluation des filtres (FilterGroup) sur un objet du jeu de données
  // ---------------------------------------------------------------------------
  const norm = (v) => (typeof v === 'string' ? v.toLowerCase() : v);
  const DATE_KEYS = new Set(['created', 'modified', 'created_at', 'updated_at', 'published', 'first_seen', 'last_seen', 'start_time', 'stop_time']);
  const NEGATIVE = new Set(['not_eq', 'not_contains', 'not_starts_with', 'not_ends_with', 'nil']);

  function createFilterEngine(db) {
    function valuesOf(o, key) {
      switch (key) {
        case 'entity_type': return [o.entity_type, ...(o.parent_types || [])];
        case 'ids': case 'id': return [o.id, o.standard_id];
        case 'objectLabel': return o.labels || [];
        case 'objectMarking': return o.markings || [];
        case 'createdBy': return o.createdBy ? [o.createdBy] : [];
        case 'objects': return o.objects || [];
        case 'alias': return [...(o.aliases || []), ...(o.x_opencti_aliases || [])];
        case 'relationship_type': return o.relationship_type ? [o.relationship_type, ...(o.parent_types || [])] : [];
        case 'fromId': return o.fromId ? [o.fromId] : [];
        case 'toId': return o.toId ? [o.toId] : [];
        case 'fromOrToId': return [o.fromId, o.toId].filter(Boolean);
        case 'fromTypes': { const f = db.byId.get(o.fromId); return f ? [f.entity_type, ...f.parent_types] : []; }
        case 'toTypes': { const t = db.byId.get(o.toId); return t ? [t.entity_type, ...t.parent_types] : []; }
        default: {
          const v = o[key];
          if (v === undefined || v === null) return [];
          return Array.isArray(v) ? v : [v];
        }
      }
    }

    function compare(attr, value, op, key) {
      if (DATE_KEYS.has(key)) { attr = Date.parse(attr); value = Date.parse(value); }
      else if (typeof attr === 'number') value = Number(value);
      switch (op) {
        case 'gt': return attr > value;
        case 'gte': return attr >= value;
        case 'lt': return attr < value;
        case 'lte': return attr <= value;
        default: return false;
      }
    }

    function regardingOf(o, f) {
      const spec = {};
      (f.values || []).forEach((v) => { if (v && v.key) spec[v.key] = v.values || []; });
      const ids = new Set(spec.id || []);
      const types = new Set(spec.relationship_type || []);
      const rels = db.relsByEntity.get(o.id) || [];
      return rels.some((rl) => {
        if (types.size && !types.has(rl.relationship_type)) return false;
        if (!ids.size) return true;
        const other = rl.fromId === o.id ? rl.toId : rl.fromId;
        const otherStd = db.byId.get(other)?.standard_id;
        return ids.has(other) || ids.has(otherStd);
      });
    }

    function matchFilter(o, f) {
      const op = f.operator || 'eq';
      const keys = Array.isArray(f.key) ? f.key : [f.key];
      return keys.some((key) => {
        if (key === 'regardingOf') {
          const res = regardingOf(o, f);
          return op === 'not_eq' ? !res : res;
        }
        const attrs = valuesOf(o, key);
        if (op === 'nil') return attrs.length === 0 || attrs.every((a) => a === '' || a === null);
        if (op === 'not_nil') return attrs.length > 0 && attrs.some((a) => a !== '' && a !== null);
        const mode = f.mode || (NEGATIVE.has(op) ? 'and' : 'or');
        const test = (value) => {
          const v = norm(value);
          const A = attrs.map(norm);
          switch (op) {
            case 'eq': return A.includes(v);
            case 'not_eq': return !A.includes(v);
            case 'contains': case 'search': case 'match': case 'wildcard': return A.some((a) => typeof a === 'string' && a.includes(String(v)));
            case 'not_contains': return !A.some((a) => typeof a === 'string' && a.includes(String(v)));
            case 'starts_with': return A.some((a) => typeof a === 'string' && a.startsWith(String(v)));
            case 'not_starts_with': return !A.some((a) => typeof a === 'string' && a.startsWith(String(v)));
            case 'ends_with': return A.some((a) => typeof a === 'string' && a.endsWith(String(v)));
            case 'not_ends_with': return !A.some((a) => typeof a === 'string' && a.endsWith(String(v)));
            case 'gt': case 'gte': case 'lt': case 'lte': return attrs.some((a) => compare(a, value, op, key));
            default: throw new Error(`Opérateur non supporté par le mock : ${op}`);
          }
        };
        const values = f.values || [];
        if (!values.length) return true;
        return mode === 'and' ? values.every(test) : values.some(test);
      });
    }

    function matchGroup(o, g) {
      if (!g) return true;
      const results = [
        ...(g.filters || []).map((f) => matchFilter(o, f)),
        ...(g.filterGroups || []).map((sub) => matchGroup(o, sub)),
      ];
      if (!results.length) return true;
      return g.mode === 'or' ? results.some(Boolean) : results.every(Boolean);
    }

    function matchSearch(o, search) {
      if (!search) return true;
      const s = search.toLowerCase();
      return [o.name, o.description, ...(o.aliases || [])].some((v) => typeof v === 'string' && v.toLowerCase().includes(s));
    }

    return { matchGroup, matchSearch };
  }

  // ---------------------------------------------------------------------------
  // Serveur
  // ---------------------------------------------------------------------------
  function createMockServer(graphql, data, options = {}) {
    const schema = graphql.buildSchema(SDL);
    const latency = options.latency ?? [60, 220];

    const db = {
      byId: new Map(),
      relsByEntity: new Map(),
      containersByObject: new Map(),
      entities: data.entities,
      relationships: data.relationships,
    };
    [...data.entities, ...data.relationships, ...data.labels, ...data.markings].forEach((o) => db.byId.set(o.id, o));
    data.relationships.forEach((rl) => {
      [rl.fromId, rl.toId].forEach((id) => {
        if (!db.relsByEntity.has(id)) db.relsByEntity.set(id, []);
        db.relsByEntity.get(id).push(rl);
      });
    });
    data.entities.forEach((c) => (c.objects || []).forEach((oid) => {
      if (!db.containersByObject.has(oid)) db.containersByObject.set(oid, []);
      db.containersByObject.get(oid).push(c);
    }));
    const engine = createFilterEngine(db);

    function paginate(list, args, wrap) {
      const first = Math.min(args.first ?? 25, 5000);
      const offset = args.after ? Number(atobSafe(args.after)) + 1 : 0;
      const slice = list.slice(offset, offset + first);
      const edges = slice.map((o, i) => ({ cursor: btoaSafe(String(offset + i)), node: wrap(o), types: ['manual'] }));
      return {
        edges,
        pageInfo: {
          startCursor: edges[0]?.cursor || '',
          endCursor: edges[edges.length - 1]?.cursor || '',
          hasNextPage: offset + first < list.length,
          hasPreviousPage: offset > 0,
          globalCount: list.length,
        },
      };
    }

    function typeFilter(types) {
      if (!types || !types.length) return () => true;
      const set = new Set(types.filter(Boolean));
      return (o) => set.has(o.entity_type) || (o.parent_types || []).some((p) => set.has(p));
    }

    function listEntities(args, baseTypes) {
      const tf = typeFilter(args.types);
      const bf = typeFilter(baseTypes);
      const list = db.entities.filter((o) => bf(o) && tf(o) && engine.matchSearch(o, args.search) && engine.matchGroup(o, args.filters));
      list.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      return paginate(list, args, view);
    }

    function view(o) {
      if (!o) return null;
      if (o.entity_type === 'Label') return { __typename: 'Label', ...o };
      if (o.entity_type === 'Marking-Definition') return { __typename: 'MarkingDefinition', ...o };
      if (o.relationship_type) return relView(o);
      return {
        ...o,
        __typename: TYPE_NAMES[o.entity_type],
        is_inferred: false,
        representative: { main: o.name, secondary: o.description || null },
        createdBy: () => view(db.byId.get(o.createdBy)),
        objectLabel: () => (o.labels || []).map((id) => view(db.byId.get(id))),
        objectMarking: () => (o.markings || []).map((id) => view(db.byId.get(id))),
        containers: (args) => {
          const list = (db.containersByObject.get(o.id) || []).filter(typeFilter(args.entityTypes));
          return paginate(list, args, view);
        },
        stixCoreRelationships: (args) => {
          let list = db.relsByEntity.get(o.id) || [];
          if (args.relationship_type) list = list.filter((rl) => rl.relationship_type === args.relationship_type);
          list = list.filter((rl) => engine.matchGroup(rl, args.filters));
          return paginate(list, args, relView);
        },
        objects: o.objects ? (args) => {
          const tf = typeFilter(args.types);
          const list = o.objects.map((id) => db.byId.get(id)).filter((e) => e && tf(e) && engine.matchGroup(e, args.filters) && engine.matchSearch(e, args.search));
          if (args.all) args = { ...args, first: 5000 };
          return paginate(list, args, view);
        } : undefined,
      };
    }

    function relView(rl) {
      return {
        ...rl,
        __typename: 'StixCoreRelationship',
        is_inferred: false,
        from: () => view(db.byId.get(rl.fromId)),
        to: () => view(db.byId.get(rl.toId)),
        createdBy: () => view(db.byId.get(rl.createdBy)),
        objectLabel: () => [],
        objectMarking: () => (rl.markings || []).map((id) => view(db.byId.get(id))),
      };
    }

    const rootValue = {
      about: () => ({ version: '6.7.7 (mock)' }),
      stixCoreObject: ({ id }) => view(db.entities.find((e) => e.id === id || e.standard_id === id)),
      stixCoreObjects: (args) => listEntities(args, null),
      stixDomainObjects: (args) => listEntities(args, ['Stix-Domain-Object']),
      container: ({ id }) => view(db.entities.find((e) => (e.id === id || e.standard_id === id) && e.objects)),
      containers: (args) => listEntities(args, ['Container']),
      reports: (args) => listEntities(args, ['Report']),
      intrusionSets: (args) => listEntities(args, ['Intrusion-Set']),
      malwares: (args) => listEntities(args, ['Malware']),
      stixCoreRelationships: (args) => {
        const set = (a) => (a && a.length ? new Set(a) : null);
        const fot = set(args.fromOrToId), fi = set(args.fromId), ti = set(args.toId), rt = set(args.relationship_type);
        const ft = typeFilter(args.fromTypes), tt = typeFilter(args.toTypes);
        const list = db.relationships.filter((rl) =>
          (!fot || fot.has(rl.fromId) || fot.has(rl.toId)) &&
          (!fi || fi.has(rl.fromId)) && (!ti || ti.has(rl.toId)) &&
          (!rt || rt.has(rl.relationship_type)) &&
          ft(db.byId.get(rl.fromId)) && tt(db.byId.get(rl.toId)) &&
          engine.matchGroup(rl, args.filters));
        return paginate(list, args, relView);
      },
      labels: (args) => paginate(data.labels.filter((l) => engine.matchGroup(l, args.filters) &&
        (!args.search || l.value.toLowerCase().includes(args.search.toLowerCase()))), args, view),
      markingDefinitions: (args) => paginate(data.markings.filter((m) => engine.matchGroup(m, args.filters) &&
        (!args.search || m.definition.toLowerCase().includes(args.search.toLowerCase()))), args, view),
    };

    const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

    return {
      schema,
      sdl: SDL,
      stats: { entities: data.entities.length, relationships: data.relationships.length },
      async execute(query, variables) {
        if (latency) await sleep(latency[0] + Math.random() * (latency[1] - latency[0]));
        const result = await graphql.graphql({ schema, source: query, rootValue, variableValues: variables });
        return JSON.parse(JSON.stringify({ data: result.data, errors: result.errors?.map((e) => ({ message: e.message })) }));
      },
    };
  }

  function btoaSafe(s) { return typeof btoa === 'function' ? btoa(s) : Buffer.from(s).toString('base64'); }
  function atobSafe(s) { return typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString(); }

  OD.createMockServer = createMockServer;
})(typeof window !== 'undefined' ? window : globalThis);
