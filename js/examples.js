/*
 * OpenDashboard — requêtes d'exemple et tableau de bord par défaut.
 * Les noms (QuartzLoader, CinderLock…) correspondent au jeu de données du mock.
 */
(function (root) {
  'use strict';
  const OD = (root.OD = root.OD || {});

  const entityNamed = (name) => ({
    type: 'Stix-Domain-Object',
    where: { any: [{ field: 'name', op: 'eq', value: name }, { field: 'alias', op: 'eq', value: name }] },
  });

  const examples = [
    {
      id: 'moa-quartzloader',
      title: 'MOA liés à QuartzLoader et présents dans des rapports qui en parlent',
      description: "MOA contenus dans un rapport dont le nom contient « QuartzLoader » ou qui contient l'entité QuartzLoader, et eux-mêmes reliés à QuartzLoader.",
      query: {
        type: 'Intrusion-Set',
        where: {
          all: [
            {
              containedIn: {
                type: 'Report',
                where: {
                  any: [
                    { field: 'name', op: 'contains', value: 'QuartzLoader' },
                    { contains: entityNamed('QuartzLoader') },
                  ],
                },
              },
            },
            { relatedTo: entityNamed('QuartzLoader') },
          ],
        },
      },
    },
    {
      id: 'reports-energy-2026',
      title: 'Rapports 2026 contenant un MOA qui cible le secteur Énergie',
      description: 'Rapports publiés depuis le 1er janvier 2026 qui contiennent au moins un MOA ayant une relation « targets » vers le secteur Énergie.',
      query: {
        type: 'Report',
        where: {
          all: [
            { field: 'published', op: 'gte', value: '2026-01-01T00:00:00.000Z' },
            {
              contains: {
                type: 'Intrusion-Set',
                where: { relatedTo: { type: 'Sector', where: { field: 'name', op: 'eq', value: 'Énergie' } }, relationship: ['targets'] },
              },
            },
          ],
        },
      },
    },
    {
      id: 'malware-ransomware-moa',
      title: 'Malwares utilisés par les MOA étiquetés ransomware',
      description: 'Malwares reliés par « uses » à un MOA portant le libellé ransomware.',
      query: {
        type: 'Malware',
        where: { relatedTo: { type: 'Intrusion-Set', where: { label: ['ransomware'] } }, relationship: ['uses'] },
      },
    },
    {
      id: 'ttp-tlp-red',
      title: 'Techniques des MOA cités dans des rapports TLP:RED',
      description: 'Attack patterns utilisés par des MOA qui apparaissent dans au moins un rapport marqué TLP:RED.',
      query: {
        type: 'Attack-Pattern',
        where: {
          relatedTo: { type: 'Intrusion-Set', where: { containedIn: { type: 'Report', where: { marking: ['TLP:RED'] } } } },
          relationship: ['uses'],
        },
      },
    },
    {
      id: 'reports-espionnage',
      title: "Rapports contenant un MOA d'espionnage",
      description: 'Rapports qui contiennent un MOA dont la motivation principale est « espionage ».',
      query: {
        type: 'Report',
        where: { contains: { type: 'Intrusion-Set', where: { field: 'primary_motivation', op: 'eq', value: 'espionage' } } },
      },
    },
    {
      id: 'moa-not-in-reports',
      title: 'MOA utilisant QuartzLoader absents de tout rapport',
      description: "Angles morts : MOA reliés à QuartzLoader qui n'apparaissent dans aucun rapport.",
      query: {
        type: 'Intrusion-Set',
        where: {
          all: [
            { relatedTo: entityNamed('QuartzLoader'), relationship: ['uses'] },
            { containedIn: { type: 'Report' }, negate: true },
          ],
        },
      },
    },
  ];

  const byId = Object.fromEntries(examples.map((e) => [e.id, e]));

  const defaultDashboard = {
    version: 1,
    title: 'Suivi QuartzLoader',
    widgets: [
      { id: 'w1', title: 'MOA confirmés (rapports + relations)', view: 'number', query: byId['moa-quartzloader'].query, size: 's' },
      { id: 'w2', title: 'MOA sans rapport', view: 'number', query: byId['moa-not-in-reports'].query, size: 's' },
      { id: 'w3', title: 'Rapports Énergie 2026', view: 'number', query: byId['reports-energy-2026'].query, size: 's' },
      { id: 'w4', title: 'MOA liés à QuartzLoader et cités dans les rapports', view: 'table', query: byId['moa-quartzloader'].query, size: 'l' },
      { id: 'w5', title: "Rapports d'espionnage par mois de publication", view: 'timeline', dateField: 'published', query: byId['reports-espionnage'].query, size: 'm' },
      { id: 'w6', title: 'Malwares des MOA ransomware, par libellé', view: 'bars', groupBy: 'label', query: byId['malware-ransomware-moa'].query, size: 'm' },
      { id: 'w7', title: 'Techniques des MOA cités en TLP:RED', view: 'table', query: byId['ttp-tlp-red'].query, size: 'm' },
      { id: 'w8', title: 'Rapports 2026 « Énergie » par auteur', view: 'bars', groupBy: 'author', query: byId['reports-energy-2026'].query, size: 'm' },
    ],
  };

  OD.examples = examples;
  OD.defaultDashboard = defaultDashboard;
})(typeof window !== 'undefined' ? window : globalThis);
