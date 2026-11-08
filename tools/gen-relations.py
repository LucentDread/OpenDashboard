#!/usr/bin/env python3
"""
Génère js/opencti-relations.js : table des relations autorisées entre types
(équivalent hors ligne de la requête schemaRelationsTypesMapping d'OpenCTI).

Outil de développement uniquement (nécessite l'accès à GitHub) :
    python3 tools/gen-relations.py 6.7.7
Les types abstraits (Threat-Actor, Stix-Cyber-Observable) sont aplatis en types
concrets, comme le fait OpenCTI dans domain/stixRelationship.js.
"""
import json, re, sys, urllib.request

TAG = sys.argv[1] if len(sys.argv) > 1 else '6.7.7'
BASE = f'https://raw.githubusercontent.com/OpenCTI-Platform/opencti/{TAG}/opencti-platform/opencti-graphql/src/'

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=60) as r:
        return r.read().decode()

stix = get('database/stix.ts')
consts = {}
for imp in sorted(set(re.findall(r"from '\.\./([^']+)'", stix))):
    try:
        src = get(imp + '.ts')
    except Exception:
        continue
    consts.update(dict(re.findall(r"export const (\w+) = '([^']+)'", src)))
consts.setdefault('ENTITY_TYPE_THREAT_ACTOR', 'Threat-Actor')
consts.setdefault('ABSTRACT_STIX_CYBER_OBSERVABLE', 'Stix-Cyber-Observable')

CHILDREN = {
    'Threat-Actor': ['Threat-Actor-Group', 'Threat-Actor-Individual'],
    'Stix-Cyber-Observable': [
        'Artifact', 'Autonomous-System', 'Bank-Account', 'Credential', 'Cryptocurrency-Wallet', 'Cryptographic-Key',
        'Directory', 'Domain-Name', 'Email-Addr', 'Email-Message', 'Email-Mime-Part-Type', 'Hostname', 'IPv4-Addr',
        'IPv6-Addr', 'Mac-Addr', 'Media-Content', 'Mutex', 'Network-Traffic', 'Payment-Card', 'Persona', 'Phone-Number',
        'Process', 'Software', 'StixFile', 'Text', 'Tracking-Number', 'Url', 'User-Account', 'User-Agent',
        'Windows-Registry-Key', 'Windows-Registry-Value-Type', 'X509-Certificate'],
}
expand = lambda t: CHILDREN.get(t, [t])

body = stix[stix.index('export const stixCoreRelationshipsMapping'):]
body = body[:body.index('\n};')]
mapping = {}
for a, b, rels in re.findall(r"\[`\$\{(\w+)\}_\$\{(\w+)\}`\]:\s*\[(.*?)\]", body, re.S):
    if a not in consts or b not in consts:
        continue
    names = {consts.get(n, n) for n in re.findall(r"name:\s*(\w+)", rels)}
    for f in expand(consts[a]):
        for t in expand(consts[b]):
            mapping.setdefault(f'{f}_{t}', set()).update(names)

out = {k: sorted(v) for k, v in sorted(mapping.items())}
js = f"""/*
 * Relations autorisées entre types d'entités dans OpenCTI {TAG}.
 * Fichier généré par tools/gen-relations.py depuis database/stix.ts : ne pas éditer.
 * Clé « Source_Cible » → types de relation possibles (related-to et revoked-by
 * sont toujours autorisés et ne figurent pas ici).
 */
(function (root) {{
  'use strict';
  const OD = (root.OD = root.OD || {{}});
  OD.relationsMapping = {{ version: '{TAG}', mapping: {json.dumps(out, ensure_ascii=False, indent=0)} }};
}})(typeof window !== 'undefined' ? window : globalThis);
"""
open('js/opencti-relations.js', 'w').write(js)
print(f'{len(out)} paires écrites dans js/opencti-relations.js')
