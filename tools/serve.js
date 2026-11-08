#!/usr/bin/env node
/*
 * Serveur local d'OpenDashboard : sert les fichiers statiques et relaie
 * /graphql vers une instance OpenCTI. La page et l'API ont alors la même
 * origine, ce qui évite toute configuration CORS côté OpenCTI.
 *
 *   node tools/serve.js --target https://opencti.exemple.fr [--port 8080] [--insecure]
 *
 * Dans les Réglages de la page : mode « Instance OpenCTI », URL http://localhost:8080
 * et votre jeton API (il est transmis tel quel à OpenCTI, jamais stocké ici).
 * --insecure accepte un certificat auto-signé sur l'instance cible.
 */
'use strict';
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : def; };
const target = opt('target', process.env.OPENCTI_URL || '');
const port = Number(opt('port', 8080));
const insecure = args.includes('--insecure');
const root = path.join(__dirname, '..');

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png' };

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/graphql')) {
    if (!target) { res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Aucune cible : relancez avec --target https://votre-opencti'); }
    const url = new URL('/graphql', target);
    const client = url.protocol === 'https:' ? https : http;
    const headers = { 'content-type': req.headers['content-type'] || 'application/json' };
    if (req.headers.authorization) headers.authorization = req.headers.authorization;
    const up = client.request(url, { method: req.method, headers, rejectUnauthorized: !insecure }, (r) => {
      res.writeHead(r.statusCode, { 'content-type': r.headers['content-type'] || 'application/json' });
      r.pipe(res);
    });
    up.on('error', (e) => { res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(`Relais vers ${target} impossible : ${e.message}`); });
    return req.pipe(up);
  }
  const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = path.normalize(path.join(root, rel === '/' ? 'index.html' : rel));
  if (!file.startsWith(root) || file.includes(`${path.sep}node_modules${path.sep}`)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Introuvable'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`OpenDashboard : http://localhost:${port}`);
  console.log(target ? `/graphql → ${new URL('/graphql', target).href}${insecure ? ' (certificat non vérifié)' : ''}` : 'Pas de --target : seul le mock fonctionnera.');
});
