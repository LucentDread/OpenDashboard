/*
 * Produit dist/artifact.html : la page index.html sans son squelette
 * (<!doctype>, <html>, <head>, <body>), format attendu pour une publication
 * en artefact claude.ai. Les scripts js/*.js sont publiés tels quels à côté.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const src = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const start = src.indexOf('<!-- OD:BODY-START -->');
const end = src.indexOf('<!-- OD:BODY-END -->');
if (start < 0 || end < 0) throw new Error('Marqueurs OD:BODY-START / OD:BODY-END introuvables');
let page = src
  .slice(start + '<!-- OD:BODY-START -->'.length, end)
  .replace(/^\s*<\/head>\s*$/m, '')
  .replace(/^\s*<body>\s*$/m, '')
  .trim() + '\n';
// Polices : l'aperçu claude.ai n'autorise pas les feuilles de style locales,
// on les inline en data URI (la page reste sans aucune ressource externe).
const fontsDir = path.join(root, 'vendor', 'fonts');
const fontsCss = fs.readFileSync(path.join(fontsDir, 'fonts.css'), 'utf8')
  .replace(/url\('([^']+\.woff2)'\)/g, (_, f) => `url('data:font/woff2;base64,${fs.readFileSync(path.join(fontsDir, f)).toString('base64')}')`);
const link = '<link rel="stylesheet" href="vendor/fonts/fonts.css">';
if (!page.includes(link)) throw new Error('Lien vers vendor/fonts/fonts.css introuvable');
page = page.replace(link, `<style>\n${fontsCss}</style>`);
fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
fs.writeFileSync(path.join(root, 'dist', 'artifact.html'), page);
console.log(`dist/artifact.html (${page.length} octets)`);
