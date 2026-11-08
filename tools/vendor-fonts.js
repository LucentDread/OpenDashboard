/*
 * Copie les polices IBM Plex (licence SIL OFL 1.1) depuis @fontsource vers
 * vendor/fonts et génère vendor/fonts/fonts.css. Outil de développement :
 * le résultat est versionné, aucune police n'est chargée depuis Internet.
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const out = path.join(root, 'vendor', 'fonts');
fs.mkdirSync(out, { recursive: true });

const FACES = [
  ['ibm-plex-sans', 'IBM Plex Sans', [400, 500, 600]],
  ['ibm-plex-sans-condensed', 'IBM Plex Sans Condensed', [600, 700]],
  ['ibm-plex-mono', 'IBM Plex Mono', [400, 500]],
];
const RANGE = 'U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD';

let css = '/* IBM Plex — SIL Open Font License 1.1 (voir LICENSE-IBM-Plex.txt). Généré par tools/vendor-fonts.js */\n';
for (const [pkg, family, weights] of FACES) {
  for (const w of weights) {
    const file = `${pkg}-latin-${w}-normal.woff2`;
    fs.copyFileSync(path.join(root, 'node_modules', '@fontsource', pkg, 'files', file), path.join(out, file));
    css += `@font-face { font-family: '${family}'; font-style: normal; font-weight: ${w}; font-display: swap; src: url('${file}') format('woff2'); unicode-range: ${RANGE}; }\n`;
  }
}
fs.writeFileSync(path.join(out, 'fonts.css'), css);
fs.copyFileSync(path.join(root, 'node_modules', '@fontsource', 'ibm-plex-sans', 'LICENSE'), path.join(out, 'LICENSE-IBM-Plex.txt'));
console.log(`vendor/fonts : ${fs.readdirSync(out).length} fichiers`);
