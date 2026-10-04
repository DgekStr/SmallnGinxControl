import {copyFileSync, mkdirSync, existsSync} from 'node:fs';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const destination = resolve(root, 'static/vendor');
mkdirSync(destination, {recursive: true});
const assets = [
  ['lucide/dist/umd/lucide.js', 'lucide.js'],
  ['chart.js/dist/chart.umd.js', 'chart.js'],
  ['@fontsource-variable/manrope/files/manrope-cyrillic-wght-normal.woff2', 'manrope-cyrillic.woff2'],
  ['@fontsource-variable/manrope/files/manrope-latin-wght-normal.woff2', 'manrope-latin.woff2'],
];
for (const [source, target] of assets) copyFileSync(resolve(root, 'node_modules', source), resolve(destination, target));
for (const name of ['lucide', 'chart.js', '@fontsource-variable/manrope']) {
  for (const license of ['LICENSE', 'LICENSE.md', 'LICENSE.txt']) {
    const source = resolve(root, 'node_modules', name, license);
    if (existsSync(source)) copyFileSync(source, resolve(destination, name.split('/').pop() + '-LICENSE.txt'));
  }
}
console.log('Local browser assets synchronized.');