import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, 'dist');

await mkdir(dist, { recursive: true });

await esbuild.build({
  entryPoints: [join(root, 'src/main.ts')],
  outfile: join(dist, 'challenge.bundle.js'),
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  minify: true,
  legalComments: 'none',
  sourcemap: false,
  logLevel: 'info'
});

await copyFile(join(root, 'index.html'), join(dist, 'index.html'));
