import type { Target } from 'bun';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const commonConfig = {
  entrypoints: ['./src/index.ts'],
  external: ['@bsv/sdk'],
  sourcemap: "external" as const,
  minify: true,
  target: "bun" as Target,
};

async function generateTypes() {
  return new Promise((resolve, reject) => {
    const tsc = spawn('tsc', ['--emitDeclarationOnly', '--declaration'], {
      stdio: 'inherit',
      shell: true
    });

    tsc.on('close', (code) => {
      if (code === 0) {
        resolve(undefined);
      } else {
        reject(new Error(`tsc exited with code ${code}`));
      }
    });
  });
}

async function build() {
  // Generate type declarations
  console.log('\nGenerating type declarations...');
  await generateTypes();

  // Build bundles
  console.log('\nBuilding bundles...');

  // ESM build (modern)
  await Bun.build({
    ...commonConfig,
    outdir: './dist',
    format: 'esm',
    naming: {
      entry: 'index.modern.js',
      chunk: '[name]-[hash].modern.js',
    },
  });

  // ESM build (module)
  await Bun.build({
    ...commonConfig,
    outdir: './dist',
    format: 'esm',
    naming: {
      entry: 'index.module.js',
      chunk: '[name]-[hash].module.js',
    },
  });

  // CJS build
  await Bun.build({
    ...commonConfig,
    outdir: './dist',
    format: 'cjs',
    naming: {
      entry: 'index.cjs',
      chunk: '[name]-[hash].cjs',
    },
  });

  // Report sizes
  const files = [
    'dist/index.modern.js',
    'dist/index.module.js',
    'dist/index.cjs'
  ];

  console.log('\nBuild sizes:');
  for (const file of files) {
    const content = readFileSync(file);
    const gzipped = gzipSync(content);
    console.log(`${file}: ${(content.length / 1024).toFixed(2)} kB (${(gzipped.length / 1024).toFixed(2)} kB gzipped)`);
  }
}

build().catch(console.error);
