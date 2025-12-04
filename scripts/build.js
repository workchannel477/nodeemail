import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');
const srcDir = path.join(root, 'public');
const distDir = path.join(root, 'dist');
const apiBaseOverride = process.env.API_BASE || process.env.API_BASE_OVERRIDE || '';

function copyRecursive(src, dest) {
  const stats = fs.statSync(src);
  if (stats.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
  } else {
    fs.copyFileSync(src, dest);
  }
}

fs.rmSync(distDir, { recursive: true, force: true });
copyRecursive(srcDir, distDir);

const configPath = path.join(distDir, 'config.js');
if (apiBaseOverride && fs.existsSync(configPath)) {
  const runtimePatch = `\n// Injected by build for deployment targets (e.g. Render)\nwindow.APP_CONFIG = Object.assign({}, window.APP_CONFIG, { apiBase: ${JSON.stringify(
    apiBaseOverride
  )} });\n`;
  fs.appendFileSync(configPath, runtimePatch, 'utf8');
  console.log(`Injected API base override into config.js -> ${apiBaseOverride}`);
}

console.log(`Copied static assets from ${srcDir} to ${distDir}`);
