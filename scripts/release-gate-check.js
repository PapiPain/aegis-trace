const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const root = process.cwd();
console.log('[Stelfid Release Gate]: Ejecutando suite completa verify:all antes de permitir empaquetado/publicacion...');
execSync('npm run verify:all', { stdio: 'inherit', cwd: root });

const manifestPath = path.join(root, 'STELFID_RC_CERTIFICATION_MANIFEST.json');
if (!fs.existsSync(manifestPath)) {
  console.error('[Stelfid Release Gate BLOCKED]: No existe STELFID_RC_CERTIFICATION_MANIFEST.json');
  process.exit(1);
}
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
if (manifest.allLocalChecksPassed !== true || (manifest.executedAndPassedChecks || []).length < 5) {
  console.error('[Stelfid Release Gate BLOCKED]: El manifiesto de certificacion tiene pruebas fallidas o incompletas.');
  process.exit(1);
}
console.log('[Stelfid Release Gate PASSED]: Las 3 suites y el manifiesto de certificacion estan verificados.');
