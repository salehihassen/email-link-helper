const {spawnSync} = require('node:child_process');
const {readdirSync} = require('node:fs');
for (const directory of ['static', 'extension', 'scripts', 'tests']) {
  for (const name of readdirSync(directory).filter(v => /\.(js|cjs)$/.test(v))) {
    const result = spawnSync(process.execPath, ['--check', directory+'/'+name], {stdio: 'inherit'});
    if (result.status !== 0) process.exit(result.status || 1);
  }
}
