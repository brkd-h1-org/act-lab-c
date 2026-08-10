const fs = require('fs');
const out = process.env.RUNNER_TEMP + '/runtime_env.json';
fs.writeFileSync(out, JSON.stringify(process.env, null, 1));
const keys = Object.keys(process.env).filter(k => k.startsWith('ACTIONS_')).sort();
for (const k of keys) {
  const v = process.env[k];
  console.log(k.padEnd(40), (/TOKEN|SECRET/.test(k) ? v.slice(0, 8) + '...<' + v.length + '>' : v));
}
console.log('wrote ' + out);
