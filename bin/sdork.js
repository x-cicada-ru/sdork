#!/usr/bin/env node

const { run } = require('../src/cli');

run(process.argv.slice(2)).catch((err) => {
  process.stderr.write('[!] ' + (err && err.message ? err.message : String(err)) + '\n');
  process.exitCode = 1;
});
