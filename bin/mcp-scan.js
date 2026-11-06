#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const { scan } = require('../src/scan');
const file = process.argv[2];
if (!file) { console.log('Usage: mcp-scan <config.json> [--json]'); process.exit(0); }
const r = scan(JSON.parse(fs.readFileSync(file, 'utf8')));
if (process.argv.includes('--json')) { console.log(JSON.stringify(r, null, 2)); process.exit(r.findings.some(x => ['critical','high'].includes(x.severity)) ? 1 : 0); }
const icon = { critical: '🔴 CRITICAL', high: '🟠 HIGH', medium: '🟡 MEDIUM', low: '🟢 LOW' };
console.log('\nMCP SECURITY SCAN\n');
for (const sev of ['critical', 'high', 'medium', 'low']) for (const x of r.findings.filter(f => f.severity === sev))
  console.log(`${icon[sev]}  [${x.server}] ${x.title}\n    fix: ${x.fix}`);
console.log(`\n${r.servers} servers, ${r.findings.length} findings. Security Score: ${r.score}/100\n`);
process.exit(r.findings.some(x => ['critical','high'].includes(x.severity)) ? 1 : 0);
