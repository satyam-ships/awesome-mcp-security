'use strict';
const test = require('node:test'); const assert = require('node:assert');
const { scan } = require('../src/scan');
test('flags root filesystem as critical', () => {
  const r = scan({ mcpServers: { f: { command: 'npx', args: ['-y', 'x', '/'] } } });
  assert.ok(r.findings.some(f => f.severity === 'critical'));
});
test('clean pinned config scores 100', () => {
  const r = scan({ mcpServers: { f: { command: 'node', args: ['server.js', './docs'] } } });
  assert.strictEqual(r.score, 100);
});
test('flags hardcoded secret', () => {
  const r = scan({ mcpServers: { d: { command: 'node', args: [], env: { API_TOKEN: 'abc' } } } });
  assert.ok(r.findings.some(f => /Hardcoded secret/.test(f.title)));
});
