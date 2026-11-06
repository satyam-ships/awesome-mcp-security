'use strict';
const SENSITIVE = /(\/etc|\/\.ssh|\.aws|\.env|\/root|~\/?$|^\/$)/;
const SECRET_KEY = /(key|token|secret|password|passwd)/i;
const SECRET_VAL = /^(sk-|ghp_|gho_|xox[bap]-|AKIA)[A-Za-z0-9_-]{8,}/;
const POISON = /(ignore (all |previous )|do not (tell|mention)|<important>|before using this tool, read)/i;

function scanServer(name, cfg) {
  const f = [];
  const add = (severity, title, fix) => f.push({ server: name, severity, title, fix });
  const args = (cfg.args || []).map(String);
  const cmd = [cfg.command, ...args].join(' ');

  if (cfg.url && /^http:\/\//.test(cfg.url) && !/localhost|127\.0\.0\.1/.test(cfg.url)) add('high', 'Remote server over plain HTTP', 'Use https:// with authentication');
  if (cfg.url && !cfg.headers && !cfg.auth) add('medium', 'Remote server with no authentication configured', 'Require OAuth or an API key header');
  if (/\bnpx\b|\buvx\b/.test(cfg.command || '') && !args.some(a => /@\d|==\d|@[a-f0-9]{7,}/.test(a)))
    add('medium', 'Package not pinned to a version (supply-chain risk)', 'Pin e.g. package@1.2.3');
  if (/(^|\s)-y(\s|$)/.test(args.join(' ')) && /npx/.test(cfg.command || '')) add('low', 'npx -y auto-installs without prompt', 'Install and review the package first');
  for (const a of args) if (SENSITIVE.test(a)) add('critical', `Broad or sensitive path exposed: ${a}`, 'Scope to a single project directory');
  if (/\b(sh|bash|zsh|cmd|powershell)\b/.test(cfg.command || '') || /\b(rm -rf|curl [^|]*\|\s*(sh|bash))\b/.test(cmd)) add('high', 'Shell execution in server command', 'Run the binary directly; avoid shell wrappers');
  if (/(filesystem|fs|shell|exec|terminal)/i.test(name + cmd) && !/readonly|read-only|--ro/i.test(cmd)) add('medium', 'Write-capable tool without read-only mode', 'Prefer read-only or add approval');
  for (const [k, v] of Object.entries(cfg.env || {})) if (SECRET_VAL.test(String(v)) || (SECRET_KEY.test(k) && v && !/^\$|\$\{/.test(String(v))))
    add('high', `Hardcoded secret in env: ${k}`, 'Reference an environment variable or secret store');
  if (POISON.test(JSON.stringify(cfg))) add('critical', 'Possible tool-poisoning text in config', 'Remove and audit this server');
  return f;
}

function scan(config) {
  const servers = config.mcpServers || config.servers || {};
  const findings = Object.entries(servers).flatMap(([n, c]) => scanServer(n, c));
  const weight = { critical: 30, high: 15, medium: 7, low: 2 };
  const score = Math.max(0, 100 - findings.reduce((s, x) => s + weight[x.severity], 0));
  return { servers: Object.keys(servers).length, findings, score };
}
module.exports = { scan, scanServer };
