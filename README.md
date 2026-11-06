# awesome-mcp-security 🔐

> Security resources for Model Context Protocol servers, plus **`mcp-scan`**, a zero-dependency scanner for your MCP config.

[awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) tells you what exists. This repo tells you **what is safe to run**.

```
$ node bin/mcp-scan.js examples/risky.json

MCP SECURITY SCAN

🔴 CRITICAL  [files] Broad or sensitive path exposed: /
    fix: Scope to a single project directory
🟠 HIGH  [db] Hardcoded secret in env: DB_PASSWORD
    fix: Reference an environment variable or secret store
🟠 HIGH  [remote] Remote server over plain HTTP
    fix: Use https:// with authentication
...
Security Score: 17/100
```

## What `mcp-scan` detects
- Overly broad or sensitive filesystem paths (`/`, `~`, `.ssh`, `.aws`)
- Hardcoded secrets in `env`
- Unpinned `npx`/`uvx` packages (supply chain)
- Shell execution wrappers
- Plain-HTTP and unauthenticated remote servers
- Tool-poisoning phrases in config

```bash
node bin/mcp-scan.js ~/Library/Application\ Support/Claude/claude_desktop_config.json
node bin/mcp-scan.js mcp.json --json   # exit 1 on critical/high, for CI
```

## Resources
- [Server risk profiles](servers.md): assessment template and common servers
- Related: awesome-ai-agent-security

## Roadmap
- [ ] Scan live servers' tool manifests for poisoning and rug-pulls
- [ ] SARIF output for GitHub code scanning
- [ ] Community database of reviewed servers

## License
[MIT](LICENSE)
