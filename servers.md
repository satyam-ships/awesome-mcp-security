# Server Risk Profiles

Use this template to assess any MCP server before installing it. Contributions welcome: add a row per server you've reviewed.

| Server | Filesystem | Network | Credentials | Prompt-injection exposure | Recommended sandbox |
|---|---|---|---|---|---|
| filesystem | read/write (scoped dir) | none | none | Medium (file contents) | Container, bind-mount one dir read-only |
| fetch / browser | none | outbound any | none | **High** (web content) | Egress allowlist, no secrets in same agent |
| github | none | api.github.com | PAT/OAuth | Medium (issues, PRs) | Fine-grained, repo-scoped token |
| postgres | none | DB host | DB creds | Medium (row data) | Read-only role, row limits |
| shell / exec | arbitrary | arbitrary | env | **High** | Disposable microVM, human approval |
| slack / email | none | API | OAuth | **High** (inbound messages) | Read-only scopes; confirm sends |

## Per-server review checklist
- [ ] Capabilities and permissions documented
- [ ] Network and filesystem access understood
- [ ] Credential requirements minimal and scoped
- [ ] Tool descriptions reviewed for hidden instructions
- [ ] Version pinned, provenance verified
- [ ] Sandbox plan defined
