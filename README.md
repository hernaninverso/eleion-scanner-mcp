# Eleion Scanner — MCP server

Drive the [Eleion](https://eleion.io) security scanner from an AI agent: register one of your own
domains, prove ownership, queue a security scan (headers, TLS, DNS, ports, tech-fingerprint, plus
AI-specific checks), and read the findings — severity, CVE, title, priority. Wraps the hosted Eleion
Scanner API (`https://scanner-api.eleion.io`).

## Tools

| Tool | What it does |
|------|--------------|
| `scanner_register_target(target_url)` | Register one of **your** domains; returns the DNS TXT / well-known record to publish for ownership proof. |
| `scanner_verify_target(target_id)` | Verify the ownership record you published. |
| `scanner_start_scan(target_id, scan_profile?)` | Queue a scan (`basic`/`full`/`deep`) over a verified target. |
| `scanner_get_scan_status(scan_id)` | Poll a scan's status and finding count. |
| `scanner_get_findings(scan_id)` | List the findings (severity, CVE, template, title, priority). |

## Setup

```json
{
  "mcpServers": {
    "eleion-scanner": {
      "command": "npx",
      "args": ["-y", "eleion-scanner-mcp"],
      "env": { "SCANNER_API_KEY": "your_tenant_key" }
    }
  }
}
```

Get a tenant key at <https://scan.eleion.io>. **You can only scan domains you have registered and
verified ownership of** — this is not an arbitrary-target scanner.

The scan worker runs the analysis server-side; large scans take time, so poll `scanner_get_scan_status`
until `completed`. Your registered domains and findings are processed by the hosted API. MIT licensed.
