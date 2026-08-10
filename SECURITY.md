# Security policy

## Supported versions

AegisScan is currently pre-1.0. Security fixes are applied to the latest code on
the default branch. Older snapshots and locally modified builds are not supported.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
**Security → Report a vulnerability** flow to submit a private security advisory.
Include a concise reproduction, affected files or versions, impact, and any
suggested mitigation. Remove API keys, GitHub tokens, repository source, and other
secrets from screenshots and logs.

If private vulnerability reporting has not yet been enabled for the repository,
the maintainer should enable it under **Settings → Security → Private vulnerability
reporting** before announcing the project publicly.

## Scope

Reports about credential handling, repository-boundary escapes, unsafe automatic
patching, misleading clean-scan states, prompt-injection resistance, or unintended
source disclosure are especially valuable.

AegisScan is a security-assistance tool, not a guarantee that scanned software is
free of vulnerabilities. Findings and generated mitigations still require human
review before deployment.
