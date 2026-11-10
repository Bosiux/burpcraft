# Security policy

BurpCraft installs a CA in your browser's trust store and holds captured traffic, credentials and API keys, so
we treat vulnerabilities in the tool itself as high priority.

## Supported versions

Only the latest release gets security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting:
[Security → Report a vulnerability](https://github.com/Bosiux/burpcraft/security/advisories/new).

Include the version, OS, steps to reproduce and the impact you see. You can expect a first answer within 7 days;
a fix and a coordinated advisory follow once the issue is confirmed. Credit is given unless you ask otherwise.

## In scope

- Anything that lets a target server, a web page, another local user or process, a BApp, a plugin or a project
  file compromise the machine running BurpCraft or read its data (CA key, history, credentials, API keys)
- Bypasses of Target scope enforcement during scans
- Unauthenticated access to the REST API or MCP server beyond what the docs describe

## Out of scope

- Findings BurpCraft reports (or misses) on the applications you test: open a normal issue for false
  positives/negatives
- Attacks that require an already-compromised user account on the same machine
- Using BurpCraft against systems you are not authorised to test
