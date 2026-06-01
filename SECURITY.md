# Security Policy

## Supported versions

Only the latest commit on `main` is actively maintained.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: **anupam.platform@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your GitHub handle (for credit in the fix commit)

You will receive a response within 48 hours. If the vulnerability is confirmed,
a patch will be published within 7 days and you will be credited.

## Scope

Sentinel runs user-supplied build tools and LLM-generated code inside an
isolated Docker sandbox. Reports about:

- Sandbox escape (container breakout)
- Secret leakage from the orchestrator environment
- LLM prompt injection leading to unintended actions on GitHub

…are in scope and treated with high priority.
