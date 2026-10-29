# Security policy

## Reporting a vulnerability

Please report security issues privately using GitHub's **"Report a vulnerability"** button on the
repository's Security tab (private vulnerability reporting). Do not open a public issue.

Include what you found, how to reproduce it, and the version (`explainfail --version`). You should
get a first reply within a few days.

## What matters most here

explainfail reads logs, which often contain secrets. The areas we treat as security-sensitive:

- **Redaction gaps:** a credential format that is not hidden before output, chat delivery or AI use.
- **The HTTP service** (`explainfail serve`): authentication, request handling, binding.
- **Outbound delivery:** webhooks, SMTP and AI calls sending more than intended.
- **Rule files:** loading of untrusted YAML (rules are loaded with `yaml.safe_load`).

## Known limits

- Redaction is pattern-based. It catches common credential shapes, but cannot recognise every
  secret. Do not rely on it as the only protection when sending logs to a third-party AI service.
  Use a local model (for example Ollama) for logs that must not leave your network.
- `explainfail serve` has no TLS. Run it on a trusted network or behind your own TLS proxy, and use a
  token (`EXPLAINFAIL_TOKEN`).

## Supported versions

Security fixes go into the latest release.
