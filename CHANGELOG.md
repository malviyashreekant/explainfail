# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

First public release.

### Added
- Rule engine with 60+ built-in rules (Python, system, network, database, cloud, auth, Java,
  container, Windows), written in YAML and validated by the test suite.
- Custom rules via `--rules` or `EXPLAINFAIL_RULES`; `explainfail rules list|check`.
- Log parsing: exit codes, last Python traceback, error lines, log tail.
- Secret redaction (keys, tokens, JWTs, URL credentials, private keys, emails; optional IPv4).
- Optional AI explanations: Anthropic, OpenAI, Ollama, any OpenAI-compatible endpoint, LiteLLM.
- Delivery to Slack, Microsoft Teams, a JSON webhook, SMTP email, or a file.
- CLI: `analyze`, `run` (wraps a command and keeps its exit code), `serve` (HTTP), `rules`.
- Docker image, GitHub Actions CI and release workflows, scheduler examples.
