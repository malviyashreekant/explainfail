# Contributing to explainfail

Thanks for helping. The most useful contribution is a **new rule**, and you do not need to write
any Python to add one.

## Add a rule (5 minutes)

1. Find a real failure you have seen and copy one or two log lines that identify it.
2. Open `src/explainfail/rules/builtin.yaml` and add an entry:

   ```yaml
   - id: sftp-host-key-changed          # unique, lowercase, dashes
     title: SFTP host key has changed
     category: network                  # python | system | network | database | cloud | auth | java | container | windows
     severity: high                     # low | medium | high | critical
     priority: 70                       # specific ~70, generic ~40, exit-code only ~20
     match: 'REMOTE HOST IDENTIFICATION HAS CHANGED'
     notify: job owner / network team
     explain: >-
       The server's identity no longer matches what this machine remembers. This can be a harmless
       server rebuild, or a sign someone is intercepting the connection.
     fix: >-
       Confirm with the server owner that it was rebuilt, then remove the old entry with
       ssh-keygen -R <host> and reconnect.
     examples:
       - "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"
   ```

3. Run the tests: every rule's `examples` must match its own pattern, and the suite also checks that
   no rule is slow on huge logs.

   ```bash
   pip install -e ".[dev]"
   pytest
   ```

### Rule guidelines

- **Write for someone who is not a debugger.** Short sentences, no unexplained jargon.
- **Say what to do next**, not only what happened. Prefer concrete commands.
- **Use named groups** to show the user their own values: `(?P<module>[^']+)` lets `explain` and
  `fix` say `{module}`.
- **Be specific.** A rule that matches too much explains the wrong thing, which is worse than no rule.
  Give it a higher `priority` if it is more specific than a generic neighbour.
- **Keep patterns fast.** Avoid nested quantifiers such as `(a+)+`. Patterns run per line.
- **No secrets or real company names** in examples. Use made-up hosts and users.

Matching is case-sensitive unless the pattern starts with `(?i)`.

## Code changes

```bash
git clone https://github.com/malviyashreekant/explainfail
cd explainfail
pip install -e ".[dev]"
pytest          # tests
ruff check .    # lint
```

- Keep the core dependency list to PyYAML. Optional features go behind extras.
- Add tests for behaviour changes. Bug fixes should come with a test that fails without the fix.
- Anything that sends data off the machine must be opt-in and go through redaction first.

## Reporting problems

- **A wrong or missing explanation:** open an issue with the (redacted) log lines. This often turns
  into a new rule.
- **A security issue:** see [SECURITY.md](SECURITY.md). Do not open a public issue.

By contributing you agree your contribution is licensed under the Apache License 2.0.
