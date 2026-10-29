# explainfail

**Plain-English explanations for failed jobs, scripts and pipelines.**
Works with any scheduler (Control-M, Airflow, cron, Jenkins, Task Scheduler). Rules first, AI optional.

When a job fails, the person on call gets a wall of log text and an exit code. If they are not a
strong debugger, finding the real cause is slow and guesswork leads to blind reruns. `explainfail`
reads the log and tells them what failed, why, how to fix it and who to tell.

```
$ explainfail analyze nightly_etl.log --job nightly_etl

JOB: nightly_etl   STATUS: FAILED   EXIT CODE: 1

MOST LIKELY CAUSE: Python package is not installed   [severity: medium]
  What happened:
    The script tried to import the Python module "pandas", but it is not installed in the Python
    environment that ran the job.
  How to fix:
    Install it into the same environment the job runs in (for example: pip install pandas) ...
  Who to tell: job owner / developer
  Evidence: ModuleNotFoundError: No module named 'pandas'
```

## Why this exists

- **No AI setup needed.** 60+ built-in rules explain the common failures (missing module, permission
  denied, out of memory, connection refused, expired credentials, disk full, bad credentials,
  timeouts, and more) completely offline.
- **AI is optional.** Turn it on for unusual errors, with Anthropic, OpenAI, any OpenAI-compatible
  endpoint, or a **local model through Ollama** so logs never leave your machine.
- **Secrets are removed first.** Passwords, tokens, keys, URL credentials and emails are redacted
  before a report is printed, posted to chat, or sent to a model.
- **Rules are just YAML.** Add one for your own systems without writing code.
- **Tiny.** One dependency (PyYAML). Everything else is the Python standard library.

## Install

```bash
pip install explainfail
```

Needs Python 3.9 or newer. Or use Docker (see below).

## Use it

**Explain a log file**

```bash
explainfail analyze job.log
cat job.log | explainfail analyze -              # from stdin
explainfail analyze job.log --exit-code 137      # if you know it
explainfail analyze job.log --format markdown    # or json
```

**Wrap a command** (the simplest way to plug into any scheduler). It runs your command as normal,
and if it fails it explains why. The original exit code is preserved, so your scheduler still sees
the failure.

```bash
explainfail run --job nightly_etl -- python etl.py
```

**Send the explanation somewhere**

```bash
export EXPLAINFAIL_SLACK_WEBHOOK=https://hooks.slack.com/services/...
explainfail run --job nightly_etl -- python etl.py
```

Supported: Slack (`--slack`), Microsoft Teams (`--teams`), a generic JSON webhook (`--webhook`),
email over SMTP (`--email-to`), or a file (`--out`). Prefer the environment variables so
secrets do not end up in process lists.

## Plug into your scheduler

| Scheduler | How |
|---|---|
| Control-M | Wrap the job command: `explainfail run --job %%JOBNAME -- <your command>` ([details](examples/controlm.md)) |
| Airflow | `on_failure_callback` ([example](examples/airflow_callback.py)) or wrap the command |
| cron | `explainfail run --job backup -- /opt/backup.sh` ([example](examples/cron.txt)) |
| Jenkins, GitLab, GitHub Actions | Pipe the failed step's log into `explainfail analyze -` |
| Anything else | Run the HTTP service and POST the log to it (below) |

> The wrapper approach only needs a command line, so it works anywhere. The examples above have been
> exercised at the command-line level; they have not been tested against a live Control-M or Airflow
> installation. If you try one and it needs a tweak, please open an issue.

## Turn on AI (optional)

AI only adds a plain-English explanation on top of the rule-based result. If the AI call fails, you
still get the rule-based answer.

```bash
# Anthropic
export ANTHROPIC_API_KEY=...
explainfail analyze job.log --ai anthropic

# OpenAI
export OPENAI_API_KEY=...
explainfail analyze job.log --ai openai --model gpt-4o-mini

# Local model, nothing leaves your machine
explainfail analyze job.log --ai ollama --model llama3.1

# Any OpenAI-compatible server (vLLM, LM Studio, Azure, Groq, ...)
explainfail analyze job.log --ai openai-compatible --base-url https://my-host/v1 --model my-model
```

You can also set `EXPLAINFAIL_PROVIDER`, `EXPLAINFAIL_MODEL`, `EXPLAINFAIL_BASE_URL` and
`EXPLAINFAIL_API_KEY`. `--ai litellm` is available after `pip install "explainfail[litellm]"`.

### What is sent to an AI model

Only the redacted evidence: the job name, exit code, matched rule findings, the traceback, error
lines and the last 40 or so lines of the log. Not the whole log. Nothing is sent unless you pass
`--ai`. Use `--redact-ips` to hide IPv4 addresses too. Redaction is pattern-based and cannot
catch everything, so review what your logs contain before sending them to a third party, or use a
local model.

## Add your own rules

```yaml
# my_rules.yaml
rules:
  - id: acme-partner-sftp-down
    title: Partner SFTP server (ACME) is unreachable
    category: network
    severity: high
    match: 'sftp\.acme-partner\.com.*(?:timed out|refused)'
    notify: Integration team
    explain: The nightly file exchange could not connect to ACME's SFTP server.
    fix: Check the ACME status page, then run sftp -v sftp.acme-partner.com from the job server.
    examples:
      - "ssh: connect to host sftp.acme-partner.com port 22: Connection timed out"
```

```bash
explainfail analyze job.log --rules my_rules.yaml
explainfail rules check my_rules.yaml        # validates the file and its examples
explainfail rules list                       # shows every rule
export EXPLAINFAIL_RULES=/etc/explainfail/rules   # a folder of *.yaml also works
```

Your rules always rank above built-in ones. Reuse a built-in `id` to replace it.

## HTTP service

```bash
export EXPLAINFAIL_TOKEN=choose-a-long-random-string
explainfail serve --host 0.0.0.0 --port 8080

curl -X POST localhost:8080/analyze \
  -H "Authorization: Bearer $EXPLAINFAIL_TOKEN" \
  -d '{"log": "...", "job": "nightly_etl", "exit_code": 1}'
```

It binds to `127.0.0.1` by default and refuses to listen on a public address without a token. It is
meant for use on a trusted network behind your own TLS proxy.

## Docker

```bash
docker build -t explainfail .
docker run --rm -i explainfail analyze - < job.log
```

## Python API

```python
from explainfail import analyze
from explainfail.outputs import render

report = analyze(open("job.log").read(), job="nightly_etl", exit_code=1)
print(report.summary)
print(render(report, "markdown"))
```

## Limits

- Rules explain *known* failures. For a new one you get a generic explanation, pointers on where to
  look, and (if enabled) an AI explanation. Adding a rule makes it known for everyone.
- It explains a failure. It does not monitor, alert, store logs, or fix anything automatically.
- AI explanations can be wrong. Treat them as a starting point.

## Contributing

New rules are the easiest and most valuable contribution. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
