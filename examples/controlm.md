# Using explainfail with Control-M

The most reliable way is to wrap the command a job runs. `explainfail run` executes your command
exactly as before, explains the failure if there is one, and **returns the original exit code**, so
Control-M still marks the job as failed and your normal alerting and workflows are unchanged.

## 1. Install on the agent host

```bash
pip install explainfail          # or use a virtualenv, e.g. /opt/explainfail/bin/pip
```

## 2. Change the job's command

Before:

```
python /opt/etl/nightly.py
```

After:

```
/opt/explainfail/bin/explainfail run --job %%JOBNAME -- python /opt/etl/nightly.py
```

`%%JOBNAME` is a Control-M variable that is filled in at run time, so the report names the job.
The text report appears in the job's output (sysout), right where the operator already looks.

## 3. Optional: send it to chat or email

Set the destination in the agent's environment (or in the job's environment variables), not on the
command line:

```bash
EXPLAINFAIL_SLACK_WEBHOOK=https://hooks.slack.com/services/...
# or EXPLAINFAIL_TEAMS_WEBHOOK, or EXPLAINFAIL_EMAIL_TO + EXPLAINFAIL_SMTP_HOST
```

## 4. Optional: add your own rules

Keep your site-specific rules in a folder and point to it once:

```bash
EXPLAINFAIL_RULES=/etc/explainfail/rules
```

## If you cannot change the command

Use a job's failure action to run a command that analyses the saved output file:

```
/opt/explainfail/bin/explainfail analyze /path/to/job_output.log --job %%JOBNAME
```

The exact place to configure a failure action, and where output files are stored, depends on your
Control-M version and setup. Check with your Control-M administrator.

## Note

This has been checked at the command-line level (wrapping a command, preserving its exit code,
reading a saved log). It has not been tested against a live Control-M installation.
