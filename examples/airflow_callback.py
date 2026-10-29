"""Explain Airflow task failures in plain English.

Add ``on_failure_callback=explain_failure`` to a DAG's ``default_args`` (or to a single task).
The explanation is written to the task log, and to Slack if EXPLAINFAIL_SLACK_WEBHOOK is set.

    pip install explainfail          # on the Airflow workers

This is a starting point; it has not been tested against a live Airflow deployment.
"""

import os
import traceback

from explainfail import analyze
from explainfail.outputs import render, send_slack


def explain_failure(context):
    exc = context.get("exception")
    if exc is None:
        return
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    job = f"{context['dag'].dag_id}.{context['task'].task_id}"

    report = analyze(text, job=job)
    print(render(report, "text"))

    webhook = os.environ.get("EXPLAINFAIL_SLACK_WEBHOOK")
    if webhook:
        try:
            send_slack(webhook, report)
        except Exception as err:  # never let reporting break the failure handling
            print(f"explainfail: could not post to Slack: {err}")


# Example wiring:
#
#   with DAG("nightly_etl", default_args={"on_failure_callback": explain_failure}, ...):
#       ...
#
# For BashOperator tasks you can instead wrap the command:
#
#   BashOperator(task_id="load", bash_command="explainfail run --job load -- python load.py")
