"""Celery app for Fortik's queue adapter tests (real producer and worker).

Environment: FORTIK_CELERY_BROKER (redis URL), FORTIK_CELERY_OUT (file each
executed task appends "<agent> <n>" to).
"""
import os

from celery import Celery

app = Celery("fortik_tasks", broker=os.environ["FORTIK_CELERY_BROKER"])
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
)


@app.task(name="fortik_test.record")
def record(agent, n):
    with open(os.environ["FORTIK_CELERY_OUT"], "a", encoding="utf-8") as f:
        f.write(f"{agent} {n}\n")
