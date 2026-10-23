"""Enqueue tasks with a genuine Celery producer.

usage: produce.py <agent> <first> <count> [countdown_seconds]
Environment: FORTIK_CELERY_BROKER, FORTIK_CELERY_QUEUE (default "celery").
Prints one task id per line. The agent is attached the way Fortik documents
it: apply_async(headers={"fortik_agent_id": agent}).
"""
import os
import sys

from fortik_tasks import record

agent, first, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
countdown = float(sys.argv[4]) if len(sys.argv) > 4 else None
queue = os.environ.get("FORTIK_CELERY_QUEUE", "celery")
for n in range(first, first + count):
    r = record.apply_async(
        args=[agent, n], headers={"fortik_agent_id": agent}, countdown=countdown, queue=queue
    )
    print(r.id)
