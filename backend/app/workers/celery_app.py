"""Celery application.

Broker/result backend are Redis. When ``MPF_CELERY_EAGER=true`` (or Redis is
absent in a dev/test context) tasks run synchronously in-process so the whole
stack works without a worker.
"""
from __future__ import annotations

from celery import Celery

from app.core.config import settings

celery = Celery(
    "mpf",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_eager_propagates=True,
    task_always_eager=settings.celery_eager,
    worker_max_tasks_per_child=20,      # recycle workers (tools can leak)
    broker_connection_retry_on_startup=True,
)
