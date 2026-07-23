"""Celery tasks.

A single task drives one analysis through the pipeline. It opens its own DB
session (workers run outside the request lifecycle), loads the ``Analysis``
row, runs the pipeline, and invalidates any cached responses for that analysis.
"""
from __future__ import annotations

from app.core.cache import cache
from app.core.logging import get_logger
from app.db.session import session_scope
from app.models import Analysis, AnalysisStatus
from app.services.pipeline.runner import Pipeline
from app.workers.celery_app import celery

log = get_logger("worker")


@celery.task(name="mpf.analyze", bind=True, max_retries=0)
def analyze_apk(self, analysis_id: str) -> dict:
    """Run the full pipeline for ``analysis_id``."""
    session = session_scope()
    try:
        analysis = session.get(Analysis, analysis_id)
        if analysis is None:
            log.error("analyze_apk: analysis %s not found", analysis_id)
            return {"analysis_id": analysis_id, "status": "missing"}
        try:
            Pipeline(session, analysis).run()
        finally:
            cache.invalidate_prefix(f"analysis:{analysis_id}")
        return {"analysis_id": analysis_id, "status": analysis.status}
    finally:
        session.close()


def enqueue_analysis(analysis_id: str) -> None:
    """Submit an analysis to the queue (eager or async per configuration)."""
    analyze_apk.delay(analysis_id)
