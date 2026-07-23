"""Aggregate v1 router."""
from fastapi import APIRouter

from app.api.v1 import analysis, components, files, intel, security

api_router = APIRouter()
api_router.include_router(analysis.router)
api_router.include_router(files.router)
api_router.include_router(components.router)
api_router.include_router(intel.router)
api_router.include_router(security.router)
