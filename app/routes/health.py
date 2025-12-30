"""Health check endpoint for the service."""

from fastapi import APIRouter
from typing import Dict
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/healthz")
async def health_check() -> Dict[str, str]:
    """Health check endpoint.
    
    Returns:
        A dictionary with status "ok".
    """
    logger.info("Health check endpoint called")
    return {"status": "ok"}
