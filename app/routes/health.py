# Copyright 2025 John Brosnihan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
