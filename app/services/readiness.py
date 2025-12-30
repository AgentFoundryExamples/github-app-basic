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
"""Readiness state management for health checks.

This module manages the application's readiness state, tracking whether
critical dependencies like Firestore and GitHub App configuration are
properly initialized.
"""

from threading import Lock
from typing import Dict, Optional
from datetime import datetime, timezone

from app.utils.logging import get_logger

logger = get_logger(__name__)


class ReadinessState:
    """Manages application readiness state.
    
    Tracks initialization status of critical dependencies and provides
    thread-safe access to readiness information.
    """
    
    def __init__(self):
        """Initialize readiness state."""
        self._lock = Lock()
        self._ready = False
        self._initialized_at: Optional[datetime] = None
        self._components: Dict[str, bool] = {
            "firestore": False,
            "github_config": False,
        }
    
    def mark_component_ready(self, component: str) -> None:
        """Mark a component as ready.
        
        Args:
            component: Name of the component to mark ready.
        """
        with self._lock:
            if component in self._components:
                was_ready = self._components[component]
                self._components[component] = True
                
                if not was_ready:
                    logger.info(
                        f"Component marked as ready: {component}",
                        extra={"extra_fields": {"component": component}}
                    )
                
                # Check if all components are ready
                if all(self._components.values()) and not self._ready:
                    self._ready = True
                    self._initialized_at = datetime.now(timezone.utc)
                    logger.info(
                        "Application is ready - all components initialized",
                        extra={"extra_fields": {
                            "components": list(self._components.keys()),
                            "initialized_at": self._initialized_at.isoformat()
                        }}
                    )
    
    def mark_component_not_ready(self, component: str) -> None:
        """Mark a component as not ready.
        
        Args:
            component: Name of the component to mark not ready.
        """
        with self._lock:
            if component in self._components:
                was_ready = self._components[component]
                self._components[component] = False
                
                if was_ready:
                    logger.warning(
                        f"Component marked as not ready: {component}",
                        extra={"extra_fields": {"component": component}}
                    )
                
                # If any component is not ready, app is not ready
                if self._ready:
                    self._ready = False
                    logger.warning(
                        "Application is no longer ready",
                        extra={"extra_fields": {"failed_component": component}}
                    )
    
    def is_ready(self) -> bool:
        """Check if application is ready.
        
        Returns:
            True if all components are ready, False otherwise.
        """
        with self._lock:
            return self._ready
    
    def get_status(self) -> Dict[str, any]:
        """Get detailed readiness status.
        
        Returns:
            Dictionary with readiness status and component details.
        """
        with self._lock:
            return {
                "ready": self._ready,
                "initialized_at": self._initialized_at.isoformat() if self._initialized_at else None,
                "components": self._components.copy()
            }


# Global readiness state instance
_readiness_state: Optional[ReadinessState] = None
_state_lock = Lock()


def get_readiness_state() -> ReadinessState:
    """Get or create the global readiness state instance.
    
    Returns:
        ReadinessState instance.
    """
    global _readiness_state
    
    with _state_lock:
        if _readiness_state is None:
            _readiness_state = ReadinessState()
        return _readiness_state


def reset_readiness_state() -> None:
    """Reset the global readiness state instance.
    
    Primarily used for testing purposes.
    """
    global _readiness_state
    
    with _state_lock:
        _readiness_state = None
