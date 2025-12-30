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
"""Metrics collection for observability.

Provides Prometheus-compatible metrics for monitoring token refresh operations,
GitHub installation events, and HTTP request patterns.
"""

from typing import Dict, Optional
from collections import defaultdict
import threading
import re


import re


# Prometheus label validation pattern (alphanumeric and underscore only)
_LABEL_KEY_PATTERN = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')


def _validate_label_key(key: str) -> bool:
    """Validate that a label key is a valid Prometheus identifier.
    
    Prometheus label keys must match [a-zA-Z_][a-zA-Z0-9_]*
    
    Args:
        key: Label key to validate
        
    Returns:
        True if valid, False otherwise
    """
    return _LABEL_KEY_PATTERN.match(key) is not None


def _sanitize_label_value(value: str, max_length: int = 256) -> str:
    """Sanitize a label value to prevent injection attacks and limit cardinality.
    
    - Truncates to max_length characters
    - Replaces newlines and control characters with spaces
    - Escapes backslashes and quotes for Prometheus format
    
    Args:
        value: Label value to sanitize
        max_length: Maximum length for the value
        
    Returns:
        Sanitized label value
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Truncate to prevent excessive cardinality
    value = value[:max_length]
    
    # Replace control characters and newlines with spaces
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', value)
    
    # Escape backslashes and quotes for Prometheus format
    value = value.replace('\\', '\\\\').replace('"', '\\"')
    
    return value


class MetricsCollector:
    """Lightweight in-memory metrics collector.
    
    Provides Prometheus-compatible counters for key application events.
    Thread-safe implementation using locks for concurrent access.
    """
    
    def __init__(self):
        """Initialize metrics collector with counters."""
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = defaultdict(int)
        
    def increment(self, metric_name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter metric.
        
        Args:
            metric_name: Name of the metric to increment
            value: Amount to increment by (default: 1)
            labels: Optional dictionary of labels for the metric
            
        Raises:
            ValueError: If label keys are invalid Prometheus identifiers
        """
        # Validate and sanitize labels
        if labels:
            validated_labels = {}
            for key, val in labels.items():
                # Validate label key
                if not _validate_label_key(key):
                    raise ValueError(
                        f"Invalid Prometheus label key '{key}'. "
                        "Label keys must match [a-zA-Z_][a-zA-Z0-9_]*"
                    )
                # Sanitize label value
                validated_labels[key] = _sanitize_label_value(val)
            
            # Build metric key with validated labels
            label_str = ",".join(f'{k}="{v}"' for k, v in sorted(validated_labels.items()))
            key = f"{metric_name}{{{label_str}}}"
        else:
            key = metric_name
            
        with self._lock:
            self._counters[key] += value
    
    def get_counter(self, metric_name: str, labels: Optional[Dict[str, str]] = None) -> int:
        """Get current value of a counter metric.
        
        Args:
            metric_name: Name of the metric
            labels: Optional dictionary of labels for the metric
            
        Returns:
            Current counter value
        """
        # Validate and sanitize labels (same as increment)
        if labels:
            validated_labels = {}
            for key, val in labels.items():
                if not _validate_label_key(key):
                    raise ValueError(
                        f"Invalid Prometheus label key '{key}'. "
                        "Label keys must match [a-zA-Z_][a-zA-Z0-9_]*"
                    )
                validated_labels[key] = _sanitize_label_value(val)
            
            label_str = ",".join(f'{k}="{v}"' for k, v in sorted(validated_labels.items()))
            key = f"{metric_name}{{{label_str}}}"
        else:
            key = metric_name
            
        with self._lock:
            return self._counters.get(key, 0)
    
    def reset(self) -> None:
        """Reset all counters to zero. Primarily for testing."""
        with self._lock:
            self._counters.clear()
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus text format.
        
        Returns:
            Prometheus-formatted metrics string
        """
        lines = []
        
        with self._lock:
            # Group metrics by base name
            metric_groups: Dict[str, list] = defaultdict(list)
            for key, value in self._counters.items():
                # Extract base metric name
                if "{" in key:
                    base_name = key.split("{")[0]
                    metric_groups[base_name].append((key, value))
                else:
                    metric_groups[key].append((key, value))
            
            # Format each metric group
            for base_name in sorted(metric_groups.keys()):
                # Add HELP and TYPE comments
                lines.append(f"# HELP {base_name} Counter for {base_name}")
                lines.append(f"# TYPE {base_name} counter")
                
                # Add metric values
                for key, value in sorted(metric_groups[base_name]):
                    lines.append(f"{key} {value}")
                
                lines.append("")  # Empty line between metrics
        
        return "\n".join(lines)


# Global metrics instance (disabled by default, enabled via config)
_metrics_instance: Optional[MetricsCollector] = None
_metrics_enabled = False


def init_metrics(enabled: bool = False) -> None:
    """Initialize the global metrics collector.
    
    Args:
        enabled: Whether to enable metrics collection
    """
    global _metrics_instance, _metrics_enabled
    _metrics_enabled = enabled
    if enabled:
        _metrics_instance = MetricsCollector()
    else:
        _metrics_instance = None


def get_metrics() -> Optional[MetricsCollector]:
    """Get the global metrics collector instance.
    
    Returns:
        MetricsCollector instance if enabled, None otherwise
    """
    return _metrics_instance


def is_metrics_enabled() -> bool:
    """Check if metrics collection is enabled.
    
    Returns:
        True if metrics are enabled, False otherwise
    """
    return _metrics_enabled


def increment_counter(metric_name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
    """Increment a counter metric (no-op if metrics disabled).
    
    Args:
        metric_name: Name of the metric to increment
        value: Amount to increment by (default: 1)
        labels: Optional dictionary of labels for the metric
    """
    if _metrics_instance:
        _metrics_instance.increment(metric_name, value, labels)


# Metric names (constants for consistency)
METRIC_TOKEN_REFRESH_ATTEMPTS = "github_token_refresh_attempts_total"
METRIC_TOKEN_REFRESH_SUCCESSES = "github_token_refresh_successes_total"
METRIC_TOKEN_REFRESH_FAILURES = "github_token_refresh_failures_total"
METRIC_TOKEN_REFRESH_COOLDOWNS = "github_token_refresh_cooldowns_total"
METRIC_OAUTH_FLOWS_STARTED = "github_oauth_flows_started_total"
METRIC_OAUTH_FLOWS_COMPLETED = "github_oauth_flows_completed_total"
METRIC_OAUTH_FLOWS_FAILED = "github_oauth_flows_failed_total"
METRIC_HTTP_REQUESTS_TOTAL = "http_requests_total"
METRIC_HEALTH_CHECK_SUCCESSES = "health_check_successes_total"
METRIC_HEALTH_CHECK_FAILURES = "health_check_failures_total"
METRIC_READINESS_CHECK_SUCCESSES = "readiness_check_successes_total"
METRIC_READINESS_CHECK_FAILURES = "readiness_check_failures_total"
