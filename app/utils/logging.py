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
"""Structured logging configuration for the service.

Provides JSON-formatted logging with support for request tracing.
"""

import logging
import sys
from contextvars import ContextVar
from typing import Any, Dict, Optional
from pythonjsonlogger import jsonlogger


# Context variable to store request ID for the current request
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)

# Context variable to store correlation ID for OAuth/transaction flows
correlation_id_var: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter that adds standard fields to all log records.
    
    Emits JSON-formatted logs compatible with GCP Logging and other cloud platforms.
    Standard fields include timestamp, level, logger, message, request_id, and correlation_id.
    Additional structured fields can be provided via the 'extra_fields' attribute.
    """
    
    def add_fields(
        self, 
        log_record: Dict[str, Any], 
        record: logging.LogRecord, 
        message_dict: Dict[str, Any]
    ) -> None:
        """Add custom fields to the log record.
        
        Args:
            log_record: The dictionary that will be logged.
            record: The original LogRecord.
            message_dict: Additional message fields.
        """
        super().add_fields(log_record, record, message_dict)
        
        # Add standard fields
        log_record["timestamp"] = self.formatTime(record, self.datefmt)
        log_record["level"] = record.levelname
        log_record["logger"] = record.name
        log_record["message"] = record.getMessage()
        
        # Add request_id from context variable if available
        request_id = request_id_var.get()
        if request_id:
            log_record["request_id"] = request_id
        
        # Add correlation_id from context variable if available
        correlation_id = correlation_id_var.get()
        if correlation_id:
            log_record["correlation_id"] = correlation_id
        
        # Add any extra fields (structured event data)
        if hasattr(record, "extra_fields"):
            log_record.update(record.extra_fields)


def setup_logging(log_level: str = "INFO") -> None:
    """Configure logging with JSON formatter.
    
    Args:
        log_level: The logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    # Create formatter
    formatter = CustomJsonFormatter(
        fmt="%(timestamp)s %(level)s %(logger)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add console handler with JSON formatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name.
    
    Args:
        name: The name of the logger (typically __name__).
        
    Returns:
        A configured logger instance.
    """
    return logging.getLogger(name)


def mask_sensitive_data(value: str, visible_chars: int = 4) -> str:
    """Mask sensitive data for safe logging.
    
    DEPRECATED: Use app.utils.security.redact_token() instead.
    This function is kept for backward compatibility.
    
    Shows only the first N characters and masks the rest with asterisks.
    
    Args:
        value: The sensitive string to mask.
        visible_chars: Number of characters to show at the beginning.
        
    Returns:
        Masked string in format "abcd****" (for visible_chars=4).
        
    Examples:
        >>> mask_sensitive_data("secret_token_12345", 4)
        "secr****************"
        >>> mask_sensitive_data("abc", 4)
        "abc"
        >>> mask_sensitive_data("", 4)
        "****"
    """
    # Import here to avoid circular dependency
    from app.utils.security import redact_token
    return redact_token(value, prefix_len=visible_chars, suffix_len=0, mask_char="*")


def log_structured_event(
    logger: logging.Logger,
    level: str,
    event: str,
    message: str,
    **kwargs
) -> None:
    """Log a structured event with consistent schema.
    
    Emits a structured log entry with standard fields for GCP Logging compatibility.
    
    Args:
        logger: Logger instance to use
        level: Log level (info, warning, error, etc.)
        event: Event type identifier (e.g., "token_refresh_attempt", "oauth_callback")
        message: Human-readable message
        **kwargs: Additional structured fields (e.g., outcome, duration, installation_id)
        
    Example:
        log_structured_event(
            logger, "info", "token_refresh_success",
            "Token refreshed successfully",
            outcome="success",
            duration_ms=150,
            installation_id="12345"
        )
    """
    extra_fields = {"event": event}
    extra_fields.update(kwargs)
    
    log_func = getattr(logger, level.lower(), logger.info)
    log_func(message, extra={"extra_fields": extra_fields})
