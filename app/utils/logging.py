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


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter that adds standard fields to all log records."""
    
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
        
        # Add any extra fields
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
