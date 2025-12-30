"""Structured logging configuration for the service.

Provides JSON-formatted logging with support for request tracing.
"""

import logging
import sys
from typing import Any, Dict, Optional
from pythonjsonlogger import jsonlogger


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
        
        # Add request_id if present in record
        if hasattr(record, "request_id"):
            log_record["request_id"] = record.request_id
        
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


class RequestIdFilter(logging.Filter):
    """Logging filter that adds request_id to log records."""
    
    def __init__(self, request_id: Optional[str] = None):
        """Initialize the filter with an optional request_id.
        
        Args:
            request_id: The request ID to add to all log records.
        """
        super().__init__()
        self.request_id = request_id
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id to the record if available.
        
        Args:
            record: The log record to modify.
            
        Returns:
            Always True to allow the record through.
        """
        if self.request_id:
            record.request_id = self.request_id
        return True


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name.
    
    Args:
        name: The name of the logger (typically __name__).
        
    Returns:
        A configured logger instance.
    """
    return logging.getLogger(name)
