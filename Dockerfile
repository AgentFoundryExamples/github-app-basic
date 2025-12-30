# Multi-stage build for minimal production image
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Copy installed dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser app/ ./app/
COPY --chown=appuser:appuser healthcheck.py .

# Switch to non-root user
USER appuser

# Add local bin to PATH for gunicorn
ENV PATH=/home/appuser/.local/bin:$PATH

# Set PORT environment variable with default fallback
ENV PORT=8080

# Set the number of workers based on environment variable, defaulting to 2
# Note: Cloud Run may override this based on container resources
ENV GUNICORN_WORKERS=2

# Expose port
EXPOSE 8080

# Health check - uses dedicated script for better reliability
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python healthcheck.py

# Run gunicorn with uvicorn workers
CMD gunicorn app.main:app \
    --workers ${GUNICORN_WORKERS} \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:${PORT} \
    --access-logfile - \
    --error-logfile - \
    --log-level info
