#!/usr/bin/env python3
"""Simple health check script for Docker container.

This script performs a basic HTTP GET request to the /healthz endpoint.
It's designed to be lightweight and fail fast if the service isn't responding.
"""

import os
import sys
import http.client


def check_health():
    """Check if the service is healthy by calling /healthz endpoint."""
    port = os.environ.get('PORT', '8080')
    
    try:
        # Use http.client for a lightweight health check
        conn = http.client.HTTPConnection('localhost', port, timeout=2)
        conn.request('GET', '/healthz')
        response = conn.getresponse()
        
        # Consider 2xx status codes as healthy
        if 200 <= response.status < 300:
            return 0
        else:
            print(f"Health check failed with status: {response.status}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"Health check failed: {e}", file=sys.stderr)
        return 1
    finally:
        if 'conn' in locals():
            try:
                conn.close()
            except Exception:
                pass


if __name__ == '__main__':
    sys.exit(check_health())
