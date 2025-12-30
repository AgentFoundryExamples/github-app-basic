#!/usr/bin/env python3
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
    except (ConnectionError, OSError, http.client.HTTPException) as e:
        # ConnectionError: Cannot connect to service
        # OSError: Network-related errors (including connection refused)
        # HTTPException: HTTP protocol errors
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
