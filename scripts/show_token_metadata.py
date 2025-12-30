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
"""Show GitHub token metadata from Firestore.

This script displays non-sensitive metadata about the stored GitHub OAuth token
without exposing the actual token value. Useful for operators to verify token
configuration and status.

Usage:
    python scripts/show_token_metadata.py [--collection COLLECTION] [--doc-id DOC_ID]

Environment Variables:
    GCP_PROJECT_ID: Google Cloud Project ID (required)
    GITHUB_TOKENS_COLLECTION: Firestore collection name (default: github_tokens)
    GITHUB_TOKENS_DOC_ID: Document ID (default: primary_user)

Exit Codes:
    0: Success (metadata displayed)
    1: Error (configuration, permissions, or document not found)
"""

import sys
import os
import argparse
import asyncio
from typing import Optional
import json

# Add parent directory to path to import app modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from google.cloud import firestore
from google.api_core import exceptions as gcp_exceptions


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Display GitHub OAuth token metadata from Firestore",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Show token metadata using default collection/doc_id
    python scripts/show_token_metadata.py

    # Show token metadata from custom location
    python scripts/show_token_metadata.py --collection my_tokens --doc-id user123

    # Output as JSON
    python scripts/show_token_metadata.py --json

Environment Variables:
    GCP_PROJECT_ID: Required. Your GCP project ID.
    GITHUB_TOKENS_COLLECTION: Optional. Collection name (default: github_tokens)
    GITHUB_TOKENS_DOC_ID: Optional. Document ID (default: primary_user)
    GOOGLE_APPLICATION_CREDENTIALS: Optional. Path to service account key.
        """
    )
    
    parser.add_argument(
        "--collection",
        default=os.getenv("GITHUB_TOKENS_COLLECTION", "github_tokens"),
        help="Firestore collection name (default: github_tokens)"
    )
    
    parser.add_argument(
        "--doc-id",
        default=os.getenv("GITHUB_TOKENS_DOC_ID", "primary_user"),
        help="Document ID (default: primary_user)"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output metadata as JSON"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-metadata output"
    )
    
    return parser.parse_args()


async def get_token_metadata(
    client: firestore.AsyncClient,
    collection: str,
    doc_id: str
) -> Optional[dict]:
    """Get token metadata from Firestore.
    
    Args:
        client: Firestore async client
        collection: Collection name
        doc_id: Document ID
        
    Returns:
        Dictionary containing metadata, or None if not found
    """
    doc_ref = client.collection(collection).document(doc_id)
    doc = await doc_ref.get()
    
    if not doc.exists:
        return None
    
    data = doc.to_dict()
    
    # Return only metadata fields, never expose encrypted tokens
    metadata = {
        "token_type": data.get("token_type"),
        "scope": data.get("scope"),
        "expires_at": data.get("expires_at"),
        "has_refresh_token": data.get("refresh_token") is not None,
        "updated_at": data.get("updated_at")
    }
    
    return metadata


def format_metadata_human(metadata: dict) -> str:
    """Format metadata for human-readable output.
    
    Args:
        metadata: Metadata dictionary
        
    Returns:
        Formatted string
    """
    lines = [
        "GitHub Token Metadata",
        "=" * 50,
        f"Token Type:       {metadata.get('token_type', 'unknown')}",
        f"Scope:            {metadata.get('scope', 'none')}",
        f"Expires At:       {metadata.get('expires_at', 'never')}",
        f"Has Refresh:      {metadata.get('has_refresh_token', False)}",
        f"Updated At:       {metadata.get('updated_at', 'unknown')}",
        "=" * 50
    ]
    return "\n".join(lines)


async def main() -> int:
    """Main script entry point.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    args = parse_args()
    
    # Validate GCP_PROJECT_ID
    project_id = os.getenv("GCP_PROJECT_ID")
    if not project_id:
        print("ERROR: GCP_PROJECT_ID environment variable is required", file=sys.stderr)
        print("\nSet it with: export GCP_PROJECT_ID=your-project-id", file=sys.stderr)
        print("\nFor authentication, ensure one of the following:", file=sys.stderr)
        print("  - GOOGLE_APPLICATION_CREDENTIALS points to a service account key", file=sys.stderr)
        print("  - You have run 'gcloud auth application-default login'", file=sys.stderr)
        return 1
    
    try:
        # Initialize Firestore client using an async context manager
        async with firestore.AsyncClient(project=project_id) as client:
            if not args.quiet and not args.json:
                print(f"Connecting to Firestore project: {project_id}")
                print(f"Collection: {args.collection}")
                print(f"Document ID: {args.doc_id}")
                print()
            
            # Get token metadata
            metadata = await get_token_metadata(client, args.collection, args.doc_id)
            
            if metadata is None:
                print(f"ERROR: Token document not found", file=sys.stderr)
                print(f"  Path: {args.collection}/{args.doc_id}", file=sys.stderr)
                print(f"\nThe token document does not exist in Firestore.", file=sys.stderr)
                print(f"Run the OAuth flow to create a token first.", file=sys.stderr)
                return 1
            
            # Output metadata
            if args.json:
                print(json.dumps(metadata, indent=2))
            else:
                print(format_metadata_human(metadata))
            
            return 0
        
    except gcp_exceptions.PermissionDenied as e:
        print(f"ERROR: Permission denied accessing Firestore", file=sys.stderr)
        print(f"\nEnsure your credentials have the proper IAM roles:", file=sys.stderr)
        print(f"  - roles/datastore.user (or roles/datastore.owner)", file=sys.stderr)
        print(f"\nAuthentication options:", file=sys.stderr)
        print(f"  1. Use a service account key:", file=sys.stderr)
        print(f"     export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json", file=sys.stderr)
        print(f"  2. Use Application Default Credentials (ADC):", file=sys.stderr)
        print(f"     gcloud auth application-default login", file=sys.stderr)
        print(f"\nDetails: {str(e)}", file=sys.stderr)
        return 1
        
    except gcp_exceptions.GoogleAPICallError as e:
        print(f"ERROR: Firestore API error: {str(e)}", file=sys.stderr)
        return 1
        
    except Exception as e:
        print(f"ERROR: Unexpected error: {str(e)}", file=sys.stderr)
        
        # Check for common authentication issues
        if "could not find default credentials" in str(e).lower():
            print(f"\nAuthentication not configured. Try:", file=sys.stderr)
            print(f"  gcloud auth application-default login", file=sys.stderr)
            print(f"OR", file=sys.stderr)
            print(f"  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json", file=sys.stderr)
        else:
            import traceback
            traceback.print_exc(file=sys.stderr)
        
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
