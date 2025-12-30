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
"""Reset GitHub token in Firestore.

This script deletes or resets the GitHub OAuth token stored in Firestore.
It is intended for local testing and manual token management.

Usage:
    python scripts/reset_github_token.py [--collection COLLECTION] [--doc-id DOC_ID]

Environment Variables:
    GCP_PROJECT_ID: Google Cloud Project ID (required)
    GITHUB_TOKENS_COLLECTION: Firestore collection name (default: github_tokens)
    GITHUB_TOKENS_DOC_ID: Document ID to reset (default: primary_user)

Exit Codes:
    0: Success (token deleted or already non-existent)
    1: Error (configuration or Firestore error)
"""

import sys
import os
import argparse
import asyncio
from typing import Optional

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from google.cloud import firestore
from google.api_core import exceptions as gcp_exceptions


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Reset GitHub OAuth token in Firestore",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Delete token using default collection/doc_id
    python scripts/reset_github_token.py

    # Delete token from custom location
    python scripts/reset_github_token.py --collection my_tokens --doc-id user123

    # Check if token exists without deleting
    python scripts/reset_github_token.py --dry-run

Environment Variables:
    GCP_PROJECT_ID: Required. Your GCP project ID.
    GITHUB_TOKENS_COLLECTION: Optional. Collection name (default: github_tokens)
    GITHUB_TOKENS_DOC_ID: Optional. Document ID (default: primary_user)
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
        help="Document ID to reset (default: primary_user)"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check if token exists without deleting it"
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress non-error output"
    )
    
    return parser.parse_args()


async def check_token_exists(
    client: firestore.AsyncClient,
    collection: str,
    doc_id: str
) -> bool:
    """Check if a token document exists.
    
    Args:
        client: Firestore async client
        collection: Collection name
        doc_id: Document ID
        
    Returns:
        True if document exists, False otherwise
    """
    doc_ref = client.collection(collection).document(doc_id)
    doc = await doc_ref.get()
    return doc.exists


async def delete_token(
    client: firestore.AsyncClient,
    collection: str,
    doc_id: str
) -> None:
    """Delete a token document from Firestore.
    
    Args:
        client: Firestore async client
        collection: Collection name
        doc_id: Document ID
        
    Raises:
        Exception: If deletion fails
    """
    doc_ref = client.collection(collection).document(doc_id)
    await doc_ref.delete()


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
        print("Set it with: export GCP_PROJECT_ID=your-project-id", file=sys.stderr)
        return 1
    
    try:
        # Initialize Firestore client using an async context manager
        async with firestore.AsyncClient(project=project_id) as client:
            if not args.quiet:
                print(f"Connecting to Firestore project: {project_id}")
                print(f"Collection: {args.collection}")
                print(f"Document ID: {args.doc_id}")
                print()
            
            # Check if token exists
            exists = await check_token_exists(client, args.collection, args.doc_id)
            
            if not exists:
                if not args.quiet:
                    print(f"✓ Token document does not exist (already deleted or never created)")
                    print(f"  Path: {args.collection}/{args.doc_id}")
                return 0
            
            if not args.quiet:
                print(f"✓ Token document found")
                print(f"  Path: {args.collection}/{args.doc_id}")
            
            if args.dry_run:
                if not args.quiet:
                    print()
                    print("Dry-run mode: Document would be deleted")
                return 0
            
            # Delete the token
            await delete_token(client, args.collection, args.doc_id)
            
            if not args.quiet:
                print()
                print(f"✓ Token document deleted successfully")
                print(f"  Path: {args.collection}/{args.doc_id}")
            
            return 0
        
    except gcp_exceptions.PermissionDenied as e:
        print(f"ERROR: Permission denied accessing Firestore", file=sys.stderr)
        print(f"Ensure your service account has the proper IAM roles:", file=sys.stderr)
        print(f"  - roles/datastore.user (or roles/datastore.owner)", file=sys.stderr)
        print(f"Details: {str(e)}", file=sys.stderr)
        return 1
        
    except gcp_exceptions.GoogleAPICallError as e:
        print(f"ERROR: Firestore API error: {str(e)}", file=sys.stderr)
        return 1
        
    except Exception as e:
        print(f"ERROR: Unexpected error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
