"""List the organization's repositories from the real Proofline API with both clients.

Reads PROOFLINE_TOKEN, PROOFLINE_ORGANIZATION_ID and the proxy variables, and
passes no proxy argument, so whether a request uses the proxy is the SDK's own
choice. Exits 0 only when both clients listed the repositories.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import os
import sys
from uuid import UUID

from proofline import AsyncProoflineClient, ProoflineClient, ProoflineError, RepositoryNames


def show(mode: str, result: RepositoryNames | ProoflineError) -> bool:
    if isinstance(result, ProoflineError):
        print(f"{mode}: failed with {result.type}: {result.detail}")
        return False
    names = sorted(repository.full_name for repository in result.repositories)
    print(f"{mode}: listed {len(names)} repositories: {', '.join(names)}")
    return True


def sync_names(organization_id: UUID) -> RepositoryNames | ProoflineError:
    try:
        with ProoflineClient() as client:
            return client.list_repositories(organization_id)
    except ProoflineError as error:
        return error


async def async_names(organization_id: UUID) -> RepositoryNames | ProoflineError:
    try:
        async with AsyncProoflineClient() as client:
            return await client.list_repositories(organization_id)
    except ProoflineError as error:
        return error


def main() -> int:
    organization_id = UUID(os.environ["PROOFLINE_ORGANIZATION_ID"])
    proxy = "set" if os.environ.get("HTTPS_PROXY") else "not set"
    print(f"proofline-sdk {importlib.metadata.version('proofline-sdk')}, HTTPS_PROXY {proxy}")
    listed = show("sync ", sync_names(organization_id))
    listed = show("async", asyncio.run(async_names(organization_id))) and listed
    return 0 if listed else 1


if __name__ == "__main__":
    sys.exit(main())
