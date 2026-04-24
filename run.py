#!/usr/bin/env python3
"""Intune to Drata MDM compliance pipeline -- single entry point.

Usage:
    python run.py [--dry-run]

Runs the full pipeline in sequence:
    1. Extractor  -- fetch all devices and compliance state from Intune via Graph API
    2. Publisher  -- delta-detect and push only changed devices to Drata

Payloads are passed in memory between stages. A debug artifact (drata_payloads.json)
is also written to disk after the extraction stage for inspection.

Exit codes:
    0  -- success (or --dry-run complete)
    1  -- unrecoverable error; check CRITICAL entries in the log output
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import structlog
from dotenv import load_dotenv

from clients.intune_client import IntuneClient
from pipeline import extractor, publisher
from pipeline.extractor import ExtractorError
from pipeline.publisher import PublisherHaltError


def _configure_logging() -> None:
    """Configure structlog for structured JSON output to stdout."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Intune -> Drata MDM compliance pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment variables are loaded from .env if present.\n"
            "See .env.example for the full list of required and optional variables."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Compute deltas and log what would be pushed "
            "without making any Drata API calls."
        ),
    )
    return parser.parse_args()


async def _run(dry_run: bool) -> None:
    log = structlog.get_logger("pipeline")
    log.info("pipeline_start", dry_run=dry_run)

    # Extraction stage -- IntuneClient is an async context manager that holds
    # a single shared httpx.AsyncClient for all concurrent Graph API calls.
    try:
        async with IntuneClient() as intune:
            payloads = await extractor.run(intune)
    except EnvironmentError as exc:
        structlog.get_logger("pipeline").critical(
            "intune_client_init_failed", error=str(exc)
        )
        sys.exit(1)
    except ExtractorError as exc:
        structlog.get_logger("pipeline").critical("extractor_failed", error=str(exc))
        sys.exit(1)

    # Publisher stage -- uses payloads from memory, no disk read required.
    try:
        await publisher.run(payloads, dry_run=dry_run)
    except EnvironmentError as exc:
        structlog.get_logger("pipeline").critical(
            "drata_client_init_failed", error=str(exc)
        )
        sys.exit(1)
    except PublisherHaltError as exc:
        structlog.get_logger("pipeline").critical("publisher_halted", error=str(exc))
        sys.exit(1)

    structlog.get_logger("pipeline").info("pipeline_complete", dry_run=dry_run)


def main() -> None:
    # Load .env before arg parsing so LOG_LEVEL is available for _configure_logging
    load_dotenv()
    args = _parse_args()
    _configure_logging()
    asyncio.run(_run(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
