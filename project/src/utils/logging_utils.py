from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    """Configure process-wide logging once."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if root_logger.handlers:
        for handler in root_logger.handlers:
            handler.setFormatter(formatter)
            handler.setLevel(root_logger.level)
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.setLevel(root_logger.level)
    root_logger.addHandler(handler)
