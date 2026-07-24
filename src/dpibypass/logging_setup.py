"""Günlükleme kurulumu ve GUI'ye aktarılan halka tampon."""

from __future__ import annotations

import collections
import logging
import logging.handlers
import os
import sys
import time
from typing import Deque

from .constants import LOG_FILE

_RING: Deque[dict] = collections.deque(maxlen=1000)


class RingHandler(logging.Handler):
    """Son N günlük satırını bellekte tutar; GUI bunları okur."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            _RING.append(
                {
                    "ts": record.created,
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": self.format(record),
                }
            )
        except Exception:  # pragma: no cover - günlükleme asla çökmemeli
            pass


def ring_entries(since: float = 0.0, limit: int = 400) -> list[dict]:
    items = [e for e in _RING if e["ts"] > since]
    return items[-limit:]


def setup(verbose: bool = False, to_file: bool = True) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    fmt = logging.Formatter("%(message)s")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                                          datefmt="%H:%M:%S"))
    root.addHandler(stream)

    ring = RingHandler()
    ring.setFormatter(fmt)
    root.addHandler(ring)

    if to_file:
        try:
            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                LOG_FILE, maxBytes=1_000_000, backupCount=2
            )
            fh.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
            )
            root.addHandler(fh)
        except OSError:
            pass

    logging.getLogger("asyncio").setLevel(logging.WARNING)


def now() -> float:
    return time.time()
