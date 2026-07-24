"""GUI tarafındaki servis istemcisi (arka planda iş parçacığı ile)."""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable

from gi.repository import GLib

from ..ipc import IpcClient


class DaemonClient:
    """Servis çağrılarını arayüzü kilitlemeden yapar."""

    def __init__(self) -> None:
        self._client = IpcClient()
        self._queue: "queue.Queue[tuple[str, dict, Callable | None]]" = queue.Queue()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self) -> None:
        while True:
            cmd, kwargs, callback = self._queue.get()
            try:
                response = self._client.call(cmd, **kwargs)
            except Exception as exc:  # pragma: no cover
                response = {"ok": False, "error": str(exc)}
            if callback is not None:
                GLib.idle_add(callback, response)

    def call(self, cmd: str, callback: Callable[[dict], Any] | None = None,
             **kwargs: Any) -> None:
        self._queue.put((cmd, kwargs, callback))

    def call_sync(self, cmd: str, **kwargs: Any) -> dict:
        return self._client.call(cmd, **kwargs)

    @property
    def socket_exists(self) -> bool:
        return self._client.available()
