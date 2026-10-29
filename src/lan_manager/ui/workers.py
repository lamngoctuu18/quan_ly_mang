"""Background QRunnable workers for non-blocking network, database, and remediation tasks."""

from __future__ import annotations

import threading
import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    """Signals emitted by background QRunnable tasks to update the UI safely on the main thread."""

    started_task = Signal(str)
    progress = Signal(int, int, str)
    result = Signal(object)
    error = Signal(str, str)
    finished_task = Signal()


class ServiceWorker(QRunnable):
    """
    Generic QRunnable wrapper that executes a service callable on QThreadPool.
    Supports optional cancel_event and progress callback injection.
    """

    def __init__(
        self,
        task_name: str,
        fn: Callable[..., Any],
        *args: Any,
        supports_cancel: bool = False,
        supports_progress: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.setAutoDelete(True)
        self.task_name = task_name
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._supports_cancel = supports_cancel
        self._supports_progress = supports_progress
        self.cancel_event = threading.Event()
        self.signals = WorkerSignals()

    def request_cancel(self) -> None:
        """Signal cooperative cancellation to the running task."""
        self.cancel_event.set()

    def _on_progress(self, current: int, total: int, host_info: Any = None) -> None:
        detail = ""
        if host_info is not None and getattr(host_info, "ip_address", None):
            state_txt = "Phản hồi" if getattr(host_info, "is_alive", False) else "Không phản hồi"
            detail = f"{host_info.ip_address} ({state_txt})"
        self.signals.progress.emit(current, total, detail)

    @Slot()
    def run(self) -> None:
        self.signals.started_task.emit(self.task_name)
        try:
            call_kwargs = dict(self._kwargs)
            if self._supports_cancel:
                call_kwargs["cancel_event"] = self.cancel_event
            if self._supports_progress:
                call_kwargs["progress_callback"] = self._on_progress

            output = self._fn(*self._args, **call_kwargs)
            self.signals.result.emit(output)
        except Exception as exc:
            err_code = getattr(exc, "error_code", exc.__class__.__name__)
            tb_summary = traceback.format_exc(limit=3)
            self.signals.error.emit(str(exc), f"{err_code}\n{tb_summary}")
        finally:
            self.signals.finished_task.emit()
