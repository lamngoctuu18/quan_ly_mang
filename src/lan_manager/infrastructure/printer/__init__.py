"""Windows Print Spooler and print queue adapter using pywin32."""

from lan_manager.infrastructure.printer.windows_printer_adapter import (
    PrintJobDetail,
    PrintQueueStatus,
    SpoolerStatus,
    WindowsPrinterAdapter,
)

__all__ = [
    "PrintJobDetail",
    "PrintQueueStatus",
    "SpoolerStatus",
    "WindowsPrinterAdapter",
]
