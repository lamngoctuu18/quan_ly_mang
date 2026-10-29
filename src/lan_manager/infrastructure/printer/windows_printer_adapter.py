"""Integration with Windows Print Spooler and win32print APIs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lan_manager.core.logging_config import get_logger

logger = get_logger(__name__)

try:
    import pywintypes
    import win32print
    import win32service
    import win32serviceutil

    _HAS_PYWIN32 = True
except ImportError:
    _HAS_PYWIN32 = False


# Standard Win32 JOB_STATUS bitflags
JOB_STATUS_PAUSED = 0x00000001
JOB_STATUS_ERROR = 0x00000002
JOB_STATUS_DELETING = 0x00000004
JOB_STATUS_SPOOLING = 0x00000008
JOB_STATUS_PRINTING = 0x00000010
JOB_STATUS_OFFLINE = 0x00000020
JOB_STATUS_PAPEROUT = 0x00000040
JOB_STATUS_PRINTED = 0x00000080
JOB_STATUS_BLOCKED_DEVQ = 0x00000200


@dataclass
class SpoolerStatus:
    """Status of the local Windows Print Spooler ('Spooler') service."""

    supported: bool = True
    is_running: bool = False
    state_name: str = "UNKNOWN"
    detail: str = ""


@dataclass
class PrintJobDetail:
    """Metadata for a single print job in a Windows print queue."""

    job_id: int
    document: str
    user_name: str
    status_code: int
    status_flags: list[str] = field(default_factory=list)
    total_pages: int = 0
    is_stuck_or_error: bool = False


@dataclass
class PrintQueueStatus:
    """Inspection summary for a Windows print queue matching a device or printer."""

    matched_queue_name: str | None = None
    port_name: str | None = None
    driver_name: str | None = None
    total_jobs: int = 0
    stuck_jobs: int = 0
    jobs: list[PrintJobDetail] = field(default_factory=list)
    detail: str = ""


def _decode_job_flags(status_code: int) -> tuple[list[str], bool]:
    flags: list[str] = []
    is_error = False
    if status_code & JOB_STATUS_ERROR:
        flags.append("ERROR")
        is_error = True
    if status_code & JOB_STATUS_OFFLINE:
        flags.append("OFFLINE")
        is_error = True
    if status_code & JOB_STATUS_PAPEROUT:
        flags.append("PAPER_OUT")
        is_error = True
    if status_code & JOB_STATUS_BLOCKED_DEVQ:
        flags.append("BLOCKED")
        is_error = True
    if status_code & JOB_STATUS_PAUSED:
        flags.append("PAUSED")
        is_error = True
    if status_code & JOB_STATUS_PRINTING:
        flags.append("PRINTING")
    if status_code & JOB_STATUS_SPOOLING:
        flags.append("SPOOLING")
    if not flags:
        flags.append("QUEUED")
    return flags, is_error


class WindowsPrinterAdapter:
    """Provides safe read and controlled remediation operations on Windows Print Spooler."""

    def check_spooler_service(self) -> SpoolerStatus:
        """Query the Windows 'Spooler' service state using win32serviceutil."""
        if not _HAS_PYWIN32:
            return SpoolerStatus(
                supported=False,
                is_running=False,
                state_name="UNSUPPORTED",
                detail="Thư viện pywin32 không khả dụng trên môi trường hiện tại.",
            )

        try:
            status_tuple = win32serviceutil.QueryServiceStatus("Spooler")
            current_state = status_tuple[1]
            state_map = {
                win32service.SERVICE_STOPPED: "STOPPED",
                win32service.SERVICE_START_PENDING: "START_PENDING",
                win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
                win32service.SERVICE_RUNNING: "RUNNING",
                win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
                win32service.SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
                win32service.SERVICE_PAUSED: "PAUSED",
            }
            state_name = state_map.get(current_state, f"STATE_{current_state}")
            is_running = current_state == win32service.SERVICE_RUNNING
            detail = (
                "Dịch vụ Print Spooler đang hoạt động bình thường."
                if is_running
                else f"Dịch vụ Print Spooler không ở trạng thái RUNNING ({state_name})."
            )
            return SpoolerStatus(
                supported=True,
                is_running=is_running,
                state_name=state_name,
                detail=detail,
            )
        except Exception as exc:
            return SpoolerStatus(
                supported=True,
                is_running=False,
                state_name="ACCESS_ERROR",
                detail=f"Không thể kiểm tra dịch vụ Spooler: {exc}",
            )

    def inspect_queue_for_device(
        self, ip_address: str, printer_name_hint: str | None = None
    ) -> PrintQueueStatus:
        """
        Find a local/shared Windows print queue associated with ip_address or printer_name_hint
        and inspect its active print jobs.
        """
        if not _HAS_PYWIN32:
            return PrintQueueStatus(
                detail="Không hỗ trợ kiểm tra hàng đợi Windows trên hệ điều hành này."
            )

        try:
            flags = win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS
            printers = win32print.EnumPrinters(flags)
        except Exception as exc:
            return PrintQueueStatus(detail=f"Không thể liệt kê danh sách máy in Windows: {exc}")

        matched_name: str | None = None
        matched_info: dict[str, Any] | None = None

        for prn_tuple in printers:
            p_name = prn_tuple[2]
            try:
                handle = win32print.OpenPrinter(p_name)
                try:
                    info2 = win32print.GetPrinter(handle, 2)
                finally:
                    win32print.ClosePrinter(handle)
            except Exception as exc:
                logger.debug("Bỏ qua hàng đợi '%s' không đọc được chi tiết: %s", p_name, exc)
                continue

            port_name = str(info2.get("pPortName") or "")
            if ip_address and ip_address in port_name:
                matched_name = p_name
                matched_info = info2
                break
            if printer_name_hint and printer_name_hint.lower() in p_name.lower():
                matched_name = p_name
                matched_info = info2
                break

        if not matched_name or matched_info is None:
            return PrintQueueStatus(
                matched_queue_name=None,
                detail=(
                    f"Máy trạm hiện tại chưa cài đặt hàng đợi in (Print Queue) trỏ tới IP {ip_address}."
                ),
            )

        jobs_list: list[PrintJobDetail] = []
        stuck_count = 0
        try:
            handle = win32print.OpenPrinter(matched_name)
            try:
                raw_jobs = win32print.EnumJobs(handle, 0, 100, 1)
            finally:
                win32print.ClosePrinter(handle)

            for rj in raw_jobs:
                status_code = int(rj.get("Status") or 0)
                flag_names, is_err = _decode_job_flags(status_code)
                if is_err:
                    stuck_count += 1
                jobs_list.append(
                    PrintJobDetail(
                        job_id=int(rj.get("JobId") or 0),
                        document=str(rj.get("pDocument") or "Untitled"),
                        user_name=str(rj.get("pUserName") or "unknown"),
                        status_code=status_code,
                        status_flags=flag_names,
                        total_pages=int(rj.get("TotalPages") or 0),
                        is_stuck_or_error=is_err,
                    )
                )
        except Exception as exc:
            return PrintQueueStatus(
                matched_queue_name=matched_name,
                port_name=str(matched_info.get("pPortName") or ""),
                driver_name=str(matched_info.get("pDriverName") or ""),
                detail=f"Đã tìm thấy hàng đợi '{matched_name}' nhưng lỗi khi đọc lệnh in: {exc}",
            )

        summary_msg = (
            f"Hàng đợi '{matched_name}' có {len(jobs_list)} lệnh in ({stuck_count} lệnh lỗi/kẹt)."
            if jobs_list
            else f"Hàng đợi '{matched_name}' thông thoáng (0 lệnh in tồn đọng)."
        )
        return PrintQueueStatus(
            matched_queue_name=matched_name,
            port_name=str(matched_info.get("pPortName") or ""),
            driver_name=str(matched_info.get("pDriverName") or ""),
            total_jobs=len(jobs_list),
            stuck_jobs=stuck_count,
            jobs=jobs_list,
            detail=summary_msg,
        )

    def restart_spooler_service(self) -> tuple[bool, str]:
        """
        Restart the local Windows 'Spooler' service via win32serviceutil.
        Requires OS-level administrative privilege on the host machine.
        """
        if not _HAS_PYWIN32:
            return False, "Môi trường hiện tại không hỗ trợ pywin32 để khởi động lại Spooler."

        try:
            win32serviceutil.RestartService("Spooler")
            status = self.check_spooler_service()
            if status.is_running:
                return True, "Đã khởi động lại dịch vụ Print Spooler thành công."
            return (
                False,
                f"Đã gửi lệnh khởi động lại nhưng trạng thái hiện tại là {status.state_name}.",
            )
        except pywintypes.error as exc:
            if exc.winerror == 5:  # ERROR_ACCESS_DENIED
                return (
                    False,
                    "Từ chối truy cập (WinError 5): Cần quyền Administrator của hệ điều hành để khởi động lại dịch vụ Print Spooler.",
                )
            return False, f"Lỗi Win32 khi khởi động lại Spooler (mã {exc.winerror}): {exc.strerror}"
        except Exception as exc:
            return False, f"Không thể khởi động lại dịch vụ Print Spooler: {exc}"

    def clear_stuck_print_jobs(self, queue_name: str) -> tuple[bool, str, int]:
        """
        Delete only stuck/errored print jobs in the specified Windows print queue.
        Returns (succeeded, message, deleted_count).
        """
        if not _HAS_PYWIN32:
            return False, "Không hỗ trợ thao tác hàng đợi in trên hệ điều hành này.", 0
        if not queue_name or not queue_name.strip():
            return False, "Tên hàng đợi in không được để trống.", 0

        deleted_count = 0
        try:
            defaults = {"DesiredAccess": win32print.PRINTER_ALL_ACCESS}
            try:
                handle = win32print.OpenPrinter(queue_name, defaults)
            except Exception:
                handle = win32print.OpenPrinter(queue_name)

            try:
                raw_jobs = win32print.EnumJobs(handle, 0, 100, 1)
                for rj in raw_jobs:
                    job_id = int(rj.get("JobId") or 0)
                    status_code = int(rj.get("Status") or 0)
                    _, is_err = _decode_job_flags(status_code)
                    if is_err or status_code == 0:
                        win32print.SetJob(handle, job_id, 0, None, win32print.JOB_CONTROL_DELETE)
                        deleted_count += 1
            finally:
                win32print.ClosePrinter(handle)

            return (
                True,
                f"Đã xóa {deleted_count} lệnh in bị kẹt trong hàng đợi '{queue_name}'.",
                deleted_count,
            )
        except Exception as exc:
            return (
                False,
                f"Không thể xóa lệnh in trên hàng đợi '{queue_name}': {exc}",
                deleted_count,
            )
