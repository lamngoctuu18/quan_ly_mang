"""Script populating comprehensive enterprise demo data for LAN Printer Manager.
Covers 10 diverse real-world network, printer, diagnostic, task, RBAC, and audit scenarios.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure 'src' directory is in Python path
_SRC_DIR = str(Path(__file__).resolve().parents[1] / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from lan_manager.core.config import get_config
from lan_manager.core.logging_config import get_logger, setup_logging
from lan_manager.domain.enums.system_enums import (
    AuditResult,
    DeviceStatusEnum,
    DeviceType,
    DiagnosticCheckType,
    DiagnosticSeverity,
    RiskLevel,
    RoleType,
    TaskStatus,
    TaskType,
)
from lan_manager.infrastructure.database.base import Base
from lan_manager.infrastructure.database.connection import get_db_manager
from lan_manager.infrastructure.database.repositories import (
    AuditRepository,
    DeviceRepository,
    DiagnosticRepository,
    PrinterRepository,
    TaskRepository,
    UserRepository,
)


def seed_demo_data() -> int:
    config = get_config()
    setup_logging(config)
    logger = get_logger("scripts.seed_demo_data")

    db_manager = get_db_manager(config)
    ok, msg = db_manager.check_connection()
    if not ok:
        logger.error("Không thể kết nối cơ sở dữ liệu: %s", msg)
        return 1

    engine = db_manager.get_engine()
    Base.metadata.create_all(bind=engine)
    logger.info("Đang nạp bộ dữ liệu mẫu đa kịch bản vào PostgreSQL...")

    now = datetime.now(UTC)

    with db_manager.session_scope() as session:
        user_repo = UserRepository(session)
        dev_repo = DeviceRepository(session)
        prn_repo = PrinterRepository(session)
        diag_repo = DiagnosticRepository(session)
        task_repo = TaskRepository(session)
        audit_repo = AuditRepository(session)

        user_repo.ensure_default_roles()

        # =====================================================================
        # 1. TẠO 4 TÀI KHOẢN NGƯỜI DÙNG PHÂN QUYỀN RBAC ĐỂ DEMO
        # =====================================================================
        accounts = [
            ("viewer_demo", "Viewer@2026!", RoleType.VIEWER, "Nguyễn Văn Xem (Chỉ xem)"),
            ("tech_demo", "Tech@2026!", RoleType.TECHNICIAN, "Trần Kỹ Thuật (Chẩn đoán & Quét)"),
            ("operator_demo", "Operator@2026!", RoleType.OPERATOR, "Lê Vận Hành (Thực thi sửa lỗi)"),
            ("admin", "Admin@2026!LanManager", RoleType.ADMIN, "Quản Trị Viên Hệ Thống"),
        ]
        created_users = {}
        for username, password, role_type, full_name in accounts:
            existing = user_repo.get_by_username(username)
            if existing is None:
                created_users[username] = user_repo.create_user(
                    username=username,
                    plain_password=password,
                    role_type=role_type,
                    full_name=full_name,
                )
            else:
                created_users[username] = existing

        admin_user = created_users["admin"]
        operator_user = created_users["operator_demo"]
        tech_user = created_users["tech_demo"]

        # =====================================================================
        # 2. KHỞI TẠO 10 THIẾT BỊ MẠNG & MÁY IN ĐẠI DIỆN 10 TRƯỜNG HỢP DEMO
        # =====================================================================
        devices_data = [
            # Kịch bản 1: Máy in HP hoạt động hoàn hảo (ONLINE)
            {
                "ip": "192.168.1.50",
                "mac": "00:1B:78:11:22:33",
                "hostname": "PRN-HP-M404-T1",
                "type": DeviceType.PRINTER,
                "vendor": "HP Inc.",
                "model": "HP LaserJet Pro M404dn",
                "location": "Phòng Kế Toán - Tầng 1",
                "status": DeviceStatusEnum.ONLINE,
                "latency": 3,
                "open_ports": [9100, 631, 80, 443],
                "protocols": ["RAW_9100", "IPP_631", "HTTP_80", "HTTPS_443"],
                "snmp_ok": True,
                "snmp_status": "idle",
                "serial": "VNB3K19821",
                "firmware": "20240915",
                "page_count": 14250,
                "console": "Ready",
                "alerts": [],
                "diag_sev": DiagnosticSeverity.NORMAL,
                "diag_cause": "Thiết bị hoạt động bình thường, không phát hiện sự cố.",
            },
            # Kịch bản 2: Máy in Canon mất kết nối / Rút cáp / Tắt nguồn (OFFLINE)
            {
                "ip": "192.168.1.51",
                "mac": "00:00:85:AA:BB:CC",
                "hostname": "PRN-CANON-LBP2900",
                "type": DeviceType.PRINTER,
                "vendor": "Canon Inc.",
                "model": "Canon imageCLASS LBP2900",
                "location": "Kho Hàng - Cổng B",
                "status": DeviceStatusEnum.OFFLINE,
                "latency": None,
                "open_ports": [],
                "protocols": [],
                "snmp_ok": False,
                "snmp_status": None,
                "serial": "CN-992182",
                "firmware": "1.02",
                "page_count": 8900,
                "console": None,
                "alerts": [],
                "diag_sev": DiagnosticSeverity.ERROR,
                "diag_cause": "Thiết bị không phản hồi mạng (Mất nguồn, tuột cáp mạng LAN hoặc đổi IP DHCP).",
            },
            # Kịch bản 3: Máy in Brother lỗi phần cứng: KẸT GIẤY & SẮP HẾT MỰC (ERROR / SNMP Alert)
            {
                "ip": "192.168.1.52",
                "mac": "00:80:77:44:55:66",
                "hostname": "PRN-BROTHER-MFC",
                "type": DeviceType.PRINTER,
                "vendor": "Brother Industries",
                "model": "Brother MFC-L2701DW",
                "location": "Phòng Kinh Doanh - Tầng 2",
                "status": DeviceStatusEnum.ERROR,
                "latency": 5,
                "open_ports": [9100, 631, 80],
                "protocols": ["RAW_9100", "IPP_631", "HTTP_80"],
                "snmp_ok": True,
                "snmp_status": "other",
                "serial": "E78921J9N123",
                "firmware": "H1.05",
                "page_count": 31200,
                "console": "Jam Rear / Toner Low",
                "alerts": ["jammed (Kẹt giấy cụm sấy)", "lowToner (Sắp hết mực)"],
                "diag_sev": DiagnosticSeverity.ERROR,
                "diag_cause": "Phát hiện sự cố vật lý trực tiếp từ SNMP: jammed (Kẹt giấy cụm sấy); lowToner (Sắp hết mực).",
            },
            # Kịch bản 4: Máy in Ricoh HẾT GIẤY KHAY 1 & NẮP MÁY ĐANG MỞ (WARNING / SNMP Alert)
            {
                "ip": "192.168.1.53",
                "mac": "00:26:73:77:88:99",
                "hostname": "PRN-RICOH-AFICIO",
                "type": DeviceType.PRINTER,
                "vendor": "Ricoh Company",
                "model": "Ricoh Aficio MP 301SPF",
                "location": "Sảnh Lễ Tân",
                "status": DeviceStatusEnum.WARNING,
                "latency": 4,
                "open_ports": [9100, 515, 80],
                "protocols": ["RAW_9100", "LPD_515", "HTTP_80"],
                "snmp_ok": True,
                "snmp_status": "other",
                "serial": "RCH-8812739",
                "firmware": "3.10",
                "page_count": 52310,
                "console": "Tray 1 Empty / Cover Open",
                "alerts": ["noPaper (Hết giấy khay 1)", "doorOpen (Nắp máy đang mở)"],
                "diag_sev": DiagnosticSeverity.WARNING,
                "diag_cause": "Cảnh báo từ máy in qua SNMP: noPaper (Hết giấy khay 1); doorOpen (Nắp máy đang mở).",
            },
            # Kịch bản 5: Máy in Epson bị TẮC NGHẼN HÀNG ĐỢI IN (Print Queue Stuck - 4 lệnh in lỗi)
            {
                "ip": "192.168.1.54",
                "mac": "00:00:48:33:22:11",
                "hostname": "PRN-EPSON-L805",
                "type": DeviceType.PRINTER,
                "vendor": "Seiko Epson",
                "model": "Epson EcoTank L805",
                "location": "Phòng Thiết Kế Marketing",
                "status": DeviceStatusEnum.ERROR,
                "latency": 6,
                "open_ports": [9100, 631],
                "protocols": ["RAW_9100", "IPP_631"],
                "snmp_ok": True,
                "snmp_status": "printing",
                "serial": "EPS-556677",
                "firmware": "2.14",
                "page_count": 18900,
                "console": "Busy",
                "alerts": [],
                "diag_sev": DiagnosticSeverity.ERROR,
                "diag_cause": "Có 4 lệnh in bị lỗi/kẹt đang chặn hàng đợi in 'Epson EcoTank L805'.",
                "queue_stuck": 4,
            },
            # Kịch bản 6: Máy in Xerox bị TREO DỊCH VỤ WINDOWS PRINT SPOOLER (Spooler Stopped)
            {
                "ip": "192.168.1.55",
                "mac": "00:00:AA:12:45:78",
                "hostname": "PRN-XEROX-B210",
                "type": DeviceType.PRINTER,
                "vendor": "Fuji Xerox",
                "model": "Xerox B210",
                "location": "Phòng Giám Đốc",
                "status": DeviceStatusEnum.ERROR,
                "latency": 3,
                "open_ports": [9100, 631, 80],
                "protocols": ["RAW_9100", "IPP_631", "HTTP_80"],
                "snmp_ok": True,
                "snmp_status": "idle",
                "serial": "XRX-001298",
                "firmware": "1.00.45",
                "page_count": 7800,
                "console": "Ready",
                "alerts": [],
                "diag_sev": DiagnosticSeverity.ERROR,
                "diag_cause": "Dịch vụ Windows Print Spooler trên máy quản lý đang bị dừng (STOPPED).",
                "spooler_stopped": True,
            },
            # Kịch bản 7: Máy in Kyocera BỊ TREO CỔNG IN 9100, nhưng mở Web Admin 80/443
            {
                "ip": "192.168.1.56",
                "mac": "00:17:C8:99:88:77",
                "hostname": "PRN-KYOCERA-ECOSYS",
                "type": DeviceType.PRINTER,
                "vendor": "Kyocera Document Solutions",
                "model": "Kyocera ECOSYS M2040dn",
                "location": "Phòng Hành Chính",
                "status": DeviceStatusEnum.ERROR,
                "latency": 4,
                "open_ports": [80, 443],  # Cổng 9100/631/515 đóng
                "protocols": ["HTTP_80", "HTTPS_443"],
                "snmp_ok": False,
                "snmp_status": None,
                "serial": "KYO-441199",
                "firmware": "2.05",
                "page_count": 25100,
                "console": None,
                "alerts": [],
                "diag_sev": DiagnosticSeverity.ERROR,
                "diag_cause": "Thiết bị phản hồi mạng nhưng tất cả cổng in chuẩn (9100, 631, 515) đều đóng. Cần mở Web Admin để kiểm tra card mạng in.",
            },
            # Kịch bản 8: Máy chủ in tập trung Windows Server (PRINT_SERVER)
            {
                "ip": "192.168.1.100",
                "mac": "00:14:22:FE:DC:BA",
                "hostname": "SRV-PRINT-01",
                "type": DeviceType.PRINT_SERVER,
                "vendor": "Dell Inc.",
                "model": "PowerEdge R440 (Print Server)",
                "location": "Phòng Server Datacenter",
                "status": DeviceStatusEnum.ONLINE,
                "latency": 1,
                "open_ports": [445, 135, 9100, 515],
                "protocols": ["SMB_445", "RPC_135", "RAW_9100", "LPD_515"],
                "snmp_ok": True,
                "snmp_status": "Ready",
                "serial": "SRV-DELL-9988",
                "firmware": "Windows Server 2022",
                "page_count": None,
                "console": None,
                "alerts": [],
                "diag_sev": DiagnosticSeverity.NORMAL,
                "diag_cause": "Máy chủ chia sẻ in hoạt động ổn định.",
            },
            # Kịch bản 9: Máy tính trạm Windows của nhân viên (WORKSTATION)
            {
                "ip": "192.168.1.110",
                "mac": "F8:B1:56:55:66:77",
                "hostname": "PC-KT-TRANGNT",
                "type": DeviceType.WORKSTATION,
                "vendor": "Dell Inc.",
                "model": "OptiPlex 7090",
                "location": "Phòng Kế Toán",
                "status": DeviceStatusEnum.ONLINE,
                "latency": 2,
                "open_ports": [445, 135],
                "protocols": ["SMB_445", "RPC_135"],
                "snmp_ok": False,
                "snmp_status": None,
                "serial": None,
                "firmware": "Windows 11 Pro",
                "page_count": None,
                "console": None,
                "alerts": [],
                "diag_sev": DiagnosticSeverity.NORMAL,
                "diag_cause": "Máy trạm Windows phản hồi bình thường.",
            },
            # Kịch bản 10: Thiết bị mở cổng 9100 nhưng SNMP tắt & không có OUI (UNKNOWN)
            {
                "ip": "192.168.1.200",
                "mac": None,
                "hostname": "DEVICE-UNKNOWN-200",
                "type": DeviceType.UNKNOWN,
                "vendor": None,
                "model": None,
                "location": "Chưa xác định",
                "status": DeviceStatusEnum.WARNING,
                "latency": 8,
                "open_ports": [9100],
                "protocols": ["RAW_9100"],
                "snmp_ok": False,
                "snmp_status": None,
                "serial": None,
                "firmware": None,
                "page_count": None,
                "console": None,
                "alerts": [],
                "diag_sev": DiagnosticSeverity.WARNING,
                "diag_cause": "Mở cổng 9100 nhưng chưa xác minh được qua SNMP hoặc OUI hãng. Hệ thống không khẳng định là máy in.",
            },
        ]

        # Nạp dữ liệu Devices, Printers, Status History, Diagnostics & Tasks
        for item in devices_data:
            dev, _ = dev_repo.upsert_scanned_device(
                ip_address=item["ip"],
                status=item["status"],
                device_type=item["type"],
                hostname=item["hostname"],
                mac_address=item["mac"],
                manufacturer=item["vendor"],
                model=item["model"],
                location=item["location"],
            )

            # Tạo lịch sử trạng thái (History)
            for i in range(3):
                hist_time = now - timedelta(hours=(3 - i) * 6)
                dev_repo.record_status_history(
                    device_id=dev.id,
                    status=item["status"],
                    latency_ms=item["latency"],
                    open_ports=item["open_ports"],
                    snmp_reachable=item["snmp_ok"],
                    status_detail=f"Kiểm tra định kỳ lúc {hist_time.strftime('%H:%M:%S')}",
                )

            # Nếu là PRINTER hoặc PRINT_SERVER, nạp bảng 'printers'
            if item["type"] in (DeviceType.PRINTER, DeviceType.PRINT_SERVER):
                prn_metadata = {
                    "open_ports": item["open_ports"],
                    "latency_ms": item["latency"],
                    "snmp_sys_descr": f"{item['vendor']} {item['model'] or ''}",
                    "snmp_printer_status": item["snmp_status"],
                    "snmp_alerts": item["alerts"],
                    "snmp_page_count": item["page_count"],
                    "snmp_console_display": item["console"],
                    "snmp_raw_oids": {
                        "1.3.6.1.2.1.1.1.0": f"{item['vendor']} {item['model']}",
                        "1.3.6.1.2.1.43.10.2.1.4.1.1": item["page_count"] or 0,
                    },
                }
                prn_repo.upsert_printer(
                    device_id=dev.id,
                    printer_name=item["model"] or item["hostname"],
                    serial_number=item["serial"],
                    firmware_version=item["firmware"],
                    supported_protocols=item["protocols"],
                    snmp_enabled=item["snmp_ok"],
                    metadata=prn_metadata,
                )

            # Nạp kết quả chẩn đoán mẫu (Diagnostic Result)
            diag_steps_evidence = [
                {
                    "step_number": 1,
                    "step_code": "CONNECTIVITY",
                    "title": "Kiểm tra kết nối IP & Mạng LAN",
                    "severity": (
                        DiagnosticSeverity.ERROR.value
                        if item["status"] == DeviceStatusEnum.OFFLINE
                        else DiagnosticSeverity.NORMAL.value
                    ),
                    "summary": (
                        "Không phản hồi ICMP và cổng TCP"
                        if item["status"] == DeviceStatusEnum.OFFLINE
                        else f"Phản hồi bình thường ({item['latency']} ms)"
                    ),
                    "evidence": {"open_ports": item["open_ports"], "latency_ms": item["latency"]},
                },
                {
                    "step_number": 2,
                    "step_code": "PRINT_PORTS",
                    "title": "Kiểm tra cổng dịch vụ in (9100 / 631 / 515)",
                    "severity": (
                        DiagnosticSeverity.ERROR.value
                        if (item["type"] == DeviceType.PRINTER and not any(p in item["open_ports"] for p in (9100, 631, 515)))
                        else DiagnosticSeverity.NORMAL.value
                    ),
                    "summary": (
                        "Đóng tất cả cổng in 9100/631/515"
                        if (item["type"] == DeviceType.PRINTER and not any(p in item["open_ports"] for p in (9100, 631, 515)))
                        else f"Cổng in sẵn sàng: {[p for p in item['open_ports'] if p in (9100, 631, 515)]}"
                    ),
                    "evidence": {"open_print_ports": [p for p in item["open_ports"] if p in (9100, 631, 515)]},
                },
                {
                    "step_number": 3,
                    "step_code": "SNMP_STATUS",
                    "title": "Kiểm tra thông tin & cảnh báo SNMP",
                    "severity": (
                        DiagnosticSeverity.ERROR.value
                        if any("jammed" in a or "noPaper" in a for a in item["alerts"])
                        else (DiagnosticSeverity.NORMAL.value if item["snmp_ok"] else DiagnosticSeverity.UNKNOWN.value)
                    ),
                    "summary": (
                        f"Phát hiện cảnh báo phần cứng: {'; '.join(item['alerts'])}"
                        if item["alerts"]
                        else ("SNMP hoạt động tốt" if item["snmp_ok"] else "SNMP không phản hồi")
                    ),
                    "evidence": {"alerts": item["alerts"], "status": item["snmp_status"]},
                },
                {
                    "step_number": 4,
                    "step_code": "WINDOWS_SPOOLER",
                    "title": "Kiểm tra dịch vụ Windows Print Spooler",
                    "severity": (
                        DiagnosticSeverity.ERROR.value
                        if item.get("spooler_stopped")
                        else DiagnosticSeverity.NORMAL.value
                    ),
                    "summary": (
                        "Dịch vụ Print Spooler bị dừng (STOPPED)"
                        if item.get("spooler_stopped")
                        else "Dịch vụ Print Spooler đang chạy (RUNNING)"
                    ),
                    "evidence": {"is_running": not item.get("spooler_stopped")},
                },
                {
                    "step_number": 5,
                    "step_code": "PRINT_QUEUE",
                    "title": "Kiểm tra hàng đợi lệnh in (Print Queue)",
                    "severity": (
                        DiagnosticSeverity.ERROR.value
                        if item.get("queue_stuck", 0) > 0
                        else DiagnosticSeverity.NORMAL.value
                    ),
                    "summary": (
                        f"Phát hiện {item.get('queue_stuck')} lệnh in bị lỗi/kẹt"
                        if item.get("queue_stuck", 0) > 0
                        else "Hàng đợi in thông thoáng (0 lệnh lỗi)"
                    ),
                    "evidence": {"stuck_jobs": item.get("queue_stuck", 0)},
                },
            ]

            diag_repo.create(
                device_id=dev.id,
                check_type=DiagnosticCheckType.FULL_DIAGNOSTIC,
                severity=item["diag_sev"],
                probable_cause=item["diag_cause"],
                diagnostic_data={"steps": diag_steps_evidence},
                performed_by=tech_user.id,
            )

            # Nạp một số tác vụ quản trị mẫu (Remote Tasks)
            if item["ip"] == "192.168.1.55":  # Xerox Print Spooler
                t1 = task_repo.create_task(
                    target_device_id=dev.id,
                    task_type=TaskType.RESTART_PRINT_SPOOLER,
                    risk_level=RiskLevel.MEDIUM,
                    requested_by=operator_user.id,
                    requested_by_username=operator_user.username,
                )
                task_repo.complete_task(
                    task_id=t1.id,
                    status=TaskStatus.SUCCEEDED,
                    result_summary="Đã khởi động lại dịch vụ Print Spooler. Hậu kiểm: Spooler status == RUNNING.",
                )
            elif item["ip"] == "192.168.1.54":  # Epson Clear Stuck Jobs
                t2 = task_repo.create_task(
                    target_device_id=dev.id,
                    task_type=TaskType.CLEAR_STUCK_PRINT_JOBS,
                    risk_level=RiskLevel.HIGH,
                    requested_by=operator_user.id,
                    requested_by_username=operator_user.username,
                    parameters={"queue_name": "Epson EcoTank L805"},
                )
                task_repo.complete_task(
                    task_id=t2.id,
                    status=TaskStatus.SUCCEEDED,
                    result_summary="Đã hủy 4 lệnh in kẹt. Hậu kiểm: Hàng đợi sạch (0 lệnh kẹt).",
                )
            elif item["ip"] == "192.168.1.51":  # Offline check
                t3 = task_repo.create_task(
                    target_device_id=dev.id,
                    task_type=TaskType.RECHECK_CONNECTIVITY,
                    risk_level=RiskLevel.LOW,
                    requested_by=tech_user.id,
                    requested_by_username=tech_user.username,
                )
                task_repo.complete_task(
                    task_id=t3.id,
                    status=TaskStatus.FAILED,
                    result_summary="Thiết bị không phản hồi ICMP và cổng in.",
                    error_message="Host unreachable / Timed out.",
                )

        # =====================================================================
        # 3. NẠP NHẬT KÝ KIỂM TOÁN MẪU (AUDIT LOGS)
        # =====================================================================
        audit_events = [
            ("SCAN_LAN_SUBNET", "SUBNET", "192.168.1.0/24", AuditResult.SUCCESS, tech_user.username, tech_user.id, {"hosts_probed": 254, "alive": 10, "printers_found": 7}),
            ("USER_LOGIN", "USER", str(admin_user.id), AuditResult.SUCCESS, admin_user.username, admin_user.id, {"role": "ADMIN", "client_ip": "127.0.0.1"}),
            ("RUN_DIAGNOSTIC", "DEVICE", "192.168.1.52", AuditResult.SUCCESS, tech_user.username, tech_user.id, {"severity": "ERROR", "alerts": ["jammed", "lowToner"]}),
            ("EXECUTE_REMEDIATION_TASK", "DEVICE", "192.168.1.55", AuditResult.SUCCESS, operator_user.username, operator_user.id, {"task_type": "RESTART_PRINT_SPOOLER", "risk": "MEDIUM"}),
            ("EXECUTE_REMEDIATION_TASK", "DEVICE", "192.168.1.54", AuditResult.DENIED, "viewer_demo", None, {"task_type": "CLEAR_STUCK_PRINT_JOBS", "reason": "Role VIEWER not allowed"}),
            ("UPDATE_CONFIG", "SYSTEM", "allowed_scan_subnets", AuditResult.SUCCESS, admin_user.username, admin_user.id, {"subnets": ["192.168.1.0/24", "10.0.0.0/24"]}),
        ]
        for action, target_type, target_id, res, user_name, user_id, meta in audit_events:
            audit_repo.append(
                action=action,
                target_type=target_type,
                target_id=target_id,
                result=res,
                username=user_name,
                user_id=user_id,
                metadata=meta,
            )

    logger.info("Đã nạp thành công 10 thiết bị mẫu, 4 tài khoản RBAC, lịch sử chẩn đoán và audit logs!")
    return 0


if __name__ == "__main__":
    raise SystemExit(seed_demo_data())

