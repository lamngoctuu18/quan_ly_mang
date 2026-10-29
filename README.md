# LAN Printer Manager — Hệ Thống Quản Trị Tập Trung Máy In IP & Thiết Bị Mạng LAN

**LAN Printer Manager** là ứng dụng Desktop quản trị nội bộ doanh nghiệp được xây dựng bằng **Python 3.12**, **PySide6 (Qt Widgets)** và **PostgreSQL (SQLAlchemy 2.0 + Psycopg 3 + Alembic)** theo kiến trúc phân lớp (**Layered Architecture**).

---

## 1. Tính Năng Cốt Lõi

- **Khám phá mạng LAN có kiểm soát**: Quét dải CIDR nằm trong danh sách cho phép (`ALLOWED_SCAN_SUBNETS`), giới hạn số lượng host và luồng đồng thời, có cơ chế điều tiết tốc độ (rate limiting), hiển thị tiến độ và hủy tác vụ tức thì mà không khóa giao diện.
- **Nhận diện thiết bị dựa trên bằng chứng (Evidence-based Classification)**: Kết hợp ICMP, TCP Port Probe (`9100`, `631`, `515`, `445`, `135`, `80`, `443`), bảng ARP, Reverse DNS và truy vấn SNMP (MIB-II & RFC 3805 Printer-MIB). **Không khẳng định một IP là máy in chỉ vì mở cổng TCP 9100**.
- **Chống trùng thiết bị thông minh (DHCP-aware Deduplication)**: Tự động gom trùng theo `mac_address` trước khi đối chiếu `ip_address` để xử lý trường hợp máy in bị đổi IP do DHCP.
- **Quản lý chuyên sâu Máy in IP (6 Tabs)**: Tổng quan, Kết nối, Thông tin SNMP, Chẩn đoán, Tác vụ và Lịch sử trạng thái.
- **Chẩn đoán sự cố 5 bước (Read-Only)**: Kiểm tra kết nối IP, cổng dịch vụ in, cảnh báo phần cứng qua SNMP (hết giấy, hết mực, kẹt giấy, mở nắp), dịch vụ Windows Print Spooler và lệnh in kẹt trong hàng đợi (`win32print`).
- **Tác vụ sửa lỗi có kiểm soát (`TaskRegistry` Allowlist)**: Tách biệt hoàn toàn với bước chẩn đoán; kiểm tra quyền RBAC ở tầng nghiệp vụ, hộp thoại xác nhận rủi ro, thực thi có timeout và **tự động hậu kiểm (`post_verify`)** sau khi sửa lỗi.
- **Nhật ký kiểm toán bất biến (`audit_logs`)**: Tự động lọc bỏ mật khẩu/secret trước khi lưu và phân quyền PostgreSQL kiểu Append-only.

---

## 2. Cấu Trúc Thư Mục Dự Án (Chi Tiết Toàn Diện)

```text
lan-printer-manager/
│
├── .env                                # [Bảo mật] Cấu hình môi trường cục bộ (DB password, secrets - không commit Git)
├── .env.example                        # File mẫu các biến môi trường để triển khai hệ thống mới
├── .gitattributes                      # Cố định định dạng CRLF cho file batch trên Windows
├── .gitignore                          # Danh sách loại trừ file nhạy cảm (.env, caches, logs, .venv)
├── alembic.ini                         # Cấu hình kết nối và format log cho Alembic Database Migration
├── pyproject.toml                      # Cấu hình dự án, công cụ Ruff Linter, Pytest và build packaging
├── README.md                           # Tài liệu hướng dẫn cài đặt, cấu hình PostgreSQL và vận hành
├── requirements.txt                    # Danh sách các thư viện Python bắt buộc đã được khóa tương thích
├── run.bat                             # File khởi động nhanh ứng dụng Desktop (tự cấu hình PYTHONPATH)
├── run_no_console.bat                  # File mở ứng dụng Desktop ở chế độ chạy nền (ẩn cửa sổ CMD đen)
│
├── data/                               # Thư mục lưu dữ liệu cục bộ, báo cáo xuất bản CSV/JSON
│   └── .gitkeep
│
├── logs/                               # Thư mục lưu file nhật ký xoay vòng của hệ thống
│   ├── .gitkeep
│   └── lan_printer_manager.log         # Nhật ký hoạt động chi tiết (Rotation: 5MB x 5 files)
│
├── migrations/                         # Quản lý phiên bản cấu trúc cơ sở dữ liệu PostgreSQL (Alembic)
│   ├── env.py                          # Script nạp metadata SQLAlchemy và kết nối DB cho Alembic
│   ├── script.py.mako                  # Template mẫu sinh file migration tự động
│   └── versions/
│       └── 0001_initial_schema.py      # Migration tạo 8 bảng, khóa ngoại, kiểu INET và index
│
├── scripts/                            # Bộ công cụ dòng lệnh quản trị viên
│   ├── init_db.py                      # Tự động kết nối DB, đồng bộ bảng và khởi tạo tài khoản admin
│   ├── provision_local_db.sql          # Script SQL tạo Role lan_manager_app và các database chính/test
│   ├── seed_demo_data.py               # Nạp dữ liệu mẫu 10 thiết bị/máy in thật và 4 tài khoản RBAC
│   └── sql_setup_guide.sql             # Hướng dẫn chi tiết phân quyền cơ sở dữ liệu PostgreSQL
│
├── tests/                              # Bộ kiểm thử tự động (Test Automation Suite)
│   ├── conftest.py                     # Cấu hình fixtures chung, Session mock và AppConfig mock
│   ├── integration/
│   │   └── test_postgres_and_ui_state.py   # Kiểm thử tích hợp kết nối PostgreSQL và lưu trạng thái UI
│   └── unit/
│       ├── test_network_and_cidr.py        # Kiểm thử phân giải IP, dải CIDR, cổng TCP và bitmask lỗi
│       ├── test_repositories_and_dedup.py  # Kiểm thử 6 Repositories, chống trùng lặp IP/MAC khi DHCP đổi
│       ├── test_services_rbac_and_diagnostics.py # Kiểm thử chặn quyền RBAC, kiểm tra Spooler & HMAC
│       ├── test_snmp_and_scan_service.py   # Kiểm thử đóng gói SNMPv2c, giải mã gói tin và Audit log
│       └── test_ui_navigation.py           # Kiểm thử chuyển tab tự động, chọn máy in và chạy chẩn đoán tức thì
│
└── src/
    └── lan_manager/
        ├── __init__.py                 # Đánh dấu package chính
        ├── main.py                     # [Entrypoint] Điểm khởi động app, nạp cấu hình và mở PySide6
        │
        ├── core/                       # [Tầng Cốt Lõi] Cấu hình, bảo mật và logging hệ thống
        │   ├── config.py               # AppConfig (Pydantic v2), load .env, chặn quét IP ngoài LAN (RFC1918)
        │   ├── logging_config.py       # Thiết lập Logging chuẩn Python (RotatingFileHandler + Console)
        │   └── security.py             # Băm mật khẩu bcrypt, tạo/kiểm tra chữ ký HMAC-SHA256, guard RBAC
        │
        ├── domain/                     # [Tầng Nghiệp Vụ Thuần - Độc lập hoàn toàn với UI/ORM]
        │   ├── exceptions.py           # Định nghĩa các lớp ngoại lệ nghiệp vụ (DeviceNotFoundError,...)
        │   ├── enums/
        │   │   └── system_enums.py     # Toàn bộ Enums: DeviceType, Status, Severity, TaskType, RoleType
        │   └── models/
        │       └── entities.py         # Thực thể Domain (Dataclasses): Device, Printer, User, Task, AuditLog
        │
        ├── infrastructure/             # [Tầng Hạ Tầng] Giao tiếp thiết bị mạng, Windows API và PostgreSQL
        │   │
        │   ├── database/               # Quản lý kết nối PostgreSQL & SQLAlchemy 2.0
        │   │   ├── base.py             # DeclarativeBase chung của SQLAlchemy
        │   │   ├── connection.py       # DatabaseManager, SessionScope context manager, Health Check
        │   │   ├── models.py           # Ánh xạ ORM 8 bảng PostgreSQL (kiểu INET, Foreign Keys, Index)
        │   │   └── repositories/       # [Repository Pattern] Toàn bộ truy vấn SQL nằm độc lập tại đây:
        │   │       ├── audit_repository.py       # Ghi và đọc nhật ký kiểm toán (Audit Trail)
        │   │       ├── device_repository.py      # Thêm, sửa, tìm kiếm, phân trang và khử trùng lặp thiết bị
        │   │       ├── diagnostic_repository.py  # Lưu và truy xuất kết quả chẩn đoán 5 bước
        │   │       ├── printer_repository.py     # Quản lý thông số phần cứng chuyên biệt của máy in
        │   │       ├── task_repository.py        # Lưu lịch sử tác vụ sửa lỗi từ xa và hậu kiểm
        │   │       └── user_repository.py        # Quản lý thông tin tài khoản người dùng và mật khẩu băm
        │   │
        │   ├── network/                # Giao thức mạng tầng thấp
        │   │   ├── port_checker.py     # Thăm dò ICMP Ping socket, kiểm tra đa cổng TCP (9100, 515, 631,...)
        │   │   ├── scanner.py          # Bộ quét đa luồng (ThreadPool) có Rate-Limit và kiểm soát dải IP
        │   │   └── snmp_client.py      # SNMPv2c Client tự đóng gói UDP, đọc OID MIB-II & Printer-MIB
        │   │
        │   ├── printer/                # Tương tác máy in & Print Subsystem của Windows
        │   │   └── windows_printer_adapter.py # Quản lý hàng đợi in, khởi động lại Spooler (pywin32)
        │   │
        │   └── remote/                 # Tương tác điều khiển tác vụ từ xa
        │       ├── agent_client.py     # Authenticated HTTPS Client gửi lệnh ký số HMAC kèm Anti-Replay
        │       └── task_executor.py    # Điều phối thực thi tác vụ theo Allowlist (Local vs Remote Agent)
        │
        ├── application/                # [Tầng Điều Phối Nghiệp Vụ - Service Layer]
        │   │
        │   ├── dto/                    # Các cấu trúc trung chuyển dữ liệu giữa các tầng (DTOs)
        │   │   └── schemas.py          # DashboardSummaryDTO, FullDiagnosticReportDTO, TaskDefinitionDTO,...
        │   │
        │   └── services/               # 7 Dịch vụ nghiệp vụ chính điều phối hệ thống:
        │       ├── audit_service.py          # Đăng nhập RBAC, ghi log hành động và làm mờ mật khẩu
        │       ├── device_service.py         # Quản lý vòng đời thiết bị, tổng hợp số liệu Dashboard KPIs
        │       ├── diagnostic_service.py     # Điều phối quy trình Chẩn đoán 5 bước và kết luận nguyên nhân
        │       ├── monitoring_service.py     # Giám sát định kỳ trạng thái Online/Offline và OID mực in
        │       ├── printer_service.py        # Quản lý hồ sơ máy in chuyên sâu (Overview, Connectivity, OIDs)
        │       ├── remote_task_service.py    # Kiểm duyệt tác vụ Allowlist, kiểm tra quyền RBAC và hậu kiểm
        │       └── scan_service.py           # Điều phối quét khám phá mạng LAN và lưu thiết bị mới vào DB
        │
        └── ui/                         # [Tầng Hiển Thị - Presentation Layer PySide6 / Qt]
            ├── main_window.py          # Cửa sổ chính: Sidebar thu gọn, Header live DB, Stacked Widget
            ├── workers.py              # ServiceWorker (QRunnable + QThreadPool) chạy tác vụ nền không đơ UI
            │
            ├── components/             # Các thành phần giao diện tái sử dụng
            │   ├── confirm_dialog.py   # Hộp thoại cảnh báo rủi ro có xác thực tên tác vụ trước khi chạy
            │   ├── device_table_model.py # Qt Model/View (QAbstractTableModel) tải bảng hàng nghìn IP siêu tốc
            │   └── status_badge.py     # Huy hiệu trạng thái chuẩn màu doanh nghiệp (Online, Error, Running)
            │
            ├── styles/                 # Định dạng giao diện
            │   └── enterprise_theme.qss # Bộ phong cách QSS chuyên nghiệp phong cách IT Enterprise
            │
            ├── dashboard.py            # 01. Dashboard: 6 thẻ KPIs, danh sách sự cố mở và tác vụ gần đây
            ├── devices_page.py         # 02. Thiết bị mạng: Bảng thiết bị phân trang, quét khám phá mạng LAN
            ├── printers_page.py        # 03. Máy in: 6 tabs chi tiết (Tổng quan, Cổng in, SNMP, Chẩn đoán,...)
            ├── diagnostics_page.py     # 04. Chẩn đoán sự cố: Bảng 5 bước kỹ thuật và đề xuất tác vụ xử lý
            ├── tasks_page.py           # 05. Tác vụ từ xa: Thực thi sửa lỗi Spooler/Hàng đợi và hậu kiểm
            ├── logs_page.py            # 06. Nhật ký hoạt động: Xem và lọc lịch sử Audit Trail toàn hệ thống
            └── settings_page.py        # 07. Cài đặt: Kiểm tra kết nối PostgreSQL, phân quyền RBAC và CIDR
```

### Phân Tầng Trách Nhiệm Kiến Trúc (Layer Responsibilities)

- **Presentation Layer (`src/lan_manager/ui/`)**: Chỉ nhận sự kiện từ người dùng, gọi Service Layer và vẽ giao diện. Tuyệt đối không chứa câu lệnh SQL hay quét socket trực tiếp.
- **Application Layer (`src/lan_manager/application/`)**: Nắm giữ toàn bộ logic nghiệp vụ, thẩm định quyền RBAC, điều phối gọi Repository / Adapter và trả kết quả dưới dạng DTO an toàn.
- **Domain Layer (`src/lan_manager/domain/`)**: Chứa các thực thể nghiệp vụ (`dataclasses`) thuần túy, Enums và Exceptions; độc lập 100% với UI và ORM Database.
- **Infrastructure Layer (`src/lan_manager/infrastructure/`)**: Triển khai kỹ thuật cụ thể: PostgreSQL qua SQLAlchemy 2.0 (với Repository Pattern), Windows API qua `pywin32`, mạng qua `socket`/`pysnmp`, và điều khiển từ xa qua HTTPS + HMAC.
- **Core Layer (`src/lan_manager/core/`)**: Tiện ích dùng chung toàn hệ thống: cấu hình Pydantic tập trung, mã hóa mật khẩu bcrypt, chữ ký HMAC-SHA256 và cơ chế ghi log xoay vòng.

---

## 3. Hướng Dẫn Cài Đặt & Khởi Chạy Chi Tiết

### Bước 1: Cài đặt Python & Tạo Virtual Environment

Yêu cầu **Python 3.11+** (khuyến nghị **Python 3.12** trên Windows):

```powershell
cd E:\toolquanlymang
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Bước 2: Cài đặt Dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### Bước 3: Cài đặt và Cấu hình Cơ sở dữ liệu PostgreSQL

1. Mở `psql` bằng tài khoản quản trị PostgreSQL và chạy các lệnh trong file [`scripts/sql_setup_guide.sql`](file:///e:/toolquanlymang/scripts/sql_setup_guide.sql) để tạo user `lan_manager_app` và database `lan_printer_manager` với quyền tối thiểu.
2. Sao chép file cấu hình mẫu `.env.example` thành `.env` và cập nhật thông tin kết nối:

```powershell
Copy-Item .env.example .env
```

> **Lưu ý bảo mật**: Không mở cổng PostgreSQL (`5432`) ra toàn mạng nếu chỉ chạy cục bộ; luôn đặt mật khẩu mạnh cho `DB_PASSWORD` và `INITIAL_ADMIN_PASSWORD` trong `.env`.

### Bước 4: Chạy Migration & Khởi tạo Dữ liệu Nền

Bạn có thể chạy migration bằng **Alembic**:

```powershell
alembic upgrade head
```

Hoặc chạy script khởi tạo (tự động kiểm tra kết nối, đồng bộ bảng và tạo các vai trò RBAC + tài khoản `admin` ban đầu):

```powershell
python scripts/init_db.py
```

### Bước 5: Khởi chạy Ứng dụng

Bạn có thể mở ứng dụng theo 2 cách:

- **Cách 1 (Khuyên dùng):** Nhấp đúp chuột trực tiếp vào file **[`run.bat`](file:///e:/toolquanlymang/run.bat)** ở thư mục gốc (hoặc **[`run_no_console.bat`](file:///e:/toolquanlymang/run_no_console.bat)** nếu muốn ẩn cửa sổ đen CMD).
- **Cách 2:** Chạy bằng dòng lệnh:

```powershell
python -m lan_manager.main
```

*(Nếu PostgreSQL chưa bật lúc mở ứng dụng, giao diện vẫn khởi động an toàn ở trạng thái `Chưa kết nối PostgreSQL` và cho phép kiểm tra/kết nối lại trong mục **07. Cài đặt**).*

---

## 4. Chạy Kiểm Thử & Kiểm Tra Chất Lượng Mã Nguồn

### Chạy toàn bộ Unit Test & Integration Test

Bộ kiểm thử không yêu cầu có máy in thật (sử dụng mock cho giao thức mạng/SNMP/Spooler và cô lập database):

```powershell
# Chạy bằng pytest (khi đã cài đặt pytest trong virtualenv)
pytest

# Hoặc chạy trực tiếp bằng unittest chuẩn của Python
python -m unittest discover -s tests -v
```

### Kiểm tra chất lượng mã nguồn với Ruff

```powershell
ruff check src tests
```

---

## 5. Hướng Dẫn Sao Lưu (Backup) & Phục Hồi (Restore) PostgreSQL

### Sao lưu định kỳ (Backup)

```powershell
pg_dump -h 127.0.0.1 -p 5432 -U postgres -F c -b -v -f "backup_lan_printer_manager.dump" lan_printer_manager
```

### Phục hồi dữ liệu (Restore)

```powershell
pg_restore -h 127.0.0.1 -p 5432 -U postgres -d lan_printer_manager -v "backup_lan_printer_manager.dump"
```

---

## 6. Đóng Gói Ứng Dụng Windows Bằng PyInstaller

Để đóng gói ứng dụng thành thư mục thực thi độc lập trên Windows (`.exe`) kèm stylesheet QSS:

```powershell
pyinstaller --noconfirm --onedir --windowed `
    --name "LANPrinterManager" `
    --paths "src" `
    --add-data "src/lan_manager/ui/styles/enterprise_theme.qss;lan_manager/ui/styles" `
    src/lan_manager/main.py
```

Sau khi đóng gói hoàn tất, bản phân phối nằm tại `dist/LANPrinterManager/LANPrinterManager.exe`. Đặt file `.env` cạnh file thực thi khi triển khai tại máy kỹ thuật viên.

