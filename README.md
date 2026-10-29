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

## 2. Cấu Trúc Thư Mục

```text
lan-printer-manager/
├── src/
│   └── lan_manager/
│       ├── main.py                              # Điểm khởi chạy ứng dụng Desktop
│       ├── core/                                # Cấu hình (.env), Logging xoay vòng, Bảo mật (RBAC, Bcrypt, HMAC)
│       ├── domain/                              # Thực thể nghiệp vụ (Entities), Enums, Exceptions
│       ├── infrastructure/
│       │   ├── database/                        # Engine, SessionScope, SQLAlchemy 2.0 Models & 6 Repositories
│       │   ├── network/                         # Controlled Scanner, Port Checker, SNMPv2c Client
│       │   ├── printer/                         # Windows Printer & Spooler Adapter (pywin32)
│       │   └── remote/                          # TaskExecutor & Authenticated HTTPS+HMAC Agent Client
│       ├── application/
│       │   ├── dto/                             # Data Transfer Objects
│       │   └── services/                        # 7 Services điều phối nghiệp vụ
│       └── ui/                                  # Giao diện PySide6, Qt Model/View, QThreadPool Workers & QSS
├── migrations/                                  # Cấu hình và phiên bản migration của Alembic
├── scripts/
│   ├── init_db.py                               # Kiểm tra kết nối, khởi tạo bảng và tạo tài khoản Admin ban đầu
│   └── sql_setup_guide.sql                      # Script tạo role/database PostgreSQL theo nguyên tắc Least Privilege
├── tests/
│   ├── unit/                                    # Kiểm thử đơn vị (Mock mạng, SNMP, Spooler, DB cô lập)
│   └── integration/                             # Kiểm thử tích hợp kết nối PostgreSQL
├── .env.example
├── alembic.ini
├── pyproject.toml
└── requirements.txt
```

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

