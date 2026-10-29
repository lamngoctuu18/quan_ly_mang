-- ============================================================================
-- HƯỚNG DẪN TẠO DATABASE VÀ USER POSTGRESQL THEO NGUYÊN TẮC LEAST PRIVILEGE
-- Chạy script này bằng tài khoản quản trị PostgreSQL (ví dụ: psql -U postgres)
-- Thay đổi mật khẩu trước khi thực thi trong môi trường thực tế.
-- ============================================================================

-- 1. Tạo tài khoản ứng dụng (Không có quyền SUPERUSER, CREATEDB, CREATEROLE)
CREATE ROLE lan_manager_app WITH
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    NOREPLICATION
    PASSWORD 'CHANGE_ME_STRONG_DB_PASSWORD';

-- 2. Tạo cơ sở dữ liệu chính và cơ sở dữ liệu kiểm thử tích hợp
CREATE DATABASE lan_printer_manager
    WITH OWNER = postgres
    ENCODING = 'UTF8'
    TEMPLATE = template0;

CREATE DATABASE lan_printer_manager_test
    WITH OWNER = postgres
    ENCODING = 'UTF8'
    TEMPLATE = template0;

-- 3. Cấp quyền kết nối tối thiểu
REVOKE ALL ON DATABASE lan_printer_manager FROM PUBLIC;
GRANT CONNECT ON DATABASE lan_printer_manager TO lan_manager_app;

\c lan_printer_manager

-- 4. Cấp quyền trên schema public sau khi chạy Alembic migration:
GRANT USAGE ON SCHEMA public TO lan_manager_app;

-- Cấp quyền SELECT, INSERT, UPDATE, DELETE trên các bảng nghiệp vụ:
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    roles,
    users,
    devices,
    printers,
    device_status_history,
    diagnostic_results,
    remote_tasks
TO lan_manager_app;

-- 5. Bảo vệ bảng audit_logs (Append-Only):
-- Tài khoản vận hành ứng dụng chỉ được phép GHI MỚI và ĐỌC, KHÔNG được phép UPDATE hay DELETE audit_logs!
GRANT SELECT, INSERT ON TABLE audit_logs TO lan_manager_app;
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_logs FROM lan_manager_app;

-- Cấp quyền sử dụng sequences (cho id tự tăng của device_status_history và audit_logs):
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lan_manager_app;

