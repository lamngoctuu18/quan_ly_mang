-- Idempotent local database and least-privilege role setup for LAN Printer Manager
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'lan_manager_app') THEN
        CREATE ROLE lan_manager_app WITH
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            PASSWORD 'LanManager_2026_SecurePassword';
    ELSE
        ALTER ROLE lan_manager_app WITH PASSWORD 'LanManager_2026_SecurePassword';
    END IF;
END
$$;

SELECT 'CREATE DATABASE lan_printer_manager OWNER lan_manager_app ENCODING ''UTF8'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'lan_printer_manager')\gexec

SELECT 'CREATE DATABASE lan_printer_manager_test OWNER lan_manager_app ENCODING ''UTF8'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'lan_printer_manager_test')\gexec

GRANT CONNECT ON DATABASE lan_printer_manager TO lan_manager_app;
GRANT CONNECT ON DATABASE lan_printer_manager_test TO lan_manager_app;

\c lan_printer_manager
GRANT ALL ON SCHEMA public TO lan_manager_app;

\c lan_printer_manager_test
GRANT ALL ON SCHEMA public TO lan_manager_app;

