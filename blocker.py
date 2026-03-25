import sqlite3
from typing import Optional


DB_PATH = "access_control.db"


class AccessControlManager:
    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _initialize_database(self) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    login_id TEXT UNIQUE NOT NULL,
                    company_id TEXT UNIQUE,
                    password TEXT NOT NULL,
                    is_blocked INTEGER NOT NULL DEFAULT 0,
                    block_reason TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    login_id TEXT,
                    full_name TEXT,
                    event_type TEXT NOT NULL,
                    event_message TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.commit()

    def add_user(
        self,
        full_name: str,
        login_id: str,
        company_id: Optional[str],
        password: str,
    ) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (full_name, login_id, company_id, password)
                VALUES (?, ?, ?, ?)
            """, (full_name, login_id, company_id, password))
            conn.commit()

    def find_user_by_name(self, full_name: str) -> list[tuple]:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, full_name, login_id, company_id, is_blocked, block_reason
                FROM users
                WHERE lower(full_name) = lower(?)
            """, (full_name,))
            return cursor.fetchall()

    def block_user_by_name(self, full_name: str, reason: str = "access policy update") -> int:
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET is_blocked = 1,
                    block_reason = ?
                WHERE lower(full_name) = lower(?)
            """, (reason, full_name))

            updated_rows = cursor.rowcount

            cursor.execute("""
                INSERT INTO access_audit (full_name, event_type, event_message)
                VALUES (?, 'BLOCK_ACCOUNT', ?)
            """, (full_name, f"Account marked blocked: {reason}"))

            conn.commit()
            return updated_rows

    def unblock_user_by_name(self, full_name: str) -> int:
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE users
                SET is_blocked = 0,
                    block_reason = NULL
                WHERE lower(full_name) = lower(?)
            """, (full_name,))

            updated_rows = cursor.rowcount

            cursor.execute("""
                INSERT INTO access_audit (full_name, event_type, event_message)
                VALUES (?, 'UNBLOCK_ACCOUNT', 'Account unblocked')
            """, (full_name,))

            conn.commit()
            return updated_rows

    def authenticate_user(self, login_id: str, password: str) -> tuple[bool, str]:
        with self._connect() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT full_name, login_id, password, is_blocked
                FROM users
                WHERE login_id = ?
            """, (login_id,))

            row = cursor.fetchone()

            if not row:
                self._log_access_event(login_id, None, "LOGIN_FAIL", "Login attempt failed")
                return False, "Unable to complete sign-in. Please verify your credentials and try again."

            full_name, stored_login_id, stored_password, is_blocked = row

            if is_blocked:
                self._log_access_event(stored_login_id, full_name, "LOGIN_DENIED", "Blocked account attempted access")
                return False, "Unable to complete sign-in at this time. Please contact support if the issue persists."

            if password != stored_password:
                self._log_access_event(stored_login_id, full_name, "LOGIN_FAIL", "Invalid password")
                return False, "Unable to complete sign-in. Please verify your credentials and try again."

            self._log_access_event(stored_login_id, full_name, "LOGIN_SUCCESS", "User authenticated successfully")
            return True, "Access granted."

    def _log_access_event(
        self,
        login_id: Optional[str],
        full_name: Optional[str],
        event_type: str,
        event_message: str,
    ) -> None:
        with self._connect() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO access_audit (login_id, full_name, event_type, event_message)
                VALUES (?, ?, ?, ?)
            """, (login_id, full_name, event_type, event_message))
            conn.commit()


if __name__ == "__main__":
    manager = AccessControlManager()

    # Demo seed data
    try:
        manager.add_user("John Smith", "jsmith01", "EMP-48291", "Password123")
        manager.add_user("Alice Brown", "abrown02", "EMP-91822", "SecurePass")
    except sqlite3.IntegrityError:
        pass  # already exists

    print("=== Search by name ===")
    records = manager.find_user_by_name("John Smith")
    for record in records:
        print(record)

    print("\n=== Block user ===")
    updated = manager.block_user_by_name("John Smith", reason="temporary access restriction")
    print(f"Rows updated: {updated}")

    print("\n=== Search again (user still exists) ===")
    records = manager.find_user_by_name("John Smith")
    for record in records:
        print(record)

    print("\n=== Attempt login for blocked user ===")
    success, message = manager.authenticate_user("jsmith01", "Password123")
    print("Success:", success)
    print("Message:", message)
