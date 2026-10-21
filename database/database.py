import os
import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash

DEFAULT_DATABASE_PATH = Path(__file__).parent / "app.db"

# Demo accounts. Plaintext is used ONLY by the intentionally vulnerable lab
# table; the secure table stores salted hashes of the same passwords.
DEMO_USERS = [
    ("omm", "password123", "user"),
    ("admin", "admin123", "admin"),
    ("student", "student123", "user"),
]


def database_path():
    """Database file location. Override with SQLI_DB_PATH (used by tests)."""
    return Path(os.environ.get("SQLI_DB_PATH", DEFAULT_DATABASE_PATH))


def get_connection():
    connection = sqlite3.connect(database_path())
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    # Lab table: plaintext passwords, used only by /vulnerable-login so the
    # injection demo stays simple. Never do this in a real application.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    # Secure table: only salted password hashes. Used by /secure-login.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS secure_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    connection.executemany("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES (?, ?, ?)
    """, DEMO_USERS)

    existing = {
        row["username"]
        for row in connection.execute("SELECT username FROM secure_users")
    }
    for username, password, role in DEMO_USERS:
        if username not in existing:
            connection.execute(
                "INSERT INTO secure_users (username, password_hash, role) "
                "VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )

    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully.")
