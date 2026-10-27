import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
INSTANCE_DIR = PROJECT_ROOT / "instance"

DATABASE_PATH = INSTANCE_DIR / "InkChain.db"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_connection():
    """Open a connection to the SQLite database."""
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def init_db():
    """Create the database tables if they do not exist."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")

    connection = get_connection()

    try:
        connection.executescript(schema)
        connection.commit()
    finally:
        connection.close()

    print(f"Database initialized at: {DATABASE_PATH}")


if __name__ == "__main__":
    init_db()