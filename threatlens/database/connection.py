import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIR / "threatlens.db"


def get_connection(
    database_path: Path = DATABASE_PATH,
) -> sqlite3.Connection:
    """Create and return a SQLite database connection."""

    database_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row

    return connection
