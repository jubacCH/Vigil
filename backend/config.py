import os
import secrets
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY_FILE = DATA_DIR / ".secret_key"

# Database: prefer DATABASE_URL env, fall back to SQLite in DATA_DIR
DATABASE_URL = os.getenv("DATABASE_URL", "")
if not DATABASE_URL:
    DATABASE_PATH = DATA_DIR / "homelab.db"
    DATABASE_URL = f"sqlite+aiosqlite:///{DATABASE_PATH}"


def get_secret_key() -> str:
    env_key = os.getenv("SECRET_KEY")
    if env_key:
        return env_key
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_text().strip()
    key = secrets.token_hex(32)
    SECRET_KEY_FILE.write_text(key)
    SECRET_KEY_FILE.chmod(0o600)
    return key


SECRET_KEY = get_secret_key()
