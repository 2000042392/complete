import os
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
APP_NAME = os.getenv("APP_NAME", "Zaalima Zero Trust Identity Provider")
JWT_SECRET = os.getenv("JWT_SECRET", "")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(ROOT / "data/idp.db")))
LEDGER_PATH = Path(os.getenv("LEDGER_PATH", str(ROOT / "data/did_ledger.json")))
KEY_DIR = Path(os.getenv("KEY_DIR", str(ROOT / "data/keys")))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", APP_NAME)
WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "zaalima-demo-client")
OIDC_REDIRECT_URIS = [x.strip() for x in os.getenv(
    "OIDC_REDIRECT_URIS", "http://localhost:5500/callback"
).split(",") if x.strip()]
ACCESS_TOKEN_ISSUER = os.getenv("ACCESS_TOKEN_ISSUER", "http://localhost:8000")
for path in (DATABASE_PATH.parent, LEDGER_PATH.parent, KEY_DIR):
    path.mkdir(parents=True, exist_ok=True)
if len(JWT_SECRET) < 32:
    raise RuntimeError("Set JWT_SECRET to a random secret of at least 32 characters in .env")
