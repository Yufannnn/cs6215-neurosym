"""Project paths and environment loading (reads the repo-root .env without extra dependencies)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "results"


def load_env(path: Path = ROOT / ".env") -> dict:
    """Return .env values, with real environment variables taking precedence."""
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    env.update({k: v for k, v in os.environ.items() if k.startswith("SOCLAAS_")})
    missing = [k for k in ("SOCLAAS_BASE_URL", "SOCLAAS_API_KEY") if not env.get(k)]
    if missing:
        raise RuntimeError(f"Missing {', '.join(missing)}: copy .env.example to .env and fill it in")
    return env
