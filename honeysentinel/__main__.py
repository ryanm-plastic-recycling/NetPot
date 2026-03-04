from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import uvicorn

from honeysentinel.app import create_app

logger = logging.getLogger(__name__)


def _load_startup_dotenv() -> None:
    dotenv_path_raw = os.environ.get("DOTENV_PATH", "").strip()
    dotenv_path = Path(dotenv_path_raw).expanduser() if dotenv_path_raw else None
    dotenv_in_cwd = Path.cwd() / ".env"

    try:
        from dotenv import load_dotenv
    except ImportError:
        logger.warning("python-dotenv not installed; .env not loaded")
        os.environ["HONEYSENTINEL_DOTENV_SOURCE"] = "python-dotenv-missing"
        return

    if dotenv_path and dotenv_path.exists():
        load_dotenv(dotenv_path=dotenv_path, override=False)
        os.environ["HONEYSENTINEL_DOTENV_SOURCE"] = "dotenv_path"
        logger.info("Loaded startup .env from DOTENV_PATH")
        return

    load_dotenv(dotenv_path=dotenv_in_cwd, override=False)
    os.environ["HONEYSENTINEL_DOTENV_SOURCE"] = "cwd"
    logger.info("Loaded startup .env from current working directory")


def main() -> None:
    _load_startup_dotenv()
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    app = create_app(config_path)
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
