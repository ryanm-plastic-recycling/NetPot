from __future__ import annotations

import os
import sys

import uvicorn
from dotenv import load_dotenv

from honeysentinel.app import create_app


def main() -> None:
    dotenv_path = os.environ.get("DOTENV_PATH")
    if dotenv_path:
        load_dotenv(dotenv_path, override=False)
    else:
        load_dotenv()
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    app = create_app(config_path)
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
