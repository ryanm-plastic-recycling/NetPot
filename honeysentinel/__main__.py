from __future__ import annotations

import sys

import uvicorn

from honeysentinel.app import create_app


def main() -> None:
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    app = create_app(config_path)
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
