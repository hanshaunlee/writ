from __future__ import annotations

import os

import uvicorn

from ..logging_setup import setup_logging
from .app import create_app


def main() -> None:
    setup_logging()
    app = create_app(api_key=os.environ.get("DEMO_SAAS_API_KEY", "demo-api-key"))
    uvicorn.run(
        app,
        host=os.environ.get("WRIT_HOST", "0.0.0.0"),
        port=int(os.environ.get("WRIT_PORT", "9000")),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
