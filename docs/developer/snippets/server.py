"""Business-owned entry point; run with PYTHONPATH=platform_entry from generated root."""

import os

from domain.business import invoke, run, validate_input
from platform_entry.server import build_execution_server, public_key_from_env


def main():
    app = build_execution_server(public_key_from_env(), invoke=invoke, run=run, validate_input=validate_input)
    httpd = app.serve(("0.0.0.0", int(os.environ.get("PORT", "8080"))))
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
