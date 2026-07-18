"""Regression guard: the FastAPI app must be importable.

A bad route signature (e.g. an invalid response-model annotation) raises at
import time and crash-loops the container — pytest should catch that before
the image ships.
"""

import os
from unittest.mock import patch


def test_main_imports_and_registers_routes():
    env = {
        "AUTH_PASSWORD_HASH": "x",
        "TOTP_SECRET": "x",
        "SESSION_SECRET": "x",
    }
    with patch.dict(os.environ, env):
        # Reload config so auth_enabled is true regardless of test order.
        import importlib

        from app import config

        importlib.reload(config)
        from app import main

        importlib.reload(main)
        paths = {route.path for route in main.app.routes}
        assert "/api/watched" in paths
        assert "/api/stats" in paths
