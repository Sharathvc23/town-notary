"""Start a fresh Notary per test: app.py reads its configuration at import."""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable

import pytest
from fastapi.testclient import TestClient
from notary_helpers import LAB_SK, NOTARY_SK, SUITE_03, did

DEFAULT_PINS = {"0.3": SUITE_03}
_UNSET = object()


@pytest.fixture
def register_path(tmp_path: Path) -> Path:
    return tmp_path / "register.json"


@pytest.fixture
def start_notary(monkeypatch: pytest.MonkeyPatch,
                 register_path: Path) -> Callable[..., ModuleType]:
    """Import app.py under a given configuration; call again to "restart"."""
    def start(*, pins=_UNSET, labs=_UNSET, anchors=(),
              path: Path | None | object = _UNSET) -> ModuleType:
        pins = DEFAULT_PINS if pins is _UNSET else pins
        labs = [did(LAB_SK)] if labs is _UNSET else labs
        path = register_path if path is _UNSET else path
        monkeypatch.setenv("NOTARY_SEED", NOTARY_SK.hex())
        monkeypatch.setenv("NOTARY_SUITE_PINS",
                           pins if isinstance(pins, str) else json.dumps(pins))
        monkeypatch.setenv("NOTARY_LAB_DIDS", ",".join(labs))
        monkeypatch.setenv("NOTARY_ANCHORS", ",".join(anchors))
        if path is None:
            monkeypatch.delenv("REGISTER_PATH", raising=False)
        else:
            monkeypatch.setenv("REGISTER_PATH", str(path))
        sys.modules.pop("app", None)
        return importlib.import_module("app")
    yield start
    sys.modules.pop("app", None)


@pytest.fixture
def client_for() -> Callable[[ModuleType], TestClient]:
    return lambda module: TestClient(module.app)
