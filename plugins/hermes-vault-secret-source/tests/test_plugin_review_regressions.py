from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

from conftest import FetchResult


PLUGIN_PATH = Path(__file__).resolve().parents[1] / "__init__.py"


class Proc:
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def _load_plugin():
    spec = importlib.util.spec_from_file_location("hermes_vault_secret_source_review_plugin", PLUGIN_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_preserves_all_generic_failures_as_warnings(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()

    def fake_run(argv, **kwargs):
        env_name, ref = argv[-1].split("=", 1)
        alias = ref.rsplit("=", 1)[-1]
        if alias == "first":
            return Proc(json.dumps({"secrets": {env_name: "value"}, "warnings": {}, "errors": {}}))
        return Proc(
            json.dumps(
                {
                    "secrets": {},
                    "warnings": {},
                    "errors": {env_name: {"kind": "EMPTY_VALUE", "message": f"failed-{alias}"}},
                }
            ),
            returncode=1,
        )

    monkeypatch.setattr(plugin, "run_secret_cli", fake_run)
    result = plugin.HermesVaultSource().fetch(
        {
            "enabled": True,
            "env": {
                "FIRST_KEY": "hv://generic?alias=first",
                "SECOND_KEY": "hv://generic?alias=second",
                "THIRD_KEY": "hv://generic?alias=third",
            },
        },
        tmp_path,
    )

    assert result.ok is True
    assert result.secrets == {"FIRST_KEY": "value"}
    assert any("failed-second" in warning for warning in result.warnings)
    assert any("failed-third" in warning for warning in result.warnings)


def test_uses_one_global_timeout_budget(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()
    timeouts = []
    ticks = iter([100.0, 100.0, 101.0, 103.0])
    monkeypatch.setattr(plugin.time, "monotonic", lambda: next(ticks))

    def fake_fetch(**kwargs):
        timeouts.append(kwargs["timeout"])
        return FetchResult(secrets={"HERMES_VAULT_SECRET": "value"})

    monkeypatch.setattr(plugin, "_fetch_bindings", fake_fetch)
    result = plugin.HermesVaultSource().fetch(
        {
            "enabled": True,
            "timeout_seconds": 5,
            "env": {
                "FIRST_KEY": "hv://generic?alias=first",
                "SECOND_KEY": "hv://generic?alias=second",
                "THIRD_KEY": "hv://generic?alias=third",
            },
        },
        tmp_path,
    )

    assert result.ok is True
    assert timeouts == [5.0, 4.0, 2.0]


def test_refresh_uses_active_hermes_home(monkeypatch, tmp_path: Path) -> None:
    plugin = _load_plugin()
    calls = []
    env_loader = types.ModuleType("hermes_cli.env_loader")
    setattr(env_loader, "reset_secret_source_cache", lambda: calls.append("reset"))
    setattr(env_loader, "load_hermes_dotenv", lambda **kwargs: calls.append(kwargs))
    hermes_cli = types.ModuleType("hermes_cli")
    constants = types.ModuleType("hermes_constants")
    setattr(constants, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.env_loader", env_loader)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)

    plugin._refresh_secret_sources_after_registration()

    assert calls == ["reset", {"hermes_home": tmp_path}]
