"""The interactive setup wizard + saved config + the shared-env safety check.
The wizard's prompt/confirm functions are injected, so it's testable without a
real terminal.
"""

import sys

from gaslight.cli import _running_in_targets_env
from gaslight.core.wizard import load_config, run_wizard, save_config


def _prompt(answers):
    it = iter(answers)
    return lambda *a, **k: next(it)


def _confirm(answers):
    it = iter(answers)
    return lambda *a, **k: next(it)


class _Console:
    def print(self, *a, **k):
        pass


# --- config load/save ---


def test_load_config_missing_returns_none(tmp_path):
    assert load_config(tmp_path) is None


def test_save_then_load_roundtrips(tmp_path):
    save_config(tmp_path, {"command": ["npx", "-y", "srv"], "llm": "ollama"})
    cfg = load_config(tmp_path)
    assert cfg == {"command": ["npx", "-y", "srv"], "llm": "ollama"}


def test_save_never_persists_credentials(tmp_path):
    # env/credentials must NEVER be written to a file that could be committed.
    save_config(tmp_path, {"command": ["python", "s.py"], "llm": "off", "env": {"DATABASE_URL": "secret"}})
    text = (tmp_path / ".gaslight.json").read_text()
    assert "DATABASE_URL" not in text and "secret" not in text


def test_load_config_bad_json_returns_none(tmp_path):
    (tmp_path / ".gaslight.json").write_text("{not json")
    assert load_config(tmp_path) is None


# --- wizard flow ---


def test_wizard_simple_no_backend(tmp_path):
    # empty cwd → nothing auto-detected → custom prompt path
    out = run_wizard(
        _Console(),
        prompt_ask=_prompt(["npx -y srv", "off"]),
        confirm_ask=_confirm([False, True]),  # needs-backend? no · save? yes
        cwd=tmp_path,
    )
    assert out["command"] == ["npx", "-y", "srv"]
    assert out["env"] == {}
    assert out["llm"] == "scripted"  # "off" maps to deterministic
    assert out["save"] is True


def test_wizard_with_backend_and_ollama(tmp_path):
    out = run_wizard(
        _Console(),
        prompt_ask=_prompt(["python -m x", "KEY=val", "", "ollama"]),
        confirm_ask=_confirm([True, False]),  # needs-backend? yes · save? no
        cwd=tmp_path,
    )
    assert out["command"] == ["python", "-m", "x"]
    assert out["env"] == {"KEY": "val"}
    assert out["llm"] == "ollama"
    assert out["save"] is False


def test_wizard_auto_runs_with_detected_target(tmp_path):
    # a project .mcp.json → Auto path returns the detected command immediately,
    # deterministic core, no further prompts.
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg"]}}}')
    out = run_wizard(
        _Console(),
        prompt_ask=_prompt(["a"]),  # Auto
        confirm_ask=_confirm([]),
        cwd=tmp_path,
    )
    assert out["mode"] == "auto"
    assert out["command"] == ["npx", "-y", "pkg"]
    assert out["llm"] == "scripted"


def test_wizard_manual_picks_detected_target(tmp_path):
    # Choosing Manual still offers the detected target as option 1.
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg"]}}}')
    out = run_wizard(
        _Console(),
        prompt_ask=_prompt(["m", "1", "off"]),  # manual · pick #1 · llm off
        confirm_ask=_confirm([False, True]),  # backend? no · save? yes
        cwd=tmp_path,
    )
    assert out["mode"] == "manual"
    assert out["command"] == ["npx", "-y", "pkg"]


def test_wizard_force_manual_skips_auto_choice(tmp_path):
    # The Auto-failed fallback re-enters with force_manual — no auto/manual prompt.
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg"]}}}')
    out = run_wizard(
        _Console(),
        prompt_ask=_prompt(["1", "off"]),  # straight to target pick · llm off
        confirm_ask=_confirm([False, True]),
        cwd=tmp_path,
        force_manual=True,
    )
    assert out["mode"] == "manual"
    assert out["command"] == ["npx", "-y", "pkg"]


# --- shared-env safety check ---


def test_same_interpreter_is_flagged():
    assert _running_in_targets_env([sys.executable, "-m", "pkg.server"]) is True


def test_npx_target_not_flagged():
    assert _running_in_targets_env(["npx", "-y", "some-server"]) is False


def test_empty_command_not_flagged():
    assert _running_in_targets_env([]) is False
