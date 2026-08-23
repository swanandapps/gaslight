"""The interactive setup wizard + saved config + the shared-env safety check.
The wizard talks to an injected `prompter` (select/text/password/confirm), so
it's fully testable without a real terminal — StubPrompter scripts the answers.
"""

import os
import sys

from gaslight.cli import _running_in_targets_env
from gaslight.core.wizard import load_config, run_wizard, save_config


class StubPrompter:
    """Scripts wizard answers. Each method pops the next value from its own
    queue, so a test lists exactly the selects / texts / passwords / confirms it
    expects, in order."""

    def __init__(self, *, selects=None, texts=None, passwords=None, confirms=None):
        self._selects = iter(selects or [])
        self._texts = iter(texts or [])
        self._passwords = iter(passwords or [])
        self._confirms = iter(confirms or [])

    def select(self, message, options):
        return next(self._selects)

    def text(self, message, default=""):
        return next(self._texts)

    def password(self, message):
        return next(self._passwords)

    def confirm(self, message, default=True):
        return next(self._confirms)


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


def test_wizard_quick_scan_with_detected_target(tmp_path):
    # a project .mcp.json → detected target selected, Quick scan returns the
    # command immediately with the deterministic core, no further prompts.
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg"]}}}')
    target = {"name": "srv", "command": ["npx", "-y", "pkg"], "source": ".mcp.json"}
    out = run_wizard(
        _Console(),
        StubPrompter(selects=[target, "quick"]),  # pick detected target · Quick scan
        cwd=tmp_path,
    )
    assert out["mode"] == "auto"
    assert out["command"] == ["npx", "-y", "pkg"]
    assert out["llm"] == "scripted"
    assert out["save"] is False


def test_wizard_custom_command_no_backend(tmp_path):
    # empty cwd → nothing auto-detected → custom path; Configure, no backend, off.
    out = run_wizard(
        _Console(),
        StubPrompter(
            selects=["configure", False, "off"],  # run mode · needs-backend? no · llm off
            texts=["npx -y srv"],  # custom launch command
            confirms=[True],  # save? yes
        ),
        cwd=tmp_path,
    )
    assert out["mode"] == "configure"
    assert out["command"] == ["npx", "-y", "srv"]
    assert out["env"] == {}
    assert out["llm"] == "scripted"  # "off" maps to deterministic
    assert out["save"] is True


def test_wizard_with_backend_and_ollama(tmp_path):
    out = run_wizard(
        _Console(),
        StubPrompter(
            selects=["configure", True, "ollama"],  # configure · backend? yes · ollama
            texts=["python -m x", "KEY=val", ""],  # command · one env pair · blank to finish
            confirms=[False],  # save? no
        ),
        cwd=tmp_path,
    )
    assert out["command"] == ["python", "-m", "x"]
    assert out["env"] == {"KEY": "val"}
    assert out["llm"] == "ollama"
    assert out["save"] is False


def test_wizard_openai_prompts_for_key_when_missing(tmp_path, monkeypatch):
    # Picking a hosted provider with no key in the env should ASK for it inline.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    try:
        out = run_wizard(
            _Console(),
            StubPrompter(
                selects=["configure", False, "openai"],
                texts=["npx -y srv"],
                passwords=["sk-test-123"],
                confirms=[True],
            ),
            cwd=tmp_path,
        )
        assert out["llm"] == "openai"
        assert os.environ.get("OPENAI_API_KEY") == "sk-test-123"
    finally:
        os.environ.pop("OPENAI_API_KEY", None)


def test_wizard_openai_blank_key_degrades_to_deterministic(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    out = run_wizard(
        _Console(),
        StubPrompter(
            selects=["configure", False, "openai"],
            texts=["npx -y srv"],
            passwords=[""],  # no key pasted
            confirms=[True],
        ),
        cwd=tmp_path,
    )
    assert out["llm"] == "scripted"
    assert os.environ.get("OPENAI_API_KEY") is None


def test_wizard_force_configure_skips_run_mode_choice(tmp_path):
    # The Quick-scan-failed fallback re-enters with force_configure — no
    # quick/configure prompt, straight to backend + llm.
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg"]}}}')
    target = {"name": "srv", "command": ["npx", "-y", "pkg"], "source": ".mcp.json"}
    out = run_wizard(
        _Console(),
        StubPrompter(selects=[target, False, "off"], confirms=[True]),  # target · backend? no · llm off · save
        cwd=tmp_path,
        force_configure=True,
    )
    assert out["mode"] == "configure"
    assert out["command"] == ["npx", "-y", "pkg"]


def test_wizard_confirms_a_best_guess_command(tmp_path):
    # A best-guess target is offered for confirm/edit via a text prompt.
    (tmp_path / "server.py").write_text("from mcp.server import FastMCP\napp = FastMCP('x')\napp.run()\n")
    guess = {"name": "server", "command": ["python", "-m", "server"], "source": "guess", "guess": True}
    out = run_wizard(
        _Console(),
        StubPrompter(
            selects=[guess, "quick"],
            texts=["python -m server"],  # confirm the guessed command
        ),
        cwd=tmp_path,
    )
    assert out["command"] == ["python", "-m", "server"]


# --- shared-env safety check ---


def test_same_interpreter_is_flagged():
    assert _running_in_targets_env([sys.executable, "-m", "pkg.server"]) is True


def test_npx_target_not_flagged():
    assert _running_in_targets_env(["npx", "-y", "some-server"]) is False


def test_empty_command_not_flagged():
    assert _running_in_targets_env([]) is False
