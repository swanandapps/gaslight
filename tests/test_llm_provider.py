"""Provider resolution for the OPTIONAL LLM layer: graceful fallback when no
model is configured, a free local (Ollama) option, and the on/off signal the
CLI shows for transparency. See core/llm.py:detect_provider / llm_is_active.
"""

import pytest

from gaslight.core.llm import (
    NoProviderAvailable,
    OpenAIProvider,
    ScriptedProvider,
    detect_provider,
    llm_is_active,
)


@pytest.fixture(autouse=True)
def _no_ambient_keys(monkeypatch):
    # These tests are about resolution logic, not whatever happens to be in the
    # developer's environment — strip both keys so the default path is testable.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def test_no_credentials_falls_back_to_deterministic_not_an_error():
    # The whole point: no key, no flag -> a full deterministic run, never a crash.
    provider = detect_provider(None)
    assert isinstance(provider, ScriptedProvider)
    assert llm_is_active(provider) is False


def test_explicit_scripted_is_deterministic():
    assert llm_is_active(detect_provider("scripted")) is False


def test_ollama_gives_a_local_openai_compatible_provider():
    provider = detect_provider("ollama")
    assert isinstance(provider, OpenAIProvider)
    assert llm_is_active(provider) is True


def test_ollama_model_is_env_overridable(monkeypatch):
    monkeypatch.setenv("GASLIGHT_OLLAMA_MODEL", "llama3.2:1b")
    provider = detect_provider("ollama")
    assert provider._model == "llama3.2:1b"


def test_anthropic_key_present_selects_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert llm_is_active(detect_provider(None)) is True


def test_unknown_explicit_provider_raises():
    with pytest.raises(NoProviderAvailable):
        detect_provider("gpt5-turbo-ultra")


def test_explicit_anthropic_without_key_raises_cleanly():
    # Must raise our own NoProviderAvailable (clean message), not let the SDK
    # throw a raw error at construction. (Pre-launch review, finding 3.)
    with pytest.raises(NoProviderAvailable):
        detect_provider("anthropic")


def test_explicit_openai_without_key_raises_cleanly():
    with pytest.raises(NoProviderAvailable):
        detect_provider("openai")
