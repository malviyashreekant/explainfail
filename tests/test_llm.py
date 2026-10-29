import io
import urllib.error

import pytest

from explainfail import analyze, llm
from explainfail.llm import ANTHROPIC_URL, LLMConfig, LLMError

ENV = [
    "EXPLAINFAIL_PROVIDER", "EXPLAINFAIL_MODEL", "EXPLAINFAIL_BASE_URL", "EXPLAINFAIL_API_KEY",
    "EXPLAINFAIL_TIMEOUT", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
]  # fmt: skip


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


def test_ai_is_off_by_default():
    assert LLMConfig.from_env() is None
    assert LLMConfig.from_env("none") is None


def test_unknown_provider():
    with pytest.raises(LLMError, match="Unknown AI provider"):
        LLMConfig.from_env("skynet")


def test_anthropic_needs_key_and_has_default_model(monkeypatch):
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        LLMConfig.from_env("anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    cfg = LLMConfig.from_env("anthropic")
    assert cfg.model == "claude-sonnet-5-5" and cfg.api_key == "k"


def test_openai_needs_model_and_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    with pytest.raises(LLMError, match="No model"):
        LLMConfig.from_env("openai")
    cfg = LLMConfig.from_env("openai", model="some-model")
    assert cfg.base_url == "https://api.openai.com/v1"


def test_ollama_needs_no_key():
    cfg = LLMConfig.from_env("ollama", model="llama3.1")
    assert cfg.api_key is None and cfg.base_url == "http://localhost:11434/v1"


def test_env_variables_configure_everything(monkeypatch):
    monkeypatch.setenv("EXPLAINFAIL_PROVIDER", "openai-compatible")
    monkeypatch.setenv("EXPLAINFAIL_MODEL", "m")
    monkeypatch.setenv("EXPLAINFAIL_BASE_URL", "http://llm.internal:8000/v1")
    cfg = LLMConfig.from_env()
    assert (cfg.provider, cfg.model, cfg.base_url) == ("openai-compatible", "m", "http://llm.internal:8000/v1")


def test_openai_compatible_needs_base_url():
    with pytest.raises(LLMError, match="base-url"):
        LLMConfig.from_env("openai-compatible", model="m")


def test_non_http_base_url_is_rejected():
    with pytest.raises(LLMError, match="http"):
        LLMConfig.from_env("ollama", model="m", base_url="file:///etc/passwd")


def _capture(monkeypatch, reply):
    calls = []

    def fake_post(url, headers, payload, timeout):
        calls.append((url, headers, payload, timeout))
        return reply

    monkeypatch.setattr(llm, "_post", fake_post)
    return calls


def test_anthropic_request_and_response(monkeypatch):
    calls = _capture(monkeypatch, {"content": [{"type": "text", "text": "Hello "}, {"type": "text", "text": "there"}]})
    cfg = LLMConfig(provider="anthropic", model="m1", api_key="secret-key")
    assert llm.complete(cfg, "SYS", "USER") == "Hello there"
    url, headers, payload, _ = calls[0]
    assert url == ANTHROPIC_URL
    assert headers["x-api-key"] == "secret-key" and "anthropic-version" in headers
    assert payload["model"] == "m1" and payload["system"] == "SYS"
    assert payload["messages"] == [{"role": "user", "content": "USER"}]
    assert "secret-key" not in str(payload)


def test_openai_style_request_and_response(monkeypatch):
    calls = _capture(monkeypatch, {"choices": [{"message": {"content": " answer "}}]})
    cfg = LLMConfig(provider="openai", model="m2", api_key="k", base_url="https://api.openai.com/v1/")
    assert llm.complete(cfg, "SYS", "USER") == "answer"
    url, headers, payload, _ = calls[0]
    assert url == "https://api.openai.com/v1/chat/completions"
    assert headers == {"Authorization": "Bearer k"}
    assert [m["role"] for m in payload["messages"]] == ["system", "user"]


def test_local_model_sends_no_auth_header(monkeypatch):
    calls = _capture(monkeypatch, {"choices": [{"message": {"content": "ok"}}]})
    cfg = LLMConfig(provider="ollama", model="llama3.1", base_url="http://localhost:11434/v1")
    llm.complete(cfg, "S", "U")
    assert calls[0][1] == {}


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_unexpected_response_shape(monkeypatch, provider):
    _capture(monkeypatch, {"surprise": True})
    cfg = LLMConfig(provider=provider, model="m", api_key="k", base_url="https://x.example/v1")
    with pytest.raises(LLMError, match="Unexpected response"):
        llm.complete(cfg, "S", "U")


def test_litellm_missing_gives_install_hint(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "litellm", None)  # makes `import litellm` fail
    with pytest.raises(LLMError, match=r"explainfail\[litellm\]"):
        llm.complete(LLMConfig(provider="litellm", model="m"), "S", "U")


def test_prompt_wraps_log_as_data_and_truncates():
    report = analyze("ERROR boom\n" + ("padding " * 40 + "\n") * 5000, exit_code=1)
    prompt = llm.build_user_prompt(report, max_chars=1000)
    assert prompt.startswith("<log_data>") and prompt.endswith("</log_data>")
    assert "[truncated]" in prompt
    assert len(prompt) < 1100


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_post_parses_json(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"], seen["data"], seen["timeout"] = req.full_url, req.data, timeout
        return _FakeResponse(b'{"ok": 1}')

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    assert llm._post("https://api.example/v1", {"X": "1"}, {"a": 1}, 7) == {"ok": 1}
    assert seen["timeout"] == 7 and b'"a": 1' in seen["data"]


def test_post_maps_http_and_network_errors(monkeypatch):
    def http_error(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b"bad key"))

    monkeypatch.setattr(llm.urllib.request, "urlopen", http_error)
    with pytest.raises(LLMError, match="HTTP 401: bad key"):
        llm._post("https://api.example/v1", {}, {}, 5)

    def down(req, timeout):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(llm.urllib.request, "urlopen", down)
    with pytest.raises(LLMError, match="Could not reach"):
        llm._post("https://api.example/v1", {}, {}, 5)


def test_post_refuses_non_http_schemes():
    with pytest.raises(LLMError, match="http"):
        llm._post("file:///etc/passwd", {}, {}, 5)
