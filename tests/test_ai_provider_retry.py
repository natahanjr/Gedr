"""Unit tests for the AI agent retry and timeout logic (provider-agnostic)."""
import pytest
from unittest.mock import Mock, patch

from ai.ai_agent import (
    GedrAgent, MAX_RETRIES, INITIAL_BACKOFF, REQUEST_TIMEOUT,
    _OpenAIBackend, _NativeBackend, _local_fallback, _parse_json,
)


# ------------------------------------------------------------------
# OpenAI-compatible backend (default, covers OpenCode Zen)
# ------------------------------------------------------------------
class TestOpenAIBackendRetry:
    def test_success_first_try(self):
        backend = _OpenAIBackend("sk-test", "https://api.example.com", "test-model")
        fake = Mock()
        fake.status_code = 200
        fake.json.return_value = {"choices": [{"message": {"content": '{"ok": true}'}}]}
        fake.raise_for_status = Mock()
        with patch("requests.post", return_value=fake) as m:
            assert backend.generate("prompt") == '{"ok": true}'
            assert m.call_count == 1

    def test_retries_on_rate_limit(self):
        backend = _OpenAIBackend("sk-test", "https://api.example.com", "test-model")
        ok = Mock(status_code=200, json=Mock(return_value={"choices": [{"message": {"content": '{"ok": true}'}}]}), raise_for_status=Mock())
        with patch("requests.post", side_effect=[Mock(status_code=429, raise_for_status=Mock()), ok]) as m:
            assert backend.generate("prompt") == '{"ok": true}'
            assert m.call_count == 2

    def test_retries_on_timeout(self):
        backend = _OpenAIBackend("sk-test", "https://api.example.com", "test-model")
        ok = Mock(status_code=200, json=Mock(return_value={"choices": [{"message": {"content": '{"ok": true}'}}]}), raise_for_status=Mock())
        import requests as req
        with patch("requests.post", side_effect=[req.Timeout("t"), ok]) as m:
            assert backend.generate("prompt") == '{"ok": true}'
            assert m.call_count == 2

    def test_exponential_backoff(self):
        backend = _OpenAIBackend("sk-test", "https://api.example.com", "test-model")
        ok = Mock(status_code=200, json=Mock(return_value={"choices": [{"message": {"content": '{"ok": true}'}}]}), raise_for_status=Mock())
        with patch("requests.post", side_effect=[Mock(status_code=429, raise_for_status=Mock()), Mock(status_code=429, raise_for_status=Mock()), ok]):
            with patch("time.sleep") as sl:
                backend.generate("prompt")
                assert sl.call_count == 2
                assert sl.call_args_list[1][0][0] > sl.call_args_list[0][0][0]

    def test_backoff_capped(self):
        backend = _OpenAIBackend("sk-test", "https://api.example.com", "test-model")
        ok = Mock(status_code=200, json=Mock(return_value={"choices": [{"message": {"content": '{"ok": true}'}}]}), raise_for_status=Mock())
        with patch("requests.post", side_effect=[Mock(status_code=429, raise_for_status=Mock())] * 5 + [ok]):
            with patch("time.sleep") as sl:
                backend.generate("prompt", retries=6)
                for call in sl.call_args_list:
                    assert call[0][0] <= 30.0


# ------------------------------------------------------------------
# Agent-level tests (default opencode provider)
# ------------------------------------------------------------------
class TestAgentDefaults:
    def test_offline_fallback_no_key(self):
        agent = GedrAgent(api_key="")
        finding = {"cwe": "CWE-89", "title": "SQLi", "file": "a.py", "line": 1, "severity": "High", "scanner": "py"}
        rec = agent.analyze_finding(finding)
        assert rec["model"] == "offline fallback"
        assert rec["cwe"] == "CWE-89"

    def test_offline_fallback_on_api_error(self):
        agent = GedrAgent(api_key="sk-test", model="m")
        # Patch the backend that was created at __init__ time
        fake_bk = Mock(side_effect=RuntimeError("boom"))
        agent._backend = fake_bk
        finding = {"cwe": "CWE-79", "title": "XSS", "file": "a.php", "line": 1, "severity": "Medium", "scanner": "web"}
        rec = agent.analyze_finding(finding)
        assert rec["model"] == "offline fallback"

    def test_analyze_many_skips_existing(self):
        agent = GedrAgent(api_key="sk-test", model="m")
        agent.enabled = True
        agent._backend = Mock()

        mock_db = Mock()
        mock_db.get_recommendation.return_value = {"already": True}
        result = agent.analyze_many([{"id": "1", "cwe": "CWE-89"}], mock_db)
        assert result == 0

    def test_parse_json_strict(self):
        raw = '{"explanation":"x","impact":"y","attack_scenario":"z","root_cause":"c","recommended_fix":"f","secure_code":"s","owasp":"Injection","cwe":"CWE-89"}'
        r = _parse_json(raw)
        assert r["cwe"] == "CWE-89"

    def test_parse_json_with_fences(self):
        raw = '```json\n{"explanation":"x","impact":"y","attack_scenario":"z","root_cause":"c","recommended_fix":"f","secure_code":"s","owasp":"Injection","cwe":"CWE-89"}\n```'
        r = _parse_json(raw)
        assert r["owasp"] == "Injection"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
