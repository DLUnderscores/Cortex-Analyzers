import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Stub cortexutils so tests run without the nix dev shell.
if "cortexutils" not in sys.modules:
    import os

    _cx = types.ModuleType("cortexutils")
    _cx_resp = types.ModuleType("cortexutils.responder")

    class _Responder:
        def __init__(self, job_directory=None):
            self._job_dir = job_directory
            self._job = {}
            if job_directory:
                input_path = os.path.join(job_directory, "input", "input.json")
                if os.path.isfile(input_path):
                    with open(input_path) as f:
                        self._job = json.load(f)

        def get_param(self, name, default=None, message=None):
            parts = name.split(".")
            obj = self._job
            for part in parts:
                if not isinstance(obj, dict):
                    return default
                obj = obj.get(part)
                if obj is None:
                    return default
            return obj if obj is not None else default

        def get_data(self):
            return self._job.get("data", {})

        def error(self, msg):
            if self._job_dir:
                out_dir = os.path.join(self._job_dir, "output")
                os.makedirs(out_dir, exist_ok=True)
                with open(os.path.join(out_dir, "output.json"), "w") as f:
                    json.dump({"success": False, "errorMessage": msg}, f)
            raise SystemExit(msg)

        def report(self, data):
            if self._job_dir:
                out_dir = os.path.join(self._job_dir, "output")
                os.makedirs(out_dir, exist_ok=True)
                with open(os.path.join(out_dir, "output.json"), "w") as f:
                    json.dump({"success": True, "full": data}, f)

    _cx_resp.Responder = _Responder
    _cx.responder = _cx_resp
    sys.modules["cortexutils"] = _cx
    sys.modules["cortexutils.responder"] = _cx_resp


class FakeResponse:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body
        self.text = text or (json.dumps(body) if body is not None else "")

    def json(self):
        return self._body


class FakeHTTP:
    """requests-like transport returning queued responses matched by method + URL fragment."""

    def __init__(self):
        self.routes = []
        self.calls = []

    def route(self, method, url_fragment, response):
        """response: FakeResponse or callable(**kwargs) -> FakeResponse"""
        self.routes.append((method.upper(), url_fragment, response))

    def _dispatch(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        for m, fragment, response in self.routes:
            if m == method and fragment in url:
                return response(url=url, **kwargs) if callable(response) else response
        raise AssertionError(f"Unexpected {method} request: {url}")

    def get(self, url, **kwargs):
        return self._dispatch("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._dispatch("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self._dispatch("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        return self._dispatch("PATCH", url, **kwargs)


@pytest.fixture
def fake_http():
    return FakeHTTP()
