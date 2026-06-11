import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


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
