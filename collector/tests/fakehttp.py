"""A fake urlopen for HTTP fetch tests: records requests, answers from a list."""

import io
import json
import urllib.error


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


class FakeUrlopen:
    def __init__(self, answers):
        self.answers = list(answers)  # (url substring, status, body)
        self.requests = []

    def __call__(self, req, timeout=None, context=None):
        self.requests.append(req)
        for i, (part, status, body) in enumerate(self.answers):
            if part in req.full_url:
                self.answers.pop(i)
                data = json.dumps(body).encode()
                if status >= 400:
                    raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(data))  # type: ignore[arg-type]
                return FakeResponse(data)
        raise AssertionError(f"unexpected request {req.full_url}")
