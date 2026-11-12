"""httpjson: the rules that keep credentials where they were sent."""

import io
import urllib.request
from http.client import HTTPMessage

import pytest

from scamallscope import httpjson


def test_redirects_are_refused():
    # urllib would re-send the Authorization header to the redirect target.
    req = urllib.request.Request("https://wazuh.example/agents", headers={"Authorization": "Bearer x"})
    target = "http://elsewhere.example/"
    assert httpjson._NoRedirect().redirect_request(req, io.BytesIO(), 302, "Found", HTTPMessage(), target) is None


def test_https_only():
    with pytest.raises(ValueError):
        httpjson.require_https("http://wazuh.example:55000")
