from __future__ import annotations

from email.message import Message
from urllib.error import HTTPError

import pytest

from trusted_rules.errors import SecurityGateError, SourceFetchError
from trusted_rules.fetcher import fetch_source


class Response:
    def __init__(self, body: bytes, content_type: str = "text/plain") -> None:
        self.body = body
        self.offset = 0
        self.status = 200
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = str(len(body))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return "https://example.invalid/rules.list"

    def read(self, size: int):
        chunk = self.body[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


class Opener:
    def __init__(self, result):
        self.result = result

    def open(self, request, timeout):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def policy():
    return {"fetch": {"timeout_seconds": 1, "retries": 0, "max_bytes": 1024}}


def source():
    return {"url": "https://example.invalid/rules.list"}


def test_http_404_is_source_failure(monkeypatch):
    error = HTTPError(source()["url"], 404, "Not Found", {}, None)
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener(error))
    with pytest.raises(SourceFetchError):
        fetch_source("test", source(), policy())


def test_html_content_type_is_rejected(monkeypatch):
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener(Response(b"<html>bad</html>", "text/html")))
    with pytest.raises(SourceFetchError):
        fetch_source("test", source(), policy())


def test_html_body_is_security_failure(monkeypatch):
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: Opener(Response(b"<!DOCTYPE html><html>bad</html>")))
    with pytest.raises(SecurityGateError):
        fetch_source("test", source(), policy())

