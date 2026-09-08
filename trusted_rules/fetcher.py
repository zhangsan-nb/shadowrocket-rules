from __future__ import annotations

import hashlib
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from .errors import SourceFetchError, TrustedRulesError
from .models import SourceMetadata
from .parser import reject_contamination


class HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            raise SourceFetchError(f"拒绝不安全重定向: {newurl}", key="source.redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_source(name: str, source: dict[str, Any], policy: dict[str, Any]) -> tuple[str, SourceMetadata]:
    url = str(source.get("url", ""))
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise SourceFetchError(f"{name} 只能使用无凭据 HTTPS URL", key="source.url")
    fetch_policy = policy.get("fetch", {})
    timeout = float(fetch_policy.get("timeout_seconds", 20))
    retries = int(fetch_policy.get("retries", 2))
    max_bytes = int(fetch_policy.get("max_bytes", 8_000_000))
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(HTTPSRedirectHandler(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "trusted-shadowrocket-rules/1.0", "Accept": "text/plain,*/*;q=0.1"},
    )
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            with opener.open(request, timeout=timeout) as response:
                status = int(response.status)
                if status != 200 or urllib.parse.urlparse(response.geturl()).scheme != "https":
                    raise SourceFetchError(f"{name} HTTP {status}", key="source.http")
                content_type = response.headers.get_content_type().lower()
                if content_type in {"text/html", "application/xhtml+xml"}:
                    raise SourceFetchError(f"{name} 返回 HTML", key="source.html")
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > max_bytes:
                    raise SourceFetchError(f"{name} 超过最大下载大小", key="source.size")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(min(65536, max_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise SourceFetchError(f"{name} 超过最大下载大小", key="source.size")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                if not raw:
                    raise SourceFetchError(f"{name} 返回空内容", key="source.empty")
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeDecodeError as exc:
                    raise SourceFetchError(f"{name} 不是 UTF-8", key="source.encoding") from exc
                reject_contamination(text)
                return text, SourceMetadata(
                    name=name,
                    url=url,
                    fetched_at=datetime.now(timezone.utc).isoformat(),
                    http_status=status,
                    content_length=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(),
                    etag=response.headers.get("ETag"),
                    last_modified=response.headers.get("Last-Modified"),
                    git_commit=None,
                )
        except TrustedRulesError:
            raise
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(min(2**attempt, 4))
    raise SourceFetchError(f"{name} 抓取失败: {last_error}", key="source.fetch")

