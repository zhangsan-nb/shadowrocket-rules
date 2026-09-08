
from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    PASS = 0
    BUILD_ERROR = 1
    SECURITY_GATE_FAIL = 2
    SOURCE_FETCH_FAIL = 3
    POLICY_CONFLICT = 4


class TrustedRulesError(RuntimeError):
    """带稳定机器退出码的失败关闭异常。"""

    def __init__(self, message: str, code: ExitCode = ExitCode.BUILD_ERROR, *, key: str = "build.error") -> None:
        super().__init__(message)
        self.code = code
        self.key = key


class SecurityGateError(TrustedRulesError):
    def __init__(self, message: str, *, key: str = "security.gate") -> None:
        super().__init__(message, ExitCode.SECURITY_GATE_FAIL, key=key)


class SourceFetchError(TrustedRulesError):
    def __init__(self, message: str, *, key: str = "source.fetch") -> None:
        super().__init__(message, ExitCode.SOURCE_FETCH_FAIL, key=key)


class PolicyConflictError(TrustedRulesError):
    def __init__(self, message: str, *, key: str = "policy.conflict") -> None:
        super().__init__(message, ExitCode.POLICY_CONFLICT, key=key)
