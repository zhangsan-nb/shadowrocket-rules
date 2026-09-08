from __future__ import annotations

import hashlib
import stat
import zipfile
from pathlib import Path, PurePosixPath

from .artifacts import safe_files, sha256_file, verify_manifest
from .errors import SecurityGateError


def seal_candidate(candidate: Path, archive: Path, digest_path: Path) -> str:
    verify_manifest(candidate)
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in safe_files(candidate):
            relative = path.relative_to(candidate).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, path.read_bytes())
    digest = sha256_file(archive)
    digest_path.write_text(f"{digest}  {archive.name}\n", encoding="utf-8", newline="\n")
    return digest


def verify_and_extract(archive: Path, digest_path: Path, output: Path) -> None:
    tokens = digest_path.read_text(encoding="utf-8").strip().split()
    if len(tokens) != 2 or tokens[1] != archive.name or tokens[0] != sha256_file(archive):
        raise SecurityGateError("传输层制品 SHA-256 不匹配", key="artifact.transport")
    output.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive) as bundle:
        names: set[str] = set()
        for info in bundle.infolist():
            pure = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or not pure.parts
                or pure.parts[0] not in {"rules", "reports", "metadata"}
                or stat.S_ISLNK(mode)
                or info.filename in names
            ):
                raise SecurityGateError(f"压缩包路径或类型非法: {info.filename}", key="artifact.archive")
            names.add(info.filename)
            target = output.joinpath(*pure.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(info))
    verify_manifest(output)

