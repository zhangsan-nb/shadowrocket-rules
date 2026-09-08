#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
candidate="${1:-$repo_root/candidate-verified}"

cd "$repo_root"
python scripts/validate.py --candidate "$candidate"
python scripts/release.py publish --candidate "$candidate"
