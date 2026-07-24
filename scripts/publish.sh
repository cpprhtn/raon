#!/usr/bin/env bash
#
# Build and publish raon to PyPI.
#
# Reads the API token from a local .env file (never committed). Copy
# .env.example to .env and fill in your token first.
#
# Usage:
#   scripts/publish.sh              # build, check, upload to PyPI
#   scripts/publish.sh --test       # upload to TestPyPI instead
#   scripts/publish.sh --dry-run    # build + twine check only, no upload
#
# .env keys:
#   PYPI_TOKEN=pypi-...             # required for PyPI
#   TESTPYPI_TOKEN=pypi-...         # required for --test
#
set -euo pipefail

# --- resolve repo root (script lives in scripts/) ---------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# --- parse args -------------------------------------------------------------
REPO="pypi"
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --test) REPO="testpypi" ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# --- load .env (simple KEY=value lines) -------------------------------------
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# --- pick token by target ---------------------------------------------------
if [[ "$REPO" == "testpypi" ]]; then
  TOKEN="${TESTPYPI_TOKEN:-}"
  TOKEN_NAME="TESTPYPI_TOKEN"
else
  TOKEN="${PYPI_TOKEN:-}"
  TOKEN_NAME="PYPI_TOKEN"
fi

# --- choose python (prefer local venv) --------------------------------------
if [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  PY="$(command -v python3 || command -v python)"
fi

echo ">> using $PY"
"$PY" -m pip install --quiet --upgrade build twine

# --- build ------------------------------------------------------------------
echo ">> cleaning old build artifacts"
rm -rf dist build src/raon.egg-info

echo ">> building distribution"
"$PY" -m build

echo ">> validating with twine check"
"$PY" -m twine check dist/*

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo ">> --dry-run: built and checked, skipping upload"
  ls -1 dist
  exit 0
fi

# --- upload -----------------------------------------------------------------
if [[ -z "$TOKEN" ]]; then
  echo "error: $TOKEN_NAME is not set. Add it to .env (see .env.example)." >&2
  exit 1
fi

echo ">> uploading to $REPO"
TWINE_ARGS=()
[[ "$REPO" == "testpypi" ]] && TWINE_ARGS+=(--repository testpypi)

TWINE_USERNAME="__token__" TWINE_PASSWORD="$TOKEN" \
  "$PY" -m twine upload "${TWINE_ARGS[@]}" dist/*

echo ">> done."
