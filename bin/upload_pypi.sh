#! /bin/sh
SCRIPT_DIR=$(dirname "$0")
python3 -m pip --no-cache-dir install --upgrade twine
python3 -m twine upload "${SCRIPT_DIR}"/../dist/*