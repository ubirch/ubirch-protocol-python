#! /bin/sh
SCRIPT_DIR=$(dirname "$0")
python3 -m pip --no-cache-dir install --upgrade build
(cd "${SCRIPT_DIR}"/.. || exit; python3 -m build)