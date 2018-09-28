#!/usr/bin/env bash

python -m venv venv
. ./venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=.

case $1 in
  build)
     python -m compileall ubirch tests examples
    ;;
  test)
    python -m unittest discover -v
    ;;
  package)
    ./bin/create_package.sh
    ;;
  push)
    ./bin/upload_pypi.sh
    ;;
  *)
    echo "Usage: $0 { build | test | package | push }"
    exit 1
esac